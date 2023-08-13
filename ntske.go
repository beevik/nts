// Copyright © 2023 Brett Vickers.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package nts

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"

	"github.com/secure-io/siv-go"
)

const (
	ntskeProtocol             = "ntske/1"
	defaultNtsPort            = 4460
	defaultNtpPort            = 123
	ntpProtocolID             = uint16(0)
	algoAEAD_AES_SIV_CMAC_256 = uint16(15)
)

var ErrKeyExchangeFailed = errors.New("key exchange failure")

type recordType uint16

const (
	recEOM recordType = 0 + iota
	recProtocols
	recError
	recWarning
	recAlgorithms
	recCookie
	recServer
	recPort

	recCritical recordType = 0x8000
)

func (s *Session) performKeyExchange() error {
	tlsConfig := s.tlsConfig
	if s.tlsConfig == nil {
		tlsConfig = &tls.Config{}
	}
	tlsConfig.MinVersion = tls.VersionTLS13
	tlsConfig.NextProtos = []string{ntskeProtocol}

	dialer := &net.Dialer{Timeout: time.Second * 5}
	conn, err := tls.DialWithDialer(dialer, "tcp", s.ntskeAddr, tlsConfig)
	if err != nil {
		return fmt.Errorf("key exchange failure: %s", err.Error())
	}
	defer conn.Close()

	state := conn.ConnectionState()
	if state.NegotiatedProtocol != ntskeProtocol {
		return ErrKeyExchangeFailed
	}

	var xmitBuf bytes.Buffer
	writeRecProtocols(&xmitBuf, ntpProtocolID)
	writeRecAlgorithms(&xmitBuf, algoAEAD_AES_SIV_CMAC_256)
	writeRecEOM(&xmitBuf)

	_, err = conn.Write(xmitBuf.Bytes())
	if err != nil {
		return fmt.Errorf("key exchange failure: %s", err.Error())
	}

	recvReader := bufio.NewReader(conn)
	recvBuf := make([]byte, 1024)

	s.ntpAddr = ""
	port := 0
loop:
	for {
		rhdr := recvBuf[:4]
		_, err := io.ReadFull(recvReader, rhdr)
		if err != nil {
			return ErrKeyExchangeFailed
		}

		rtype := recordType(binary.BigEndian.Uint16(rhdr[0:2]))
		critical := (rtype & recCritical) != 0
		rtype &= ^recCritical
		if rtype > 7 {
			return ErrKeyExchangeFailed
		}

		rlen := int(binary.BigEndian.Uint16(rhdr[2:4]))
		if rlen > len(recvBuf) {
			return ErrKeyExchangeFailed
		}

		rbody := recvBuf[:rlen]
		_, err = io.ReadFull(recvReader, rbody)
		if err != nil {
			return ErrKeyExchangeFailed
		}

		switch rtype {
		case recEOM:
			if len(rbody) != 0 || !critical {
				return ErrKeyExchangeFailed
			}
			break loop

		case recProtocols:
			if len(rbody) < 2 || (len(rbody)%2) != 0 || !critical {
				return ErrKeyExchangeFailed
			}
			found := false
			for i := 0; i < len(rbody); i += 2 {
				id := binary.BigEndian.Uint16(rbody[i:])
				if id == ntpProtocolID {
					found = true
					break
				}
			}
			if !found {
				return ErrKeyExchangeFailed
			}

		case recError:
			if len(rbody) < 2 || (len(rbody)%2) != 0 || !critical {
				return ErrKeyExchangeFailed
			}
			e := binary.BigEndian.Uint16(rbody)
			return fmt.Errorf("key exchange failure: error 0x%02x", e)

		case recWarning:
			if len(rbody) < 2 || (len(rbody)%2) != 0 || !critical {
				return ErrKeyExchangeFailed
			}
			w := binary.BigEndian.Uint16(rbody)
			return fmt.Errorf("key exchange failure: warning 0x%02x", w)

		case recAlgorithms:
			if len(rbody) < 2 || (len(rbody)%2) != 0 {
				return ErrKeyExchangeFailed
			}
			found := false
			for i := 0; i < len(rbody); i += 2 {
				a := binary.BigEndian.Uint16(rbody[i:])
				if a == algoAEAD_AES_SIV_CMAC_256 {
					found = true
					break
				}
			}
			if !found {
				return ErrKeyExchangeFailed
			}

		case recCookie:
			if len(rbody) == 0 || critical {
				return ErrKeyExchangeFailed
			}
			cookie := make([]byte, len(rbody))
			copy(cookie, rbody)
			s.cookies.Add(cookie)

		case recServer:
			if len(rbody) == 0 {
				return ErrKeyExchangeFailed
			}
			s.ntpAddr = string(rbody)

		case recPort:
			if len(rbody) != 2 || critical {
				return ErrKeyExchangeFailed
			}
			port = int(binary.BigEndian.Uint16(rbody))
		}
	}

	// Use the NTS host for NTP if no server record was reported.
	if s.ntpAddr == "" {
		s.ntpAddr, _, _ = net.SplitHostPort(conn.RemoteAddr().String())
	}

	// Use the default NTP port if no port was reported.
	if port == 0 {
		port = defaultNtpPort
	}

	s.ntpAddr = net.JoinHostPort(s.ntpAddr, strconv.Itoa(port))

	// Extract encryption keys from the TLS connection.
	keyC2S, keyS2C, err := extractKeys(conn, algoAEAD_AES_SIV_CMAC_256)
	if err != nil {
		return fmt.Errorf("key exchange failure: %s", err.Error())
	}

	// Create AEAD ciphers from the keys.
	s.cipherC2S, err = siv.NewCMAC(keyC2S)
	if err != nil {
		return ErrKeyExchangeFailed
	}
	s.cipherS2C, err = siv.NewCMAC(keyS2C)
	if err != nil {
		return ErrKeyExchangeFailed
	}

	return nil
}

func writeRecProtocols(w io.Writer, id uint16) {
	binary.Write(w, binary.BigEndian, recProtocols|recCritical)
	binary.Write(w, binary.BigEndian, uint16(2))
	binary.Write(w, binary.BigEndian, id)
}

func writeRecAlgorithms(w io.Writer, algo uint16) {
	binary.Write(w, binary.BigEndian, recAlgorithms|recCritical)
	binary.Write(w, binary.BigEndian, uint16(2))
	binary.Write(w, binary.BigEndian, algo)
}

func writeRecEOM(w io.Writer) {
	binary.Write(w, binary.BigEndian, recEOM|recCritical)
	binary.Write(w, binary.BigEndian, uint16(0))
}

func extractKeys(conn *tls.Conn, algorithm uint16) (c2s, s2c []byte, err error) {
	const (
		keyLabel     = "EXPORTER-network-time-security"
		keyLength    = 32
		c2sIndicator = 0
		s2cIndicator = 1
	)

	context := make([]byte, 5)
	binary.BigEndian.PutUint16(context[0:2], ntpProtocolID)
	binary.BigEndian.PutUint16(context[2:4], algorithm)

	state := conn.ConnectionState()

	context[4] = c2sIndicator
	c2s, err = state.ExportKeyingMaterial(keyLabel, context, keyLength)
	if err != nil {
		return nil, nil, err
	}

	context[4] = s2cIndicator
	s2c, err = state.ExportKeyingMaterial(keyLabel, context, keyLength)
	if err != nil {
		return nil, nil, err
	}

	return c2s, s2c, nil
}
