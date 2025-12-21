// Copyright © Brett Vickers.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package nts

import (
	"bufio"
	"bytes"
	"crypto/cipher"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"

	"github.com/secure-io/siv-go"
)

const (
	ntskeProtocol             = "ntske/1"
	defaultNtsPort            = 4460
	defaultNtpPort            = 123
	ntpProtocolID             = uint16(0)
	algoAEAD_AES_SIV_CMAC_256 = uint16(15)
	algoAEAD_AES_128_GCM_SIV  = uint16(30)
)

var (
	errInvalidRecordSize  = errors.New("key exchange: invalid record size")
	errInvalidCriticalBit = errors.New("key exchange: incorrect critical bit")
)

type recordType uint16
type newAEAD func(key []byte) (cipher.AEAD, error)

const (
	recEOM              recordType = 0
	recProtocols        recordType = 1
	recError            recordType = 2
	recWarning          recordType = 3
	recAlgorithms       recordType = 4
	recCookie           recordType = 5
	recNegotiatedServer recordType = 6
	recNegotiatedPort   recordType = 7
	recCompliant128GCM  recordType = 1024

	recCritical recordType = 0x8000
)

func (s *Session) performKeyExchange() error {
	dialer := s.options.Dialer

	// Use the default TLS dialer if none was provided.
	if dialer == nil {
		dialer = func(network, addr string, tlsConfig *tls.Config) (*tls.Conn, error) {
			d := &net.Dialer{Timeout: s.options.Timeout}
			return tls.DialWithDialer(d, network, addr, tlsConfig)
		}
	}

	// Open a connection to the NTS-KE server.
	conn, err := dialer("tcp", s.ntskeAddr, s.options.TLSConfig)
	if err != nil {
		return fmt.Errorf("key exchange: connection error: %w", err)
	}
	defer conn.Close()

	// Verify that the negotiated protocol is NTS-KE.
	state := conn.ConnectionState()
	if state.NegotiatedProtocol != ntskeProtocol {
		return errors.New("key exchange: NTS-KE protocol not negotiated")
	}

	// Build the NTS-KE request by writing records into a buffer.
	var xmitBuf bytes.Buffer
	{
		writeRecProtocols(&xmitBuf, ntpProtocolID)

		writeRecAlgorithms(&xmitBuf, algoAEAD_AES_128_GCM_SIV, algoAEAD_AES_SIV_CMAC_256)
		writeRecCompliantAes128GcmSiv(&xmitBuf)

		if s.options.RequestedNTPServerAddress != "" {
			writeRecNegotiatedServer(&xmitBuf, s.options.RequestedNTPServerAddress)
		}

		if s.options.RequestedNTPServerPort != 0 {
			writeRecNegotiatedPort(&xmitBuf, uint16(s.options.RequestedNTPServerPort))
		}

		writeRecEOM(&xmitBuf)
	}

	// Send the NTS-KE request to the server.
	_, err = conn.Write(xmitBuf.Bytes())
	if err != nil {
		return fmt.Errorf("key exchange: connection error: %w", err)
	}

	// Read the NTS-KE response.
	recvReader := bufio.NewReader(conn)
	recvBuf := make([]byte, 1024)

	useCompliant128GCM := s.options.AssumeCompliant128GCM

	s.ntpAddr = ""
	var port int
	var algorithm uint16

	// Parse the NTS-KE response records.
loop:
	for {
		// Retrieve the record header (type + length).
		rhdr := recvBuf[:4]
		_, err := io.ReadFull(recvReader, rhdr)
		if err != nil {
			return errors.New("key exchange: failed to read record header")
		}

		// Parse the record type, extracting the critical bit.
		rtype := recordType(binary.BigEndian.Uint16(rhdr[0:2]))
		critical := (rtype & recCritical) != 0
		rtype &= ^recCritical

		// Parse the record length.
		rlen := int(binary.BigEndian.Uint16(rhdr[2:4]))
		if rlen > len(recvBuf) {
			return errors.New("key exchange: record length too large")
		}

		// Read the record body.
		rbody := recvBuf[:rlen]
		_, err = io.ReadFull(recvReader, rbody)
		if err != nil {
			return errors.New("key exchange: failed to read record")
		}

		// Process the record body based on its type.
		switch rtype {
		case recEOM:
			if !critical {
				return errInvalidCriticalBit
			}
			if len(rbody) != 0 {
				return errInvalidRecordSize
			}
			break loop

		case recProtocols:
			if !critical {
				return errInvalidCriticalBit
			}
			if len(rbody) != 2 {
				return errInvalidRecordSize
			}
			p := binary.BigEndian.Uint16(rbody)
			if p != ntpProtocolID {
				return errors.New("key exchange: NTP protocol not supported")
			}

		case recError:
			if !critical {
				return errInvalidCriticalBit
			}
			if len(rbody) != 2 {
				return errInvalidRecordSize
			}
			e := binary.BigEndian.Uint16(rbody)
			return fmt.Errorf("key exchange: server error (0x%02x)", e)

		case recWarning:
			if !critical {
				return errInvalidCriticalBit
			}
			if len(rbody) != 2 {
				return errInvalidRecordSize
			}
			w := binary.BigEndian.Uint16(rbody)
			return fmt.Errorf("key exchange: server warning (0x%02x)", w)

		case recAlgorithms:
			if len(rbody) != 2 {
				return errInvalidRecordSize
			}
			algorithm = binary.BigEndian.Uint16(rbody)

		case recCookie:
			if critical {
				return errInvalidCriticalBit
			}
			if len(rbody) == 0 {
				return errInvalidRecordSize
			}
			cookie := make([]byte, len(rbody))
			copy(cookie, rbody)
			s.cookies.Add(cookie)

		case recNegotiatedServer:
			if len(rbody) == 0 {
				return errInvalidRecordSize
			}
			s.ntpAddr = string(rbody)

		case recNegotiatedPort:
			if len(rbody) != 2 {
				return errInvalidRecordSize
			}
			port = int(binary.BigEndian.Uint16(rbody))

		case recCompliant128GCM:
			if critical {
				return errInvalidCriticalBit
			}
			if len(rbody) != 0 {
				return errInvalidRecordSize
			}
			useCompliant128GCM = true

		default:
			if critical {
				return errInvalidCriticalBit
			}
		}
	}

	// Use the NTS host for NTP if no negotiated server record was reported.
	if s.ntpAddr == "" {
		s.ntpAddr, _, _ = net.SplitHostPort(conn.RemoteAddr().String())
	}

	// Use the default NTP port if no negotiated port was reported.
	if port == 0 {
		port = defaultNtpPort
	}

	// Form the host:port NTP server address string.
	s.ntpAddr = net.JoinHostPort(s.ntpAddr, strconv.Itoa(port))

	// If the NTP address override resolver is defined, call it.
	if s.options.Resolver != nil {
		s.ntpAddr = s.options.Resolver(s.ntpAddr)
	}

	// Extract TLS keys and use them to generate AEAD ciphers.
	switch algorithm {
	case algoAEAD_AES_128_GCM_SIV:
		if useCompliant128GCM {
			return s.extractKeys(conn, algoAEAD_AES_128_GCM_SIV, 16, siv.NewGCM)
		}
		return s.extractKeys(conn, algoAEAD_AES_SIV_CMAC_256, 16, siv.NewGCM)

	case algoAEAD_AES_SIV_CMAC_256:
		return s.extractKeys(conn, algoAEAD_AES_SIV_CMAC_256, 32, siv.NewCMAC)

	default:
		return errors.New("key exchange: no supported algorithm negotiated")
	}
}

func writeRecProtocols(w io.Writer, id uint16) {
	binary.Write(w, binary.BigEndian, recProtocols|recCritical)
	binary.Write(w, binary.BigEndian, uint16(2))
	binary.Write(w, binary.BigEndian, id)
}

func writeRecAlgorithms(w io.Writer, algo1, algo2 uint16) {
	binary.Write(w, binary.BigEndian, recAlgorithms|recCritical)
	binary.Write(w, binary.BigEndian, uint16(4))
	binary.Write(w, binary.BigEndian, algo1)
	binary.Write(w, binary.BigEndian, algo2)
}

func writeRecCompliantAes128GcmSiv(w io.Writer) {
	binary.Write(w, binary.BigEndian, recCompliant128GCM)
	binary.Write(w, binary.BigEndian, uint16(0))
}

func writeRecNegotiatedServer(w io.Writer, addr string) {
	binary.Write(w, binary.BigEndian, recNegotiatedServer)
	binary.Write(w, binary.BigEndian, uint16(len(addr)))
	w.Write([]byte(addr))
}

func writeRecNegotiatedPort(w io.Writer, port uint16) {
	binary.Write(w, binary.BigEndian, recNegotiatedPort)
	binary.Write(w, binary.BigEndian, uint16(2))
	binary.Write(w, binary.BigEndian, port)
}

func writeRecEOM(w io.Writer) {
	binary.Write(w, binary.BigEndian, recEOM|recCritical)
	binary.Write(w, binary.BigEndian, uint16(0))
}

func (s *Session) extractKeys(conn *tls.Conn, algorithmID uint16, keyLength int, aead newAEAD) error {
	const (
		keyLabel     = "EXPORTER-network-time-security"
		c2sIndicator = 0
		s2cIndicator = 1
	)

	context := make([]byte, 5)
	binary.BigEndian.PutUint16(context[0:2], ntpProtocolID)
	binary.BigEndian.PutUint16(context[2:4], algorithmID)

	state := conn.ConnectionState()

	context[4] = c2sIndicator
	c2s, err := state.ExportKeyingMaterial(keyLabel, context, keyLength)
	if err != nil {
		return fmt.Errorf("key exchange: failed to export keying material: %w", err)
	}

	s.cipherC2S, err = aead(c2s)
	if err != nil {
		return fmt.Errorf("key exchange: failed to create c2s cipher: %w", err)
	}

	context[4] = s2cIndicator
	s2c, err := state.ExportKeyingMaterial(keyLabel, context, keyLength)
	if err != nil {
		return fmt.Errorf("key exchange: failed to export keying material: %w", err)
	}

	s.cipherS2C, err = aead(s2c)
	if err != nil {
		return fmt.Errorf("key exchange: failed to create s2c cipher: %w", err)
	}

	return nil
}
