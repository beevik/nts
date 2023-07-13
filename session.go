// Copyright © 2023 Brett Vickers.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package nts provides a client implementation of Network Time Security (NTS)
// for the Network Time Protocol (NTP). It enables the secure querying of
// time-related information that can be used to synchronize the local system
// clock with a more accurate network clock. See RFC 8915
// (https://tools.ietf.org/html/rfc8915) for more details.
package nts

import (
	"bytes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
	"unsafe"

	"github.com/beevik/ntp"
)

var (
	ErrAuthFailedOnClient = errors.New("authentication failed on client")
	ErrAuthFailedOnServer = errors.New("authentication failed on server")
	ErrInvalidFormat      = errors.New("invalid packet format")
	ErrNoCookies          = errors.New("no NTS cookies available")
	ErrUniqueIDMismatch   = errors.New("client and server unique ID mismatch")
)

// Session contains the state of an active NTS session. It is initialized by
// exchanging keys and cookies with an NTS key-exchange server, after which
// the connection to the key-exchange server is immediately dropped. The
// session's internal state is updated as NTP queries are made against an
// NTS-capable NTP server.
type Session struct {
	ntskeAddr string      // "host:port" address used for NTS key exchange
	ntpAddr   string      // "host:port" address to use for NTP service
	cookies   cookieJar   // container for cookies consumed by NTP queries
	cipherC2S cipher.AEAD // client-to-server authentication & encryption
	cipherS2C cipher.AEAD // server-to-client authentication & encryption
	uniqueID  []byte      // most recently transmitted unique ID
}

// NewSession creates an NTS session by connecting to an NTS key-exchange
// server and requesting keys and cookies to be used for future secure NTP
// queries. Once keys and cookies have been received, the connection is
// dropped. The address is of the form "host", "host:port", "host%zone:port",
// "[host]:port" or "[host%zone]:port". If no port is included, NTS default
// port 4460 is used.
func NewSession(address string) (*Session, error) {
	if _, _, err := net.SplitHostPort(address); err != nil {
		if strings.Contains(err.Error(), "missing port") {
			address = net.JoinHostPort(address, strconv.Itoa(defaultNtsPort))
		} else {
			return nil, err
		}
	}

	s := &Session{ntskeAddr: address}
	err := s.performKeyExchange()
	if err != nil {
		return nil, err
	}
	return s, nil
}

// Address returns the NTP server "host:port" pair configured for the session.
func (s *Session) Address() string {
	return s.ntpAddr
}

// Query time data from the session's associated NTP server. The response
// contains information from which an accurate local time can be determined.
func (s *Session) Query() (response *ntp.Response, err error) {
	return s.QueryWithOptions(&ntp.QueryOptions{})
}

// QueryWithOptions performs the same function as Query but allows for the
// customization of certain NTP behaviors.
func (s *Session) QueryWithOptions(opt *ntp.QueryOptions) (response *ntp.Response, err error) {
	opt.Extensions = append(opt.Extensions, privateWrapper{s})
	return ntp.QueryWithOptions(s.ntpAddr, *opt)
}

// Refresh the session by clearing the its current cookies and performing a
// new key exchange. This should only be done when no queries have been
// performed with the session for a very long time (i.e., more than 24 hours).
func (s *Session) Refresh() error {
	s.ntpAddr = ""
	s.cipherC2S = nil
	s.cipherS2C = nil
	s.uniqueID = nil
	s.cookies.Clear()

	return s.performKeyExchange()
}

// privateWrapper wraps a session in a private type so we can avoid exposing
// ntp.Extension's ProcessQuery and ProcessResponse functions as public
// Session APIs.
type privateWrapper struct {
	session *Session
}

func (w privateWrapper) ProcessQuery(buf *bytes.Buffer) error {
	return w.session.processQuery(buf)
}

func (w privateWrapper) ProcessResponse(buf []byte) error {
	return w.session.processResponse(buf)
}

func (s *Session) processQuery(buf *bytes.Buffer) error {
	// Refresh session if we're out of cookies.
	if s.cookies.count == 0 {
		err := s.Refresh()
		if err != nil {
			return err
		}
	}

	// Append the UniqueID extension field. Remember the unique ID so we can
	// compare it to the response's value.
	s.uniqueID = make([]byte, 32)
	_, err := rand.Read(s.uniqueID)
	if err != nil {
		return err
	}
	writeExtUniqueID(buf, s.uniqueID)

	// Append the cookie extension field.
	cookie := s.cookies.Consume()
	if cookie == nil {
		return ErrNoCookies
	}
	writeExtCookie(buf, cookie)

	// Append cookie placeholder fields. Request enough additional cookies to
	// fill the jar.
	phCount := cookieJarSize - (s.cookies.Count() + 1)
	if phCount > 0 {
		placeholder := make([]byte, paddedLen(len(cookie)))
		for i := 0; i < phCount; i++ {
			writeExtCookiePlaceholder(buf, placeholder)
		}
	}

	// Authenticate the packet up to this point and append the AEAD extension
	// field.
	nonce := allocAligned(s.cipherC2S.NonceSize())
	_, err = rand.Read(nonce)
	if err != nil {
		return err
	}
	ciphertext := s.cipherC2S.Seal(nil, nonce, nil, buf.Bytes())
	writeExtAEAD(buf, nonce, ciphertext)

	return nil
}

func (s *Session) processResponse(buf []byte) error {
	const (
		cryptoNAK    = 0x4e54534e // Kiss code "NTSN"
		ntpHeaderLen = 48
	)

	defer func() {
		s.uniqueID = nil
	}()

	// Check the NTP header for a crypto-NAK kiss-of-death.
	stratum := buf[1]
	if stratum == 0 {
		kissCode := binary.BigEndian.Uint32(buf[12:])
		if kissCode == cryptoNAK {
			return ErrAuthFailedOnServer
		}
	}

	// Process all NTS extension fields.
	offset := ntpHeaderLen
	cur := buf[offset:]
	for len(cur) > 4 {
		xtype := extType(binary.BigEndian.Uint16(cur[0:2]))
		xlen := int(binary.BigEndian.Uint16(cur[2:4]))
		if len(cur) < xlen {
			return ErrInvalidFormat
		}

		body := cur[4:xlen]
		cur = cur[xlen:]

		switch xtype {
		case extUniqueID:
			if !bytes.Equal(s.uniqueID, body) {
				return ErrUniqueIDMismatch
			}

		case extAEAD:
			if len(body) < 4 {
				return ErrInvalidFormat
			}

			nonceLen := int(binary.BigEndian.Uint16(body[0:2]))
			nonceLenPadded := paddedLen(nonceLen)
			ciphertextLen := int(binary.BigEndian.Uint16(body[2:4]))
			ciphertextLenPadded := paddedLen(ciphertextLen)
			if len(body) < 4+ciphertextLenPadded+nonceLenPadded {
				return ErrInvalidFormat
			}

			// NOTE: The siv-go package has an undocumented issue where all
			// memory accesses must be 64-bit aligned or it segfaults. To
			// prevent this, copy the nonce and ciphertext into newly
			// allocated, memory-aligned slices before decrypting and
			// authenticating.
			nonce := allocAligned(nonceLen)
			copy(nonce, body[4:])
			ciphertext := allocAligned(ciphertextLen)
			copy(ciphertext, body[4+nonceLenPadded:])

			// Decrypt and authenticate. The ciphertext contains only
			// encrypted cookies.
			plaintext, err := s.cipherS2C.Open(nil, nonce, ciphertext, buf[:offset])
			if err != nil {
				return ErrAuthFailedOnClient
			}
			err = s.processCookies(plaintext)
			if err != nil {
				return err
			}
		}

		offset += xlen
	}

	return nil
}

func (s *Session) processCookies(buf []byte) error {
	for len(buf) > 4 {
		xtype := extType(binary.BigEndian.Uint16(buf[0:2]))
		xlen := int(binary.BigEndian.Uint16(buf[2:4]))
		if len(buf) < xlen {
			return ErrInvalidFormat
		}

		body := buf[4:xlen]
		buf = buf[xlen:]

		if xtype == extCookie {
			cookie := make([]byte, len(body))
			copy(cookie, body)
			s.cookies.Add(cookie)
		}
	}
	return nil
}

func allocAligned(size int) []byte {
	buf := make([]byte, size)
	ptr := uintptr(unsafe.Pointer(&buf[0]))
	if (ptr & uintptr(7)) == 0 {
		return buf
	}
	buf = make([]byte, size+7)
	ptr = uintptr(unsafe.Pointer(&buf[0]))
	offset := (8 - int(ptr&uintptr(7))) & 7
	return buf[offset : offset+size]
}

var pad = make([]byte, 4)

func paddedLen(len int) int {
	return (len + 3) & ^3
}

type extType uint16

const (
	extUniqueID          extType = 0x0104
	extCookie            extType = 0x0204
	extCookiePlaceholder extType = 0x0304
	extAEAD              extType = 0x0404
)

func writeExtUniqueID(w io.Writer, uniqueID []byte) {
	totalLen := 4 + len(uniqueID)
	binary.Write(w, binary.BigEndian, extUniqueID)
	binary.Write(w, binary.BigEndian, uint16(totalLen))
	w.Write(uniqueID)
}

func writeExtCookie(w io.Writer, cookie []byte) {
	cookieLenPadded := paddedLen(len(cookie))
	totalLen := 4 + cookieLenPadded
	binary.Write(w, binary.BigEndian, extCookie)
	binary.Write(w, binary.BigEndian, uint16(totalLen))
	w.Write(cookie)
	w.Write(pad[:cookieLenPadded-len(cookie)])
}

func writeExtCookiePlaceholder(w io.Writer, placeholder []byte) {
	totalLen := 4 + len(placeholder)
	binary.Write(w, binary.BigEndian, extCookiePlaceholder)
	binary.Write(w, binary.BigEndian, uint16(totalLen))
	w.Write(placeholder)
}

func writeExtAEAD(w io.Writer, nonce []byte, ciphertext []byte) {
	nonceLenPadded := paddedLen(len(nonce))
	ciphertextLenPadded := paddedLen(len(ciphertext))
	totalLen := 4 + 4 + nonceLenPadded + ciphertextLenPadded
	binary.Write(w, binary.BigEndian, extAEAD)
	binary.Write(w, binary.BigEndian, uint16(totalLen))
	binary.Write(w, binary.BigEndian, uint16(len(nonce)))
	binary.Write(w, binary.BigEndian, uint16(len(ciphertext)))
	w.Write(nonce)
	w.Write(pad[:nonceLenPadded-len(nonce)])
	w.Write(ciphertext)
	w.Write(pad[:ciphertextLenPadded-len(ciphertext)])
}
