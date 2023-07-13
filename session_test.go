// Copyright © 2023 Brett Vickers.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package nts

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/beevik/ntp"
)

const host = "time.cloudflare.com"

func TestOnlineSession(t *testing.T) {
	s, err := NewSession(host)
	if err != nil {
		t.Fatal(err)
	}

	host, port, err := net.SplitHostPort(s.Address())
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("NTP host: %s\n", host)
	t.Logf("NTP port: %s\n", port)

	const iterations = 10
	var minPoll = 10 * time.Second
	for i := 1; i <= iterations; i++ {
		r, err := s.Query()
		if err != nil {
			t.Fatal(err)
		}

		t.Log(strings.Repeat("=", 48))
		t.Logf("Query %d of %d\n", i, iterations)
		logResponse(t, r)

		wait := r.Poll
		if wait < minPoll {
			wait = minPoll
		}

		if i < iterations {
			t.Logf("Waiting %s for next query...\n", wait)
			time.Sleep(wait)
		}
	}
}

func logResponse(t *testing.T, r *ntp.Response) {
	const timeFormat = "Mon Jan _2 2006  15:04:05.00000000 (MST)"

	now := time.Now()
	t.Logf("[%s] ClockOffset: %s", host, r.ClockOffset)
	t.Logf("[%s]  SystemTime: %s", host, now.Format(timeFormat))
	t.Logf("[%s]   ~TrueTime: %s", host, now.Add(r.ClockOffset).Format(timeFormat))
	t.Logf("[%s]    XmitTime: %s", host, r.Time.Format(timeFormat))
	t.Logf("[%s]     Stratum: %d", host, r.Stratum)
	t.Logf("[%s]       RefID: %s (0x%08x)", host, formatRefID(r.ReferenceID, r.Stratum), r.ReferenceID)
	t.Logf("[%s]     RefTime: %s", host, r.ReferenceTime.Format(timeFormat))
	t.Logf("[%s]         RTT: %s", host, r.RTT)
	t.Logf("[%s]        Poll: %s", host, r.Poll)
	t.Logf("[%s]   Precision: %s", host, r.Precision)
	t.Logf("[%s]   RootDelay: %s", host, r.RootDelay)
	t.Logf("[%s]    RootDisp: %s", host, r.RootDispersion)
	t.Logf("[%s]    RootDist: %s", host, r.RootDistance)
	t.Logf("[%s]    MinError: %s", host, r.MinError)
	t.Logf("[%s]        Leap: %d", host, r.Leap)
	t.Logf("[%s]    KissCode: %s", host, stringOrEmpty(r.KissCode))
}

func formatRefID(id uint32, stratum uint8) string {
	if stratum == 0 {
		return "<kiss>"
	}

	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, id)

	// Stratum 1 ref IDs typically contain ASCII-encoded string identifiers.
	if stratum == 1 {
		const dot = rune(0x22c5)
		var r []rune
		for i := range b {
			if b[i] == 0 {
				break
			}
			if b[i] >= 32 && b[i] <= 126 {
				r = append(r, rune(b[i]))
			} else {
				r = append(r, dot)
			}
		}
		return fmt.Sprintf(".%s.", string(r))
	}

	// Stratum 2+ ref IDs typically contain IPv4 addresses.
	return fmt.Sprintf("%d.%d.%d.%d", b[0], b[1], b[2], b[3])
}

func stringOrEmpty(s string) string {
	if s == "" {
		return "<empty>"
	}
	return s
}
