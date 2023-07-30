// Copyright © 2023 Brett Vickers.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package nts

import (
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/beevik/ntp"
)

// The NTS key-exchange server to use for online unit tests. May be overridden
// by the NTS_HOST environment variable.
var host string = "time.cloudflare.com"

func init() {
	h := os.Getenv("NTS_HOST")
	if h != "" {
		host = h
	}
}

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
	t.Logf("[%s]       RefID: %s (0x%08x)", host, r.ReferenceString(), r.ReferenceID)
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

func stringOrEmpty(s string) string {
	if s == "" {
		return "<empty>"
	}
	return s
}
