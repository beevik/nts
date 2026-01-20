// Copyright © 2023 Brett Vickers.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package nts

import (
	"bytes"
	"fmt"
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

	const iterations = 10
	var minPoll = 10 * time.Second
	for i := 1; i <= iterations; i++ {
		opt := ntp.QueryOptions{
			Version:                  5,
			Timescale:                ntp.TimescaleUTC,
			AdditionalTimescales:     []ntp.Timescale{ntp.TimescaleTAI, ntp.TimescaleUT1, ntp.TimescaleUTCSmeared},
			RequestSupportedVersions: true,
			RequestCorrection:        false,
			RequestReferenceTime:     true,
			RequestMonotonic:         true,
			RequestInterleavedMode:   true,
			RequestReferenceID: ntp.ReferenceIDRequest{
				ChunkOffset: 0,
				ChunkSize:   uint16(512),
			},
		}

		r, err := s.QueryWithOptions(&opt)
		if err != nil {
			t.Fatal(err)
		}

		t.Log(strings.Repeat("=", 48))
		t.Logf("Query %d of %d\n", i, iterations)
		t.Log(strings.Repeat("=", 48))

		var buf bytes.Buffer
		fmt.Fprintf(&buf, "\n\n    Address: %v\n", s.Address())
		r.Log(&buf)
		t.Log(buf.String() + "\n")

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
