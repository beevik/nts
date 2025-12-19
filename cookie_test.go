// Copyright © 2023 Brett Vickers.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package nts

import (
	"bytes"
	"testing"
)

func TestCookieJar_Add(t *testing.T) {
	jar := cookieJar{}
	cookies := make([][]byte, 10)
	for i := 0; i < 10; i++ {
		cookies[i] = []byte{byte(i)}
		jar.Add(cookies[i])
		if i < cookieJarSize {
			if jar.Count() != i+1 {
				t.Errorf("expected count %d, got %d", i+1, jar.Count())
			}
		} else {
			if jar.Count() != cookieJarSize {
				t.Errorf("expected count %d, got %d", cookieJarSize, jar.Count())
			}
		}
	}

	// Check that the jar contains the last 8 cookies added
	for i := 0; i < cookieJarSize; i++ {
		actual := jar.Consume()
		expected := cookies[i+2]
		if !bytes.Equal(expected, actual) {
			t.Errorf("cookie mismatch: expected %v, got %v", expected, actual)
		}
	}
}

func TestCookieJar_Clear(t *testing.T) {
	jar := cookieJar{}
	for i := 0; i < cookieJarSize; i++ {
		jar.Add([]byte{byte(i)})
	}
	jar.Clear()
	if jar.Count() != 0 {
		t.Errorf("expected count 0, got %d", jar.Count())
	}
	if jar.head != 0 || jar.tail != 0 {
		t.Errorf("head and tail should be 0 after clear")
	}
}

func TestCookieJar_Consume(t *testing.T) {
	jar := cookieJar{}
	for i := 0; i < cookieJarSize; i++ {
		jar.Add([]byte{byte(i)})
	}

	for i := 0; i < cookieJarSize; i++ {
		c := jar.Consume()
		if c == nil {
			t.Errorf("unexpected nil cookie")
		}
		if c[0] != byte(i) {
			t.Errorf("unexpected cookie value: %d", c[0])
		}
	}
	if jar.Consume() != nil {
		t.Errorf("expected nil cookie from empty jar")
	}
}

func TestCookieJar_Count(t *testing.T) {
	jar := cookieJar{}
	if jar.Count() != 0 {
		t.Errorf("initial count should be zero")
	}

	for i := 0; i < cookieJarSize; i++ {
		jar.Add([]byte{byte(i)})
		if jar.Count() != i+1 {
			t.Errorf("expected count %d, got %d", i+1, jar.Count())
		}
	}

	for i := 0; i < cookieJarSize; i++ {
		jar.Consume()
		if jar.Count() != cookieJarSize-i-1 {
			t.Errorf("expected count %d, got %d", cookieJarSize-i-1, jar.Count())
		}
	}
}
