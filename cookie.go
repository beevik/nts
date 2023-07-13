// Copyright © 2023 Brett Vickers.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package nts

const (
	cookieJarSize = 8
)

// A cookieJar is a ring-buffer that holds the 8 most recent NTS cookies
// supplied by the NTP server or NTS key-exchange server. Each NTS-based NTP
// query consumes a cookie from the cookie jar. The cookie jar is refilled
// after each successful NTS-based NTP query response.
type cookieJar struct {
	cookies [cookieJarSize][]byte
	count   int
	head    int
	tail    int
}

// Add a cookie to the cookie jar. If the cookie jar is already full, the
// oldest cookie is replaced by the added cookie.
func (jar *cookieJar) Add(cookie []byte) {
	jar.cookies[jar.head] = cookie
	jar.head = (jar.head + 1) % cookieJarSize
	if jar.count == cookieJarSize {
		jar.tail = (jar.tail + 1) % cookieJarSize
	} else {
		jar.count++
	}
}

// Clear the contents of the cookie jar.
func (jar *cookieJar) Clear() {
	for i := range jar.cookies {
		jar.cookies[i] = nil
	}
	jar.head, jar.tail, jar.count = 0, 0, 0
}

// Consume the oldest cookie in the cookie jar. If the jar is empty, return
// nil.
func (jar *cookieJar) Consume() []byte {
	if jar.count == 0 {
		return nil
	}
	cookie := jar.cookies[jar.tail]
	jar.cookies[jar.tail] = nil
	jar.tail = (jar.tail + 1) % cookieJarSize
	jar.count--
	return cookie
}

// Count returns the number of cookies in the cookie jar.
func (jar *cookieJar) Count() int {
	return jar.count
}
