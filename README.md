[![GoDoc](https://godoc.org/github.com/beevik/nts?status.svg)](https://godoc.org/github.com/beevik/nts)

nts
===

The nts package provides a client implementation of Network Time Security
(NTS) for the Network Time Protocol (NTP). It enables the secure querying of
time-related information that can be used to synchronize the local system
clock with a more accurate network clock. See
[RFC 8915](https://tools.ietf.org/html/rfc8915) for further details.

This package is implemented as an extension to the go-based [simple ntp
client package](https://github.com/beevik/ntp), but it may be used without
directly installing that package.


## Creating an NTS session

Before requesting time synchronization data, you must first establish a
"session" with an NTS key-exchange server.

```go
session, err := nts.NewSession("time.cloudflare.com")
```

This is not a session in the typical sense of the word, which often implies a
long-running network connection to a server. Rather, it is merely a collection
of cryptographic keys and other state used to communicate securely with an
NTS-capable NTP server. Once the session has been created, the network
connection to the key-exchange server is immediately dropped and all future
queries proceed via NTP using the session's query functions.

If you wish to customize the behavior of the session, you may do so by using
[`NewSessionWithOptions`](https://godoc.org/github.com/beevik/nts#NewSessionWithOptions)
instead of `NewSession`.

```go
opt := &nts.SessionOptions{
    TLSConfig: &tls.Config{
        RootCAs: certPool,
    },
}
session, err := nts.NewSessionWithOptions(host, opt)
```

See the documentation for
[`SessionOptions`](https://godoc.org/github.com/beevik/nts#SessionOptions) for a
list of available customizations.

## Querying time synchronization data

After successful establishment of the session, you may issue NTP
[`Query`](https://godoc.org/github.com/beevik/nts#Query) requests for time
synchronization data.

```go
if response, err := session.Query(); err != nil {
    accurateTime := time.Now().Add(response.ClockOffset)
    fmt.Printf("The current time is: %s\n", accurateTime)
}
```

In addition to the clock offset, the
[`Response`](https://godoc.org/github.com/beevik/ntp#Response) includes
information you can use to tune future queries. For instance, it includes a
`Poll` interval, which describes how long you should wait before querying
again. The response also has a
[`Validate`](https://godoc.org/github.com/beevik/ntp#Response.Validate)
function, which you can use to perform additional sanity checks on the data to
determine whether it is suitable for time synchronization purposes.
```go
err := response.Validate()
if err == nil {
    // response data is suitable for synchronization purposes
}
```

If you wish to customize the behavior of the query, you may do so by using
[`QueryWithOptions`](https://godoc.org/github.com/beevik/nts#QueryWithOptions)
instead of `Query`.

```go
opt := &ntp.QueryOptions{ Timeout: 30 * time.Second }
response, err := session.QueryWithOptions(opt)
```

See the documentation for
[`QueryOptions`](https://godoc.org/github.com/beevik/ntp#QueryOptions) for a
list of available customizations.


## Choosing an NTS server

NTS is a relatively new protocol, having become an IETF RFC in September 2020.
So there are a limited number of NTS key-exchange servers available for public
use. You can find a list [here](https://netfuture.ch/public-nts-server-list/).
The [NTP pool](https://www.pool.ntp.org) does not currently support NTS.

If you wish to operate your own NTS-capable NTP server, you may install
[NTPsec](https://docs.ntpsec.org/latest/NTS-QuickStart.html) or
[Chrony](https://chrony.tuxfamily.org).
