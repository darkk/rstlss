rstlss (RST-less TCP)
=====================

`rstlss` is an example of an unprivileged Linux process using a BPF filter to
block certain TCP packets coming to the socket.

This specific example shows how to circumvent one-sided [TCP reset attack](https://en.wikipedia.org/wiki/TCP_reset_attack)
by an _on-path_ DPI box [blocking](http://isitblockedinrussia.com/?host=https%3A%2F%2Frutracker.org)
`https://rutracker.org` (as _Inappropriate TCP Resets Considered Harmful_). :-)

_On-path_ DPI box is assumed to be _passive_, being unable to _drop_ packets,
just being able to inject some.

_One-sided TCP reset attack_ means that RST packet is injected only towards the
"client" endpoints and the "server" does not get another RST. E.g. some networks
in [Uganda block OpenVPN/TCP](https://ooni.torproject.org/post/uganda-social-media-tax/#vpn-blocking)
with two-sided TCP reset attacks. One has to control the server as well to
mitigate two-sided attack.

## Example

Following tests were done on 2019-04-19 from AS8997, OJSC Rostelecom. The
vantage point observes blocking of HTTPS websites by means of SNI-based
detection and one-sided RST injection to block connections.

### Desktop Linux

It just runs and just works:

```
$ go build .
$ ./rstlss
panic: Get https://rutracker.org/robots.txt: read tcp 192.168.100.223:34176->195.82.146.214:443: read: connection reset by peer

goroutine 1 [running]:
main.main()
        /home/darkk/go/src/github.com/darkk/rstlss/main.go:72 +0x69a
$ RSTLSS=1 ./rstlss | grep -C 3 rutracker
Allow: /forum/viewforum.php?f=
Allow: /forum/viewtopic.php
Disallow: /
Host: rutracker.org

User-agent: Adsbot-Google
User-agent: Googlebot-Image
$
```

### Android

The binary is run with awesome [Termux](https://termux.com/) after
cross-compiling the binary at the desktop:

```
$ CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=7 go build .
```

Android PoC needs DNS server specified manually due to
[golang/go#8877](https://github.com/golang/go/issues/8877) and
[`net.dns1` hidden](https://developer.android.com/about/versions/oreo/android-8.0-changes.html#o-pri)
since Android 8.0. One can get DNS server from _Network Details_:

```
$ RSTLSS_DNS=192.168.100.1:53 ./rstlss
panic: Get https://rutracker.org/robots.txt: read tcp 192.168.100.136:39882->195.82.146.214:443: read: connection reset by peer

goroutine 1 [running]:
main.main()
        /home/darkk/go/src/github.com/darkk/rstlss/main.go:72 +0x544
$ RSTLSS_DNS=192.168.100.1:53 RSTLSS=1 ./rstlss | grep -C 3 rutracker
Allow: /forum/viewforum.php?f=
Allow: /forum/viewtopic.php
Disallow: /
Host: rutracker.org

User-agent: Adsbot-Google
User-agent: Googlebot-Image
$
```

## Outro

This technique does not protect from malicious data being injected and
effectively terminating the connection (e.g. HTTP redirect, TLS Alert or random
garbage for authenticated TLS connection). Doing MAC within 4096 opcodes limit
of a BPF program (~11 opcodes per dword) is left as an exercise for the reader.
