// `rstlss` is an example of an unprivileged Linux process using a BPF filter
// to block certain TCP packets coming to the socket.
//
// Inspired by awesome blog post "eBPF, Sockets, Hop Distance and manually
// writing eBPF assembly" by Marek Majkowski:
// https://blog.cloudflare.com/epbf_sockets_hop_distance/
//
// CC0, No Rights Reserved.  -- Leonid Evdokimov <leon@darkk.net.ru>

package main

import (
	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"
	"io"
	"net"
	"net/http"
	"os"
	"syscall"
	"time"
	"unsafe"
)

// DNS resolve workaround for android in pure go
// this only work before any Lookup call and net.dnsReadConfig() failed
//go:linkname defaultNS net.defaultNS
var defaultNS []string

func main() {
	if _, err := os.Stat("/etc/resolv.conf"); os.IsNotExist(err) {
		// Ugly hack for Android, good enough for proof-of-concept.
		dns := os.Getenv("RSTLSS_DNS")
		if dns != "" {
			defaultNS = []string{dns}
		}
	}

	// https://en.wikipedia.org/wiki/Transmission_Control_Protocol#TCP_segment_structure
	// IP headers are also reachable at some magic offset
	// https://github.com/torvalds/linux/blob/ead751507de86d90fa250431e9990a8b881f713c/include/uapi/linux/filter.h#L84
	filter, err := bpf.Assemble([]bpf.Instruction{
		bpf.LoadAbsolute{Off: 13, Size: 1},                        // load flags[RST]
		bpf.JumpIf{Cond: bpf.JumpBitsSet, Val: 0x04, SkipTrue: 1}, // check RST
		bpf.RetConstant{Val: 65535},                               // ACCEPT
		bpf.RetConstant{Val: 0},                                   // DROP
	})
	if err != nil {
		panic(err)
	}
	prog := unix.SockFprog{
		Len:    uint16(len(filter)),
		Filter: (*unix.SockFilter)(unsafe.Pointer(&filter[0])),
	}
	dialer := &net.Dialer{
		Control: func(network, address string, c syscall.RawConn) error {
			return c.Control(func(fd uintptr) {
				if os.Getenv("RSTLSS") == "" {
					return
				}
				err := unix.SetsockoptSockFprog(int(fd), unix.SOL_SOCKET, unix.SO_ATTACH_FILTER, &prog)
				if err != nil {
					panic(err)
				}
			})
		},
	}
	tr := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           dialer.DialContext,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
	client := &http.Client{Transport: tr}
	resp, err := client.Get("https://rutracker.org/robots.txt")
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	_, err = io.Copy(os.Stdout, resp.Body)
	if err != nil {
		panic(err)
	}
}
