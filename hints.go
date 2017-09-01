package godane

import (
	"io"
	"strings"

	"github.com/miekg/dns"
)

// ReadHints reads in DNS resource records from a file
func ReadHints(f io.Reader) ([]dns.RR, error) {
	//
	hints := make([]dns.RR, 0)
	for token := range dns.ParseZone(f, "", "") {
		if token.Error != nil {
			return nil, token.Error
		}
		hints = append(hints, token.RR)
	}
	return hints, nil
}

// DefaultHints returns a list of DNS resource records with the root hints.
func DefaultHints() ([]dns.RR, error) {
	return ReadHints(strings.NewReader(rootHints))
}

const rootHints string = `
; <<>> DiG 9.8.3-P1 <<>> @199.7.91.13 +dnssec . ns
; (1 server found)
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 52047
;; flags: qr aa rd; QUERY: 1, ANSWER: 14, AUTHORITY: 0, ADDITIONAL: 27
;; WARNING: recursion requested but not available

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags: do; udp: 4096
;; QUESTION SECTION:
;.				IN	NS

;; ANSWER SECTION:
.			518400	IN	NS	l.root-servers.net.
.			518400	IN	NS	j.root-servers.net.
.			518400	IN	NS	g.root-servers.net.
.			518400	IN	NS	e.root-servers.net.
.			518400	IN	NS	d.root-servers.net.
.			518400	IN	NS	m.root-servers.net.
.			518400	IN	NS	k.root-servers.net.
.			518400	IN	NS	b.root-servers.net.
.			518400	IN	NS	h.root-servers.net.
.			518400	IN	NS	f.root-servers.net.
.			518400	IN	NS	c.root-servers.net.
.			518400	IN	NS	i.root-servers.net.
.			518400	IN	NS	a.root-servers.net.
.			518400	IN	RRSIG	NS 8 0 518400 20170831050000 20170818040000 15768 . OhAgk+tfsOYTIEluTsCAaitLM3+AjoKCzKXmA/LO1wB3/jz8qGgbk1Py Xhyc2JOjoRa8TkgJBUxRJL1kxmFuXI6kX9pkJqikHR/f4rP+O5YERB0Q pzv9GLnYcHGKdhqBXbbqRV/w0HrHLuFMB84z+czIfpraKHm7gyjJZFXh FfsmlyynvC62/5SesE7GW0UYOTcw8GIcxMBeYP9u7FInwT3/At+UbYt+ gY4KWnHFvCbP9Ilqsu/C8ZsaABRVvRJdaYf3CQfn4r6lzcxzpy0rMlp1 TS4kcA4g8Q0DlWDbpBkKYO+5FuEPqRBEr0DAshhk/nqC0As/8u0FSJFH 9paxhg==

;; ADDITIONAL SECTION:
a.root-servers.net.	3600000	IN	A	198.41.0.4
b.root-servers.net.	3600000	IN	A	192.228.79.201
c.root-servers.net.	3600000	IN	A	192.33.4.12
d.root-servers.net.	3600000	IN	A	199.7.91.13
e.root-servers.net.	3600000	IN	A	192.203.230.10
f.root-servers.net.	3600000	IN	A	192.5.5.241
g.root-servers.net.	3600000	IN	A	192.112.36.4
h.root-servers.net.	3600000	IN	A	198.97.190.53
i.root-servers.net.	3600000	IN	A	192.36.148.17
j.root-servers.net.	3600000	IN	A	192.58.128.30
k.root-servers.net.	3600000	IN	A	193.0.14.129
l.root-servers.net.	3600000	IN	A	199.7.83.42
m.root-servers.net.	3600000	IN	A	202.12.27.33
a.root-servers.net.	3600000	IN	AAAA	2001:503:ba3e::2:30
b.root-servers.net.	3600000	IN	AAAA	2001:500:200::b
c.root-servers.net.	3600000	IN	AAAA	2001:500:2::c
d.root-servers.net.	3600000	IN	AAAA	2001:500:2d::d
e.root-servers.net.	3600000	IN	AAAA	2001:500:a8::e
f.root-servers.net.	3600000	IN	AAAA	2001:500:2f::f
g.root-servers.net.	3600000	IN	AAAA	2001:500:12::d0d
h.root-servers.net.	3600000	IN	AAAA	2001:500:1::53
i.root-servers.net.	3600000	IN	AAAA	2001:7fe::53
j.root-servers.net.	3600000	IN	AAAA	2001:503:c27::2:30
k.root-servers.net.	3600000	IN	AAAA	2001:7fd::1
l.root-servers.net.	3600000	IN	AAAA	2001:500:9f::42
m.root-servers.net.	3600000	IN	AAAA	2001:dc3::35

;; Query time: 113 msec
;; SERVER: 199.7.91.13#53(199.7.91.13)
;; WHEN: Fri Aug 18 17:18:20 2017
;; MSG SIZE  rcvd: 1097
`
