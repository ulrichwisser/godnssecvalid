package godnssecvalid

import (
	"fmt"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

var rawdata = `
example.com.			666	IN	A	198.51.100.0
example.com.			666	IN	A	198.51.100.2
example.com.			666	IN	A	198.51.100.3
example.com.			666	IN	A	198.51.100.4
example.com.			666	IN	A	198.51.100.5
example.com.			666	IN	AAAA	2001:db8::1111
example.com.			666	IN	AAAA	2001:db8::2222
example.com.			666	IN	AAAA	2001:db8::3333
example.com.			666	IN	RRSIG	A 5 2 60 20171014074502 20171004074502 25665 example.com. qPNbTL885pTKZ7Lne6cyHmI2ISAJ1oO/3GwW+D0T+XMSjnFc4LWvV dYi5zffVuzBK7168x+z7KjVL7S9VTCNZ/HQSRgQzQbNQjn20L1k7iGN2 EL1SInN3i4xMg7anz3x9JNhYOIRh7FdHmuczy+AcBngrBISPhDQmyL7c hZY=
example.com.			666	IN	RRSIG	AAAA 5 2 60 20171014074502 20171004074502 25665 example.com. qPNbTL885pTKZ7Lne6cyHmI2ISAJ1oO/3GwW+DMSSDwjnFc4LWvV dYi5zffVuzBK7168x+z7KjVL7S9VTCNZ/HQSRgQzQbNQjn20L1k7iGN2 EL1SInN3i4xMg7anz3x9JNhYOIRh7FdHmuczy+AcBngrBISPhDQmyL7c hZY=
example.com.			666	IN	RRSIG	AAAA 5 2 60 20171014074502 20171004074502 12345 example.com. qPNbTL885pTKZ7Lne6cyHmI2ISAJ1oO/3GwW+DMSSDwjnFc4LWvV dYi5zffVuzBK7168x+z7KjVL7S9VTCNZ/HQSRgQzQbNQjn20L1k7iGN2 EL1SInN3i4xMg7anz3x9JNhYOIRh7FdHmuczy+AcBngrBISPhDQmyL7c hZY=
_25._tcp.mx1.example.com.	777	IN	TLSA	3 1 1 0894A6827F435CCB7435552290FF13E704776E4568235BBC899F515D E3314CE3
_25._tcp.mx1.example.com.	777	IN	RRSIG	TLSA 5 5 3600 20171014074502 20171004074502 25665 example.com. FaFa4OM9wvGz/9D6ayI5XD/F55y1t+xlXA9qInOj3nsOruT FX0ihZiVmobr4TUostrWKuoXVBBjMK9YnwF1gKq1Oi5jRTj1FgPg/vGZ 28j1sypLXY++tKyInl4Ov14R6JdX8HGG0xjiuNHEFuGWCjfeK8+yo60A 4tQ=
`

func records() []dns.RR {
	anchors := make([]dns.RR, 0)
	for token := range dns.ParseZone(strings.NewReader(rawdata), "", "") {
		if token.Error != nil {
			fmt.Println("Error in rawdata: ", token.Error)
			return nil
		}
		anchors = append(anchors, token.RR)
	}
	return anchors
}

func TestGetRRsett(t *testing.T) {
	rrlist := records()
	alistsec := getRRset(rrlist, dns.TypeA)
	if len(alistsec) != 6 {
		t.Error("Expected 6 A + RRSIG records, got ", len(alistsec))
	}
	a4listsec := getRRset(rrlist, dns.TypeAAAA)
	if len(a4listsec) != 5 {
		t.Error("Expected 5 AAAA + RRSIG records, got ", len(a4listsec))
	}
	txtlistsec := getRRset(rrlist, dns.TypeTXT)
	if len(txtlistsec) != 0 {
		t.Error("Expected 0 TXT + RRSIG records, got ", len(txtlistsec))
	}

}
