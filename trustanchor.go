package godane

import (
	"fmt"
	"os"

	"github.com/miekg/dns"
)

func GetTrustAnchors(filename string) []dns.RR {
	anchors := make([]dns.RR, 0)
	f, err := os.Open(filename)
	if err != nil {
		panic(err)
	}
	defer f.Close()

	//
	for token := range dns.ParseZone(f, "", "") {
		if token.Error != nil {
			fmt.Println("Error: ", token.Error)
		}
		if token.RR.Header().Rrtype == dns.TypeDS {
			anchors = append(anchors, token.RR)
		}
		if token.RR.Header().Rrtype == dns.TypeDNSKEY {
			anchors = append(anchors, token.RR.(*dns.DNSKEY).ToDS(dns.SHA256))
		}
	}
	return anchors
}
