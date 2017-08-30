package godane

import (
	"fmt"

	"github.com/miekg/dns"
)

func parseAnswer(rrlist []dns.RR, cache []dns.RR) []dns.RR {
	QTYPES := [3]uint16{dns.TypeTLSA, dns.TypeDS, dns.TypeDNSKEY}
	for _, rr := range rrlist {
		if Verbose {
			fmt.Printf("RR: %s\n", rr.String())
		}
		for _, qtype := range QTYPES {
			if rr.Header().Rrtype == qtype {
				cache = append(cache, rr)
			}
			if rr.Header().Rrtype == dns.TypeRRSIG && rr.(*dns.RRSIG).TypeCovered == qtype {
				cache = append(cache, rr)
			}
		}
	}
	return cache
}

func parseAdditional(rrlist []dns.RR, cache []dns.RR) []dns.RR {
	QTYPES := [3]uint16{dns.TypeA, dns.TypeAAAA, dns.TypeNS}
	for _, rr := range rrlist {
		if Verbose {
			fmt.Printf("RR: %s\n", rr.String())
		}
		for _, qtype := range QTYPES {
			if rr.Header().Rrtype == qtype {
				cache = append(cache, rr)
			}
		}
	}
	return cache
}
