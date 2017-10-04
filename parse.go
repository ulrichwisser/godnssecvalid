package godnssecvalid

import (
	"fmt"

	"github.com/miekg/dns"
)

func getRRset(rrlist []dns.RR, qtype uint16) []dns.RR {
	if Verbose {
		fmt.Printf("getRRset(rrlist[%d], %d<%s>)\n", len(rrlist), qtype, dns.TypeToString[qtype])
	}
	result := make([]dns.RR, 0)
	for _, rr := range rrlist {
		if Verbose {
			fmt.Printf("RR: %s\n", rr.String())
		}
		if rr.Header().Rrtype == qtype {
			result = append(result, rr)
		}
		if rr.Header().Rrtype == dns.TypeRRSIG && rr.(*dns.RRSIG).TypeCovered == qtype {
			result = append(result, rr)
		}
	}
	return result
}
