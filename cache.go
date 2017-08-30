package godane

import (
	"fmt"
	"net"

	"github.com/miekg/dns"
)

func getNS(cache []dns.RR, zone string) []string {
	if Verbose {
		fmt.Printf("getNS(%s)\n", zone)
	}
	result := make([]string, 0)
	for _, rr := range findRR(cache, zone, dns.TypeNS) {
		result = append(result, rr.(*dns.NS).Ns)
	}
	if Verbose {
		fmt.Printf("getIP results: ")
		fmt.Println(result)
	}
	return result
}

func getIP(cache []dns.RR, name string) []*net.IP {
	if Verbose {
		fmt.Printf("getIP(%s)\n", name)
	}
	result := make([]*net.IP, 0)
	for _, rr := range findRR(cache, name, dns.TypeAAAA) {
		result = append(result, &rr.(*dns.AAAA).AAAA)
	}
	for _, rr := range findRR(cache, name, dns.TypeA) {
		result = append(result, &rr.(*dns.A).A)
	}
	if Verbose {
		fmt.Print("getIP results: ")
		fmt.Println(result)
	}
	return result
}

func findRR(cache []dns.RR, name string, qtype uint16) []dns.RR {
	result := make([]dns.RR, 0)
	for _, rr := range cache {
		if rr.Header().Name == name && rr.Header().Rrtype == qtype {
			result = append(result, rr)
		}
	}
	return result
}
