package godnssecvalid

import (
	"fmt"
	"strings"

	"github.com/miekg/dns"
)

// GetChain uses the specified resolvers and builds a list of DNSKEY, DS and RRSIG
// records leading to the requested record. The fqdn is seperated in labels and
// for each label DNSKEY and RRSIG and DS and RRSIG records are requested from
// one of the resolvers. Any failure is silently ignored. For the last labels
// qtype records and RRSIG are requested. Any failure to do so is reported back.
// We can not know where a zone cut is. Therefor we try all labels, but fail
// silently if no records can be found.
// servers - a list of resolvers to uses
// fqdn - full qualified domain name
// qtype - type of DNS record to retrieve
func GetChain(servers []string, fqdn string, qtype uint16) ([]dns.RR, error) {
	if Verbose {
		fmt.Printf("GODANE: GetChain(\"%s\", %d<%s>)\n", fqdn, qtype, dns.TypeToString[qtype])
	}

	// prepare labels
	fqdn = dns.Fqdn(fqdn)
	labels := strings.Split(fqdn, ".")
	reverseLabels(labels)
	if Verbose {
		fmt.Print("LABELS ")
		for _, label := range labels {
			fmt.Print(`"`, label, `",`)
		}
		fmt.Println()
	}

	// save the result
	chain := make([]dns.RR, 0)

	// which zone to query
	zone := ""

	// run through all labels
	for _, label := range labels {
		// compute zone
		if zone == "." {
			zone = label + zone
		} else {
			zone = label + "." + zone
		}
		if Verbose {
			fmt.Printf("\n\n\n========================================================================\n")
			fmt.Printf("Zone: %s\n", zone)
			fmt.Printf("Chain:\n")
			for _, rr := range chain {
				fmt.Println(rr)
			}
		}

		// get DS records for zone
		dsmsg := resolv(servers, zone, dns.TypeDS)
		// ignore if no DS records were found
		if dsmsg != nil {
			if Verbose {
				fmt.Printf("DS\n%s\n", dsmsg.String())
			}
			// save DS records in chain
			chain = append(chain, getRRset(dsmsg.Answer, dns.TypeDS)...)
			chain = append(chain, getRRset(dsmsg.Ns, dns.TypeDS)...)
		}

		// get DNSKEY records for zone
		keymsg := resolv(servers, zone, dns.TypeDNSKEY)
		// ignore if no DNSKEY records were found
		if keymsg != nil {
			if Verbose {
				fmt.Printf("DNSKEY\n%s\n", keymsg.String())
			}
			// save DNSKEY records in chain
			chain = append(chain, getRRset(keymsg.Answer, dns.TypeDNSKEY)...)
			chain = append(chain, getRRset(keymsg.Ns, dns.TypeDNSKEY)...)
		}

	}

	// last step
	// Add desired RR with RRSIG
	qmsg := resolv(servers, fqdn, qtype)
	if qmsg == nil {
		return chain, fmt.Errorf("Could not get %s IN %s", fqdn, dns.TypeToString[qtype])
	}

	if Verbose {
		fmt.Printf("%s\n%s\n", dns.TypeToString[qtype], qmsg.String())
	}
	chain = append(chain, getRRset(qmsg.Answer, qtype)...)
	chain = append(chain, getRRset(qmsg.Ns, qtype)...)

	if Verbose {
		fmt.Printf("FQDN: %s\n", fqdn)
		fmt.Printf("Chain:\n")
		for _, rr := range chain {
			fmt.Println(rr)
		}
	}

	// done
	return chain, nil
}

func reverseLabels(labels []string) {
	for i, j := 0, len(labels)-1; i < j; i, j = i+1, j-1 {
		labels[i], labels[j] = labels[j], labels[i]
	}
}
