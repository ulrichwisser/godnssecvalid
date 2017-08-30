package godane

import (
	"errors"
	"fmt"

	"github.com/miekg/dns"
)

var Verbose bool = false

func GetChain(tlsa string, hints []dns.RR) ([]dns.RR, error) {
	if Verbose {
		fmt.Printf("GODANE: GetChain(\"%s\", [%d]dns.RR)\n", tlsa, len(hints))
	}

	zone := "."
	chain := make([]dns.RR, 0)
	cache := hints

	run := 0
	for {
		run = run + 1

		// compute zone
		if len(chain) > 0 {
			zone = chain[len(chain)-1].Header().Name
		} else {
			zone = `.`
		}

		if Verbose {
			fmt.Printf("\n\n\n========================================================================\nRun %d\n", run)
			fmt.Printf("Zone: %s\n", zone)
			fmt.Printf("Chain:\n")
			for _, rr := range chain {
				fmt.Println(rr)
			}
		}

		// get keys for zone
		keymsg := resolv(cache, zone, zone, dns.TypeDNSKEY)
		if Verbose {
			fmt.Printf("DNSKEY\n%s\n", keymsg.String())
		}
		chain = parseAnswer(keymsg.Answer, chain)

		// get TLSA RR or we do get a referral
		tlsamsg := resolv(cache, zone, tlsa, dns.TypeTLSA)
		if Verbose {
			fmt.Printf("TLSA\n%s\n", tlsamsg.String())
		}
		if tlsamsg == nil {
			return nil, errors.New("Resolving error")
		}
		chain = parseAnswer(tlsamsg.Answer, chain)
		chain = parseAnswer(tlsamsg.Ns, chain)
		cache = parseAdditional(tlsamsg.Ns, cache)
		cache = parseAdditional(tlsamsg.Extra, cache)

		// check if we are done
		if len(findRR(chain, tlsa, dns.TypeTLSA)) > 0 {
			break
		}

		// Endless loop?
		if run >= 20 {
			return nil, errors.New("Seems we are in an endless loop.")
		}
	}

	if Verbose {
		fmt.Printf("Zone: %s\n", zone)
		fmt.Printf("Chain:\n")
		for _, rr := range chain {
			fmt.Println(rr)
		}
	}

	// done
	return chain, nil
}
