package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/miekg/dns"
	"github.com/ulrichwisser/godane/rrcache"
)

var verbose bool = false

func main() {

	// define and parse command line arguments
	flag.BoolVar(&verbose, "verbose", false, "print more information while running")
	flag.BoolVar(&verbose, "v", false, "print more information while running")
	flag.Parse()

	if flag.NArg() != 1 {
		fmt.Printf("Usage: %s [-v] <filename>\n", os.Args[0])
		os.Exit(1)
	}

	var domain = flag.Arg(0)
	tlsa, _ := dns.TLSAName(dns.Fqdn(domain), "443", "tcp")

	if verbose {
		fmt.Printf("Domain: %s\nTLSA:   %s\n", domain, tlsa)
	}

	zone := "."
	chain := rrcache.NewRRcache()
	cache := rrcache.NewRRcache()
	cache.ReadCachefile("./hints")

	run := 0
	for {
		run = run + 1

		// compute zone
		if len(chain.Cache) > 0 {
			zone = chain.Cache[len(chain.Cache)-1].Header().Name
		} else {
			zone = `.`
		}

		if verbose {
			fmt.Printf("\n\n\n========================================================================\nRun %d\n", run)
			fmt.Printf("Zone: %s\n", zone)
			fmt.Printf("Chain:\n")
			for _, rr := range chain.Cache {
				fmt.Println(rr)
			}
		}

		// get keys for zone
		keymsg := resolv(cache, zone, zone, dns.TypeDNSKEY)
		if verbose {
			fmt.Printf("DNSKEY\n%s\n", keymsg.String())
		}
		ParseAnswer(keymsg.Answer, chain)

		// get TLSA RR or we do get a referral
		tlsamsg := resolv(cache, zone, tlsa, dns.TypeTLSA)
		if verbose {
			fmt.Printf("TLSA\n%s\n", tlsamsg.String())
		}
		ParseAnswer(tlsamsg.Answer, chain)
		ParseAnswer(tlsamsg.Ns, chain)
		ParseAdditional(tlsamsg.Ns, cache)
		ParseAdditional(tlsamsg.Extra, cache)

		// check if we are done
		if len(chain.FindRR(tlsa, dns.TypeTLSA)) > 0 {
			break
		}

		// Endless loop?
		if run >= 20 {
			panic("Seems we are in an endless loop.")
		}
	}

	if verbose {
		fmt.Printf("Zone: %s\n", zone)
		fmt.Printf("Chain:\n")
		for _, rr := range chain.Cache {
			fmt.Println(rr)
		}
	}

	valid := ValidateChain(chain, GetTrustAnchors("./trustanchor"))
	if valid {
		fmt.Println("Chain is valid")
	} else {
		fmt.Println("Chain is not valid")
	}
}

func ParseAnswer(rrlist []dns.RR, cache *rrcache.RRcache) {
	QTYPES := [3]uint16{dns.TypeTLSA, dns.TypeDS, dns.TypeDNSKEY}
	for _, rr := range rrlist {
		if verbose {
			fmt.Printf("RR: %s\n", rr.String())
		}
		for _, qtype := range QTYPES {
			if rr.Header().Rrtype == qtype {
				cache.AddToCache(rr)
			}
			if rr.Header().Rrtype == dns.TypeRRSIG && rr.(*dns.RRSIG).TypeCovered == qtype {
				cache.AddToCache(rr)
			}
		}
	}
}

func ParseAdditional(rrlist []dns.RR, cache *rrcache.RRcache) {
	QTYPES := [3]uint16{dns.TypeA, dns.TypeAAAA, dns.TypeNS}
	for _, rr := range rrlist {
		if verbose {
			fmt.Printf("RR: %s\n", rr.String())
		}
		for _, qtype := range QTYPES {
			if rr.Header().Rrtype == qtype {
				cache.AddToCache(rr)
			}
		}
	}
}
