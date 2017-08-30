package godane

import (
	"fmt"

	"github.com/miekg/dns"
)

func getKSK(ds []dns.RR, keys []dns.RR) []dns.RR {

	// Check parameters
	if len(ds) == 0 || !dns.IsRRset(ds) || ds[0].Header().Rrtype != dns.TypeDS {
		if Verbose {
			fmt.Printf("First parameter is not a DS set")
		}
		return nil
	}
	if len(keys) == 0 || !dns.IsRRset(keys) || keys[0].Header().Rrtype != dns.TypeDNSKEY {
		if Verbose {
			fmt.Printf("Second parameter is not a DNSKEY set")
		}
		return nil
	}

	// This is where we save the results
	result := make([]dns.RR, 0)

	for _, dsrr := range ds {
		for _, keyrr := range keys {
			if dsrr.(*dns.DS).KeyTag == keyrr.(*dns.DNSKEY).KeyTag() {
				result = append(result, keyrr.(*dns.DNSKEY))
			}
		}
	}
	return result
}

func checkRRSIG(keys []dns.RR, rrset []dns.RR, rrsigs []dns.RR) bool {

	// Check parameters
	if len(keys) == 0 || !dns.IsRRset(keys) || keys[0].Header().Rrtype != dns.TypeDNSKEY {
		if Verbose {
			fmt.Printf("First parameter is not a DNSKEY set")
		}
		return false
	}
	if len(rrset) == 0 || !dns.IsRRset(rrsigs) {
		if Verbose {
			fmt.Printf("Second parameter is not a RR set")
		}
		return false
	}
	if len(rrsigs) == 0 || !dns.IsRRset(rrsigs) || rrsigs[0].Header().Rrtype != dns.TypeRRSIG {
		if Verbose {
			fmt.Printf("Third parameter is not a RRSIG set")
		}
		return false
	}

	// now check the signature
	if Verbose {
		fmt.Println("===================\nCheckRRSIG:")
		fmt.Printf("  RRset has %d RRs of type %s\n", len(rrset), dns.TypeToString[rrset[0].Header().Rrtype])
	}
	for _, key := range keys {
		if Verbose {
			fmt.Printf("  Key: %s\n", key.String())
		}
		for _, rrsig := range rrsigs {
			if Verbose {
				fmt.Printf("  Sig: %s\n", rrsig.String())
			}
			err := rrsig.(*dns.RRSIG).Verify(key.(*dns.DNSKEY), rrset)
			if err == nil {
				if Verbose {
					fmt.Println("  Valid signature")
				}
				return true
			} else {
				if Verbose {
					fmt.Println("  No valid signature")
				}
			}
		}
	}
	return false
}

func ValidateChain(chain []dns.RR, trustanchor []dns.RR) bool {

	// process chain into RR sets
	chainset := make([][]dns.RR, 0)
	var oldtype uint16
	for _, rr := range chain {
		if rr.Header().Rrtype != oldtype {
			chainset = append(chainset, make([]dns.RR, 0))
		}
		chainset[len(chainset)-1] = append(chainset[len(chainset)-1], rr)
		oldtype = rr.Header().Rrtype
	}
	if Verbose {
		fmt.Printf("Chain has %d RR sets\n", len(chainset))
		for i := range chainset {
			fmt.Printf("  RRset %2d has %2d RRs of type %s\n", i, len(chainset[i]), dns.TypeToString[chainset[i][0].Header().Rrtype])
		}
	}

	// did we find sets
	if len(chainset) == 0 {
		if Verbose {
			fmt.Println("No RR sets found")
		}
		return false
	}

	// Must be even number of RR sets (RR set + RRSIG)
	if len(chainset)%2 != 0 {
		if Verbose {
			fmt.Println("Chain has odd number of RR sets.")
		}
		return false
	}

	// check RR sets
	for i := range chainset {
		if !dns.IsRRset(chainset[i]) {
			if Verbose {
				fmt.Printf("RR set %d is not an RR set!!!\n", i)
			}
			return false
		}
	}

	// check each RR set is followed by a RR set with RRSIG that cover the first set
	for i := 0; i < len(chainset); i = i + 2 {
		if chainset[i][0].Header().Rrtype == dns.TypeRRSIG {
			if Verbose {
				fmt.Printf("RR set %d is of type RRSIG\n", i)
			}
			return false
		}
		if chainset[i+1][0].Header().Rrtype != dns.TypeRRSIG {
			if Verbose {
				fmt.Printf("RR set %d is not of type RRSIG\n", i)
			}
			return false
		}
		if chainset[i+1][0].(*dns.RRSIG).TypeCovered != chainset[i][0].Header().Rrtype {
			if Verbose {
				fmt.Printf("RR set %d is of type %s, but RR set %d covers type %s\n", i, dns.TypeToString[chainset[i][0].Header().Rrtype], i+1, dns.TypeToString[chainset[i+1][0].Header().Rrtype])
			}
			return false
		}
	}

	// First RR set must be DNSKEY
	if chainset[0][0].Header().Rrtype != dns.TypeDNSKEY {
		if Verbose {
			fmt.Printf("First RR set is not of type DNSKEY, but instead of type %s\n", dns.TypeToString[chainset[0][0].Header().Rrtype])
		}
		return false
	}

	// Now validate all sets
	keys := getKSK(trustanchor, chainset[0])
	for i := 0; i < len(chainset); i = i + 2 {
		if !checkRRSIG(keys, chainset[i], chainset[i+1]) {
			if Verbose {
				fmt.Printf("RR set %d is not signed by RR set %d\n", i, i+1)
			}
			return false
		}
		if chainset[i][0].Header().Rrtype == dns.TypeDS {
			keys = getKSK(chainset[i], chainset[i+2])
			if keys == nil || len(keys) == 0 {
				if Verbose {
					fmt.Printf("RR set %d did not identify any keys in RR set %d\n", i, i+2)
				}
				return false
			}
		}
		if chainset[i][0].Header().Rrtype == dns.TypeDNSKEY {
			keys = chainset[i]
		}
	}

	// seems we've done it
	return true
}
