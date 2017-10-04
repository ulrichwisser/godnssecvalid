package godnssecvalid

import (
	"fmt"

	"github.com/miekg/dns"
)

// GetAnswer returns a list of resource records of the desired type and for the desired label.
func GetAnswer(servers []string, trustanchors []dns.RR, fqdn string, qtype uint16) ([]dns.RR, error) {
	chain, err := GetChain(servers, fqdn, qtype)
	if err != nil {
		return nil, err
	}
	valid := ValidateChain(chain, trustanchors)
	if !valid {
		return nil, fmt.Errorf("No valid chain found")
	}

	result := make([]dns.RR, 0)
	for _, rr := range chain {
		if rr.Header().Name == fqdn && rr.Header().Rrtype == qtype {
			result = append(result, rr)
		}
	}
	return result, nil
}
