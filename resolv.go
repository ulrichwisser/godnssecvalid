package godane

import (
	"fmt"
	"net"
	"time"

	"github.com/miekg/dns"
)

const (
	resolvtimeout time.Duration = 5 * time.Second
	edns0size     uint16        = 4096
)

// ask all servers and return first result
func resolv(servers []string, qname string, qtype uint16) *dns.Msg {
	if len(servers) == 0 {
		if Verbose {
			fmt.Printf("resolv: no resolvers found.\n")
		}
		return nil
	}

	for _, server := range servers {
		msg, err := resolving(server, qname, qtype)
		if Verbose && err != nil {
			fmt.Printf("resolv: error resolving. %s\n", err)
		}
		if msg != nil {
			return msg
		}
	}
	if Verbose {
		fmt.Printf("resolv: no answers from resolvers(%d)", len(servers))
	}
	return nil
}

// resolv will send a query and return the result
func resolving(server string, qname string, qtype uint16) (*dns.Msg, error) {
	if Verbose {
		fmt.Printf("resolving(%s, %s, %d<%s>)\n", server, qname, qtype, dns.TypeToString[qtype])
	}
	// Setting up query
	query := new(dns.Msg)
	query.SetQuestion(qname, qtype)
	query.SetEdns0(edns0size, false)
	query.IsEdns0().SetDo()
	query.RecursionDesired = true
	query.AuthenticatedData = true

	// Setting up resolver
	client := new(dns.Client)
	client.ReadTimeout = resolvtimeout

	// make the query and wait for answer
	r, _, err := client.Exchange(query, server)

	// check for errors
	if err != nil {
		return nil, fmt.Errorf("resolving: error resolving %s (server %s), %s", qname, server, err)
	}
	if r == nil {
		return nil, fmt.Errorf("resolving: no answer resolving %s (server %s)", qname, server)
	}
	if r.Rcode != dns.RcodeSuccess {
		return nil, fmt.Errorf("resolving: could not resolve %s rcode %s  (server %s)", qname, dns.RcodeToString[r.Rcode], server)
	}

	return r, nil
}

func ip2Resolver(ip *net.IP) string {
	return net.JoinHostPort(ip.String(), "53")
}

func isIPv4(ip *net.IP) bool {
	return ip.To4() != nil
}

func isIPv6(ip *net.IP) bool {
	if ip.To4() != nil {
		return false
	}
	return ip.To16() != nil
}

// getResolvers will read the list of resolvers from /etc/resolv.conf
func GetDefaultResolvers() ([]string, error) {
	resolvers := make([]string, 0)

	conf, err := dns.ClientConfigFromFile("/etc/resolv.conf")
	if conf == nil {
		return nil, fmt.Errorf("Cannot initialize local resolver: %s", err)
	}
	for _, server := range conf.Servers {
		resolvers = append(resolvers, net.JoinHostPort(server, "53"))
	}
	if len(resolvers) == 0 {
		return nil, fmt.Errorf("No resolvers found")
	}
	return resolvers, nil
}
