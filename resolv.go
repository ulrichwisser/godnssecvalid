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
func resolv(hints []dns.RR, zone string, qname string, qtype uint16) *dns.Msg {
	iplist := make([]*net.IP, 0)
	for _, ns := range getNS(hints, zone) {
		for _, ip := range getIP(hints, ns) {
			iplist = append(iplist, ip)
		}
	}
	for _, ip := range iplist {
		msg := resolving(ip, qname, qtype)
		if msg != nil {
			return msg
		}
	}
	return nil
}

// resolv will send a query and return the result
func resolving(ip *net.IP, qname string, qtype uint16) *dns.Msg {
	if Verbose {
		fmt.Printf("resolving(%s, %s, %d)\n", ip.String(), qname, qtype)
	}
	// Setting up query
	query := new(dns.Msg)
	query.SetQuestion(qname, qtype)
	query.SetEdns0(edns0size, false)
	query.IsEdns0().SetDo()
	query.RecursionDesired = false
	query.AuthenticatedData = true

	// Setting up resolver
	client := new(dns.Client)
	client.ReadTimeout = resolvtimeout

	// make the query and wait for answer
	server := ip2Resolver(ip)
	r, _, err := client.Exchange(query, server)

	// check for errors
	if err != nil {
		if Verbose {
			fmt.Printf("%-30s: Error resolving %s (server %s)\n", qname, err, server)
		}
		return nil
	}
	if r == nil {
		if Verbose {
			fmt.Printf("%-30s: No answer (Server %s)\n", qname, server)
		}
		return nil
	}
	if r.Rcode != dns.RcodeSuccess {
		if Verbose {
			fmt.Printf("%-30s: %s (Rcode %d, Server %s)\n", qname, dns.RcodeToString[r.Rcode], r.Rcode, server)
		}
		return nil
	}

	return r
}

func ip2Resolver(ip *net.IP) string {
	if isIPv4(ip) {
		return ip.String() + ":53"
	}
	if isIPv6(ip) {
		return "[" + ip.String() + "]:53"
	}
	return "NOT AN IP"
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
