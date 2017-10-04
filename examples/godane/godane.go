package main

import (
	"flag"
	"fmt"
	"os"
	"strconv"

	"github.com/miekg/dns"
	"github.com/ulrichwisser/godnssecvalid"
)

type Strings []string

func (s *Strings) String() string {
	return fmt.Sprintf("%s", *s)
}

func (s *Strings) Set(value string) error {
	*s = append(*s, value)
	return nil
}

func main() {

	// define and parse command line arguments
	var verbose bool = false
	var port uint64 = 443
	var udp bool = false
	var resolvers Strings = make(Strings, 0)

	flag.BoolVar(&verbose, "v", false, "print more information while running")
	flag.Uint64Var(&port, "p", 443, "Specify port for TLSA record")
	flag.BoolVar(&udp, "udp", false, "specify udp as transport (default tcp)")
	flag.Var(&resolvers, "resolver", "give ip addresses to resolvers")
	flag.Var(&resolvers, "r", "give ip addresses to resolvers")
	flag.Parse()

	if flag.NArg() != 1 {
		flag.Usage()
		fmt.Println()
		//fmt.Printf("Usage: %s [-v] [-udp] [-p <port>] <domain> \n", os.Args[0])
		os.Exit(1)
	}

	godnssecvalid.Verbose = verbose
	var transport = "tcp"
	if udp {
		transport = "udp"
	}
	var domain = flag.Arg(0)
	tlsa, err := dns.TLSAName(dns.Fqdn(domain), strconv.FormatUint(port, 10), transport)
	if err != nil {
		panic(err)
	}

	// check/get resolver list
	if len(resolvers) == 0 {
		var err error
		resolvers, err = godnssecvalid.GetDefaultResolvers()
		if err != nil {
			fmt.Printf("resolv: error finding resolvers. %s\n", err)
			os.Exit(5)
		}
	}

	chain, _ := godnssecvalid.GetChain(resolvers, tlsa, dns.TypeTLSA)
	anchors, _ := godnssecvalid.GetDefaultTrustAnchors()
	valid := godnssecvalid.ValidateChain(chain, anchors)

	// print result
	if valid {
		fmt.Println("Chain is valid")
	} else {
		fmt.Println("Chain is not valid")
	}
}
