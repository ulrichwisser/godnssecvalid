package main

import (
	"flag"
	"fmt"
	"os"
	"strconv"

	"github.com/miekg/dns"
	"github.com/ulrichwisser/godane"
)

func main() {

	// define and parse command line arguments
	var verbose bool = false
	var port uint64 = 443
	var udp bool = false

	flag.BoolVar(&verbose, "v", false, "print more information while running")
	flag.Uint64Var(&port, "p", 443, "Specify port for TLSA record")
	flag.BoolVar(&udp, "udp", false, "specify udp as transport (default tcp)")
	flag.Parse()

	if flag.NArg() != 1 {
		flag.Usage()
		fmt.Println()
		//fmt.Printf("Usage: %s [-v] [-udp] [-p <port>] <domain> \n", os.Args[0])
		os.Exit(1)
	}

	godane.Verbose = verbose
	var transport = "tcp"
	if udp {
		transport = "udp"
	}
	var domain = flag.Arg(0)
	fmt.Println(dns.Fqdn(domain))
	tlsa, err := dns.TLSAName(dns.Fqdn(domain), strconv.FormatUint(port, 10), transport)
	if err != nil {
		panic(err)
	}
	if verbose {
		fmt.Printf("Domain:    %s\nPort:      %d\nTransport: %s\nTLSA:   %s\n", domain, port, transport, tlsa)
	}

	hints, _ := godane.DefaultHints()
	chain, _ := godane.GetChain(tlsa, hints)
	anchors, _ := godane.DefaultTrustAnchors()
	valid := godane.ValidateChain(chain, anchors)
	if valid {
		fmt.Println("Chain is valid")
	} else {
		fmt.Println("Chain is not valid")
	}
}
