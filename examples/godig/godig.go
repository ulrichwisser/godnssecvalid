package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/miekg/dns"
	"github.com/ulrichwisser/godnssecvalid"
)

func main() {

	// define and parse command line arguments
	var verbose bool = false

	flag.BoolVar(&verbose, "v", false, "print more information while running")
	flag.Parse()

	if flag.NArg() != 2 {
		flag.Usage()
		fmt.Println()
		os.Exit(1)
	}

	godnssecvalid.Verbose = verbose
	anchors, _ := godnssecvalid.GetDefaultTrustAnchors()
	domain := dns.Fqdn(flag.Arg(0))
	var qtype uint16
	var ok bool
	if qtype, ok = dns.StringToType[strings.ToUpper(flag.Arg(1))]; !ok {
		fmt.Printf("Qtype %s not known.\n", flag.Arg(1))
		os.Exit(5)
	}
	resolvers, _ := godnssecvalid.GetDefaultResolvers()
	answer, err := godnssecvalid.GetAnswer(resolvers, anchors, domain, qtype)
	if err != nil {
		fmt.Println(err)
		os.Exit(0)
	}

	if answer == nil || len(answer) == 0 {
		fmt.Printf("No answer found.\n")
		os.Exit(0)
	}

	for _, rr := range answer {
		fmt.Println(rr)
	}
}
