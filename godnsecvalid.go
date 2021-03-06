// Copyright 2017 by Ulrich Wisser
// Source code is licensed under GPL-3.0
// (which should come together with the source code)

// Package godnssecvalid implements collection and verification of a DNSSEC chain
//
// Overview
//
// The GetChain function will traverse the DNS tree beginning at the root
// servers. It will build a chain of DNSKEY, DS and RRSIG records until the
// desired information is collected.
//
// ValidateChain will take a chain of DNS resource records and verify all
// signatures beginning with the trust anchor.
//
// Example usage
// See example/godane for an example command line tlsa verifier
//
// In short, do something like this
//
//  tlsa, _:= dns.TLSAName(dns.Fqdn("example.com"), "443", "tcp")
//  chain, _ := godnssecvalid.GetChain(godnssecvalid.GetDefaultResolvers(), tlsa, dns.TypeTLSA)
//  anchors, _ := godnssecvalid.GetDefaultTrustAnchors()
//  valid := godnssecvalid.ValidateChain(chain, anchors)
//
// Of course, you should do proper error checking!
//
package godnssecvalid

// Verbose set to true will generate debug output on stdout
var Verbose = false
