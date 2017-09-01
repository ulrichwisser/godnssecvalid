// Copyright 2017 by Ulrich Wisser
// Source code is licensed under GPL-3.0
// (which should come together with the source code)

// Package godane implements collection and verification of a DNSSEC chain
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
//  domain := "example.com"
//  port := 443 // 443 = https, 25 = smtp
//  transport := "tcp" // or "udp"
//  tlsa, _:= dns.TLSAName(dns.Fqdn(domain), strconv.FormatUint(port, 10), transport)
//  hints, _ := godane.DefaultHints()
//  chain, _ := godane.GetChain(tlsa, hints)
//  anchors, _ := godane.DefaultTrustAnchors()
//  valid := godane.ValidateChain(chain, anchors)
//
// Of course, you should do proper error checking!
//
package godane
