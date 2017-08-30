# godane
Build the DNS chain from root to the TLSA record and validate the chain

## Build the chain
Starting at the DNS root the chain is build to contain DNSKEY and DS records down to the target zone containing the TLSA record.

- TODO: currently CNAME indirection is not supported
- TODO: currently zones without glue are not supported

## Validate the chain
In each step all records need to be signed by the latest DNSKEY RR set pointed out by the latest DS RR set.

## Example
See example/godane for an example command line tlsa verifier

In short, do something like this
```
domain := "example.com"
port := 443 // 443 = https, 25 = smtp
transport := "tcp" // or "udp"
tlsa, _:= dns.TLSAName(dns.Fqdn(domain), strconv.FormatUint(port, 10), transport)
hints, _ := godane.DefaultHints()
chain, _ := godane.GetChain(tlsa, hints)
anchors, _ := godane.DefaultTrustAnchors()
valid := godane.ValidateChain(chain, anchors)
```
Of course, you should do proper error checking!
