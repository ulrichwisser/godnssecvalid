# godane
Godane is a [Go](http://golang.org/) implementation to verify an arbitrary DNSSEC chain.

[![Build Status](https://travis-ci.org/ulrichwisser/godane.svg?branch=master)](https://travis-ci.org/ulrichwisser/godane)
[![GoDoc](https://godoc.org/github.com/ulrichwisser/godane?status.svg)](https://godoc.org/github.com/ulrichwisser/godane)

### Documentation

* [API Reference](http://godoc.org/github.com/ulrichwisser/godane)
* [Example](https://github.com/ulrichwisser/godane/example/godane)

### Status
Thia is a first working version.

- TODO: currently CNAME indirection is not supported
- TODO: currently zones without glue are not supported

## Validate the chain
In each step all records need to be signed by the latest DNSKEY RR set pointed out by the latest DS RR set.


### Installation

    go get github.com/ulrichwisser/godane
