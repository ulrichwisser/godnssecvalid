# godnssecvalid/examples/godane
Godig is a [Go](https://golang.org/) implementation to retrieve DNS records with DNSSEC validation.


### usage

godig [-v] <domain> <record type>

> -v        verbose  - print (much) more information
>
> <domain>  domain   - full qualified domain name, used to compute TLSA label
>
><record type>      - identify DNS record type (e.g. A TXT TLSA ...

### TLSA label

Godig tries to retrieve the requested record and to validate the whole DNSSEC chain for the records.

Godig uses the system confugured resolvers (/etc/resolv.conf) and the current root trust anchors.


### Status
This is an example project to illustrate the usage of the [Godnssecvalid](https://github.com/ulrichwisser/godane) library.
