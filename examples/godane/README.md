# godnssecvalid/examples/godane
Godane is a [Go](https://golang.org/) implementation to verify a DANE TLSA records.


### usage

godane [-v] [-udp] [-p <port>] [-r <resolver ip>|...] <domain>

> -v        verbose  - print (much) more information
>
> -udp      udp      - use udp instead of tcp as transport to compute TLSA label (default: tcp)
>
> -p <port> port     - specify which port to use to compute TLSA label (default: 443)
>
> -r <ip>   resolver - specify which resolver(s) to use (default: resolver list from /etc/resolv.conf)
>
>                      can be given multiple times
>
> <domain>  domain   - full qualified domain name, used to compute TLSA label

### TLSA label

Godane tries to retrieve a TLSA record for the given domain name.

The generic form is `_<port>._<transport>.<domain`.

port|transport|domain|tlsa record
----|---------|------|-----------
443|tcp|example.com|_443._tcp.example.com
25|tcp|mx.example.com|_25._tcp.mx.example.com
53|udp|ns.example.com|_53._udp.ns.example.com


### Status
This is an example project to illustrate the usage of the [Godnssecvalid](https://github.com/ulrichwisser/godane) library.
