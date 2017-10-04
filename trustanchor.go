package godnssecvalid

import (
	"fmt"
	"io"
	"strings"

	"github.com/miekg/dns"
)

// GetTrustAnchors reads a list of trust anchors and returns a list of DS records.
// All DS records in the file will be returned as well as all DNSKEY records
// converted to DS records. Any other records will be ignored.
func GetTrustAnchors(f io.Reader) ([]dns.RR, error) {
	anchors := make([]dns.RR, 0)

	//
	for token := range dns.ParseZone(f, "", "") {
		if token.Error != nil {
			if Verbose {
				fmt.Println("Error: ", token.Error)
			}
			return nil, token.Error
		}
		if token.RR.Header().Rrtype == dns.TypeDS {
			anchors = append(anchors, token.RR)
		}
		if token.RR.Header().Rrtype == dns.TypeDNSKEY {
			anchors = append(anchors, token.RR.(*dns.DNSKEY).ToDS(dns.SHA256))
		}
	}
	return anchors, nil
}

// GetDefaultTrustAnchors returns a list of the trust anchors for the root zone.
func GetDefaultTrustAnchors() ([]dns.RR, error) {
	return GetTrustAnchors(strings.NewReader(rootTrustAnchors))
}

// trust anchors as of 2017-08-29
const rootTrustAnchors string = `
.			172800	IN	DNSKEY	257 3 8 AwEAAagAIKlVZrpC6Ia7gEzahOR+9W29euxhJhVVLOyQbSEW0O8gcCjFFVQUTf6v58fLjwBd0YI0EzrAcQqBGCzh/RStIoO8g0NfnfL2MTJRkxoXbfDaUeVPQuYEhg37NZWAJQ9VnMVDxP/VHL496M/QZxkjf5/Efucp2gaDX6RS6CXpoY68LsvPVjR0ZSwzz1apAzvN9dlzEheX7ICJBBtuA6G3LQpzW5hOA2hzCTMjJPJ8LbqF6dsV6DoBQzgul0sGIcGOYl7OyQdXfZ57relSQageu+ipAdTTJ25AsRTAoub8ONGcLmqrAmRLKBP1dfwhYB4N7knNnulqQxA+Uk1ihz0=
.			172800	IN	DNSKEY	257 3 8 AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3+/4RgWOq7HrxRixHlFlExOLAJr5emLvN7SWXgnLh4+B5xQlNVz8Og8kvArMtNROxVQuCaSnIDdD5LKyWbRd2n9WGe2R8PzgCmr3EgVLrjyBxWezF0jLHwVN8efS3rCj/EWgvIWgb9tarpVUDK/b58Da+sqqls3eNbuv7pr+eoZG+SrDK6nWeL3c6H5Apxz7LjVc1uTIdsIXxuOLYA4/ilBmSVIzuDWfdRUfhHdY6+cn8HFRm+2hM8AnXGXws9555KrUB5qihylGa8subX2Nn6UwNR1AkUTV74bU=
`
