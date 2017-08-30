package godane

import (
	"os"

	"github.com/miekg/dns"
)

func ReadHints(filename string) ([]dns.RR, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	//
	hints := make([]dns.RR, 0)
	for token := range dns.ParseZone(f, "", "") {
		if token.Error != nil {
			return nil, token.Error
		}
		hints = append(hints, token.RR)
	}
	return hints, nil
}
