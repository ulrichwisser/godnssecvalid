package godnssecvalid

import (
	"strings"
	"testing"

	"github.com/miekg/dns"
)

var raw1 = `
nu.			3600	IN	DNSKEY	256 3 7 AwEAAa5hKIk4DFfz5TSKhwpumyaGgQYhZk5V+S/laRXUmpmVraEaGHzw 1fg6BrP3T/fH9uyDH2pvPAKQ8/zrKwQhp5qPfZyfa6KyGO3vJ3X1mm7U FDDSOO7madQB1Inrg3RIF7005ELlSOgPPJPnVjeVoddoekdrTvkyPG0/ 5fdJt4rV
nu.			3600	IN	DNSKEY	256 3 7 AwEAAdFbfEvH5pzi/wkeUYW6DYduPOiTWPH4LpXTih9AWm9T/LjWtpSS Ld6jmKtJsoeG3gOJFaCuFBe91PpeE8iUs3e1yRcobjc41em6bNaYEtxG ywMNhwuavKytWhnYnmWhmzlO0yffFwmbnGBiRgCd3MBmv2073SV7ykfN R9TGs4A1
nu.			3600	IN	DNSKEY	257 3 7 AwEAAdwrx3bF30rEEHV6/abLFkCTkfGot1Kme8BPYRPrO9B8msfK5GXI qsxN8o5qeMH/p8f9xJ7g8hKWAK1ijs0g5+q7DS/IXe6qFhsuVSj8vbBi sIglJqm7ojS+/2clkDe8gAHtLUs7Rjz0GU3pTktnwglaR5WXkMRGdV7M 95cLyiSjYLSBvnrEdIKfLG7MRCYR4OHf6rnS77BMNB+I3Zmnb9T8mzLq Cao9XDQOz4gCLgYO0QyAym+3aYjmj0O4Qatg8VdFcVe8gdfHOBW4cu02 QiQRapf8bBUnNMiIe0Rov9+//wTRenx4EgV80ZS9YmYGh/ir89ZEsI+3 mjUUYcmdHRk=
`

var raw2 = `
nu.			86374	IN	DS	3453 7 2 270AAD4FB6BC3AF95CB66B2F9C61F615D4510C5702B54899C26EE2E3 7DBCA6D8
se.			85952	IN	DS	59747 5 2 44388B3DE9A22CAFA8A12883F60A0F984472D0DFEF0F63ED59A29BE0 18658B28
cz.			86232	IN	DS	54576 10 2 397E50C85EDE9CDE33F363A9E66FD1B216D788F8DD438A57A423A386 869C8F06
com.			85921	IN	DS	30909 8 2 E2D3C916F6DEEAC73294E8268FB5885044A833FC5459588F4A9184CF C41A5766
google.			86400	IN	DS	34531 8 2 0F8937F75BD5D2FC0392F83F7F63AF7F0802FFDA37150C0D0B0B44FA 07D83D89
biz.			86400	IN	DS	12385 8 1 E917523077754FB03308402D76144EAF0D4F6778
biz.			86400	IN	DS	12385 8 2 AE03B95863B999FC84B725DF5C903511FF96D53825F0454CE6880987 E96F5D20
biz.			86400	IN	DS	28450 8 1 D9C2F912C657E4005CF0C13BA55C5AAA291AEF56
biz.			86400	IN	DS	28450 8 2 403F234609C56B3A221BC4CFB694948AB5DDF4A26AE17439BF1279CF C5CF21AB
`

func TestGetDefaultTrustAnchors(t *testing.T) {
	dslist, err := GetDefaultTrustAnchors()
	if err != nil {
		t.Error("Error getting trust anchors, ", err)
	}
	if len(dslist) != 2 {
		t.Error("Expected 2 DS records, got ", len(dslist))
	}
	for _, rr := range dslist {
		if rr.Header().Rrtype != dns.TypeDS {
			t.Error("Expected DS record, got ", dns.TypeToString[rr.Header().Rrtype])
		}
	}
}

func TestGetTrustAnchors(t *testing.T) {
	list1, err := GetTrustAnchors(strings.NewReader(raw1))
	if err != nil {
		t.Error("Error getting trust anchors, ", err)
	}
	if len(list1) != 3 {
		t.Error("Expected 3 DS records, got ", len(list1))
	}
	for _, rr := range list1 {
		if rr.Header().Rrtype != dns.TypeDS {
			t.Error("Expected DS record, got ", dns.TypeToString[rr.Header().Rrtype])
		}
	}
	list2, err := GetTrustAnchors(strings.NewReader(raw2))
	if err != nil {
		t.Error("Error getting trust anchors, ", err)
	}
	if len(list2) != 9 {
		t.Error("Expected 9 DS records, got ", len(list2))
	}
	for _, rr := range list2 {
		if rr.Header().Rrtype != dns.TypeDS {
			t.Error("Expected DS record, got ", dns.TypeToString[rr.Header().Rrtype])
		}
	}
}
