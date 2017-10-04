package godane

import (
	"testing"
  "net"
)

var ip1 = net.ParseIP("")
var ip2 = net.ParseIP("1.2.3.4")
var ip3 = net.ParseIP("192.168.13.13")
var ip4 = net.ParseIP("10.10/16")
var ip5 = net.ParseIP("dead::beef")
var ip6 = net.ParseIP("dead::beef::dead")

func TestIsIPv4(t *testing.T) {
  if  isIPv4(&ip1) {t.Error("Expected ",ip1, "to not be acceptad as IPv4 address")}
  if !isIPv4(&ip2) {t.Error("Expected ",ip2, "to     be acceptad as IPv4 address")}
  if !isIPv4(&ip3) {t.Error("Expected ",ip3, "to     be acceptad as IPv4 address")}
  if  isIPv4(&ip4) {t.Error("Expected ",ip4, "to not be acceptad as IPv4 address")}
  if  isIPv4(&ip5) {t.Error("Expected ",ip5, "to not be acceptad as IPv4 address")}
  if  isIPv4(&ip6) {t.Error("Expected ",ip6, "to not be acceptad as IPv4 address")}
}

func TestIsIPv6(t *testing.T) {
  if  isIPv6(&ip1) {t.Error("Expected ",ip1, "to not be acceptad as IPv6 address")}
  if  isIPv6(&ip2) {t.Error("Expected ",ip2, "to not be acceptad as IPv6 address")}
  if  isIPv6(&ip3) {t.Error("Expected ",ip3, "to not be acceptad as IPv6 address")}
  if  isIPv6(&ip4) {t.Error("Expected ",ip4, "to not be acceptad as IPv6 address")}
  if !isIPv6(&ip5) {t.Error("Expected ",ip5, "to     be acceptad as IPv6 address")}
  if  isIPv6(&ip6) {t.Error("Expected ",ip6, "to not be acceptad as IPv6 address")}
}

func TestIp2Resolver(t *testing.T) {
  str1 := ip2Resolver(&ip1)
  if str1 != "<nil>:53" { t.Error("Expected <nil>:53 got ", str1)}
  str2 := ip2Resolver(&ip2)
  if str2 != "1.2.3.4:53" { t.Error("Expected 1.2.3.4:53 got ",str2)}
}
