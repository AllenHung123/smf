package processor

import (
	"net"
	"testing"

	smf_context "github.com/free5gc/smf/internal/context"
	"github.com/free5gc/smf/internal/pfcp/pfcptype"
)

func TestValidPFCPSource(t *testing.T) {
	upf := &smf_context.UPF{NodeID: pfcptype.NodeID{
		NodeIdType: pfcptype.NodeIdTypeIpv4Address, IP: net.ParseIP("192.0.2.251"),
	}}
	for _, tc := range []struct {
		name   string
		upf    *smf_context.UPF
		remote *net.UDPAddr
		want   bool
	}{
		{"valid-ipv4", upf, &net.UDPAddr{IP: net.ParseIP("192.0.2.251").To4()}, true},
		{"wrong-ipv4", upf, &net.UDPAddr{IP: net.ParseIP("192.0.2.1")}, false},
		{"nil-upf", nil, &net.UDPAddr{IP: net.ParseIP("192.0.2.251")}, false},
		{"nil-remote", upf, nil, false},
		{"nil-ip", upf, &net.UDPAddr{}, false},
		{"unspecified", upf, &net.UDPAddr{IP: net.IPv4zero}, false},
		{"multicast", upf, &net.UDPAddr{IP: net.ParseIP("224.0.0.1")}, false},
		{"invalid-ip", upf, &net.UDPAddr{IP: net.IP{1}}, false},
		{"unconfigured", &smf_context.UPF{}, &net.UDPAddr{IP: net.ParseIP("192.0.2.251")}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := validPFCPSource(tc.upf, tc.remote); got != tc.want {
				t.Fatalf("validPFCPSource = %t, want %t", got, tc.want)
			}
		})
	}
}
