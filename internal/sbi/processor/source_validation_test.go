package processor

import (
	"net"
	"testing"

	smf_context "github.com/free5gc/smf/internal/context"
	"github.com/free5gc/smf/internal/pfcp/pfcptype"
)

func TestValidPFCPSource(t *testing.T) {
	upf := &smf_context.UPF{
		NodeID: pfcptype.NodeID{
			NodeIdType: pfcptype.NodeIdTypeIpv4Address,
			IP:         net.ParseIP("10.100.200.3").To4(),
		},
	}

	tests := []struct {
		name   string
		remote *net.UDPAddr
		want   bool
	}{
		{
			"Valid UPF",
			&net.UDPAddr{IP: net.ParseIP("10.100.200.3")},
			true,
		},
		{
			"Spoofed Node ID",
			&net.UDPAddr{IP: net.ParseIP("10.100.200.1")},
			false,
		},
		{
			"Missing source",
			nil,
			false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := validPFCPSource(upf, tt.remote)
			if got != tt.want {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}
