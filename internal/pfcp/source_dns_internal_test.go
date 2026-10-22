package pfcp

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/wmnsk/go-pfcp/ie"
	"golang.org/x/net/dns/dnsmessage"

	smf_context "github.com/free5gc/smf/internal/context"
	"github.com/free5gc/smf/internal/pfcp/pfcptype"
	"github.com/free5gc/smf/internal/sbi/processor"
)

type associationDNS struct {
	calls    atomic.Int32
	fail     atomic.Bool
	lastIPv4 atomic.Uint32
	ipv6     atomic.Bool
}

// Answer DNS over an in-memory stream. No external DNS or socket is involved.
// The failure switch blocks until the lookup's own context deadline expires.
func controlledAssociationDNS(t *testing.T) *associationDNS {
	t.Helper()
	dns := &associationDNS{}
	dns.lastIPv4.Store(251)
	dns.ipv6.Store(true)
	previous := net.DefaultResolver
	t.Cleanup(func() { net.DefaultResolver = previous })
	net.DefaultResolver = &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			dns.calls.Add(1)
			if dns.fail.Load() {
				<-ctx.Done()
				return nil, ctx.Err()
			}
			client, server := net.Pipe()
			go func() {
				defer func() {
					if err := server.Close(); err != nil {
						t.Error(err)
					}
				}()
				length := make([]byte, 2)
				if _, err := io.ReadFull(server, length); err != nil {
					t.Error(err)
					return
				}
				packet := make([]byte, binary.BigEndian.Uint16(length))
				if _, err := io.ReadFull(server, packet); err != nil {
					t.Error(err)
					return
				}
				var query dnsmessage.Message
				if err := query.Unpack(packet); err != nil {
					t.Error(err)
					return
				}
				response := dnsmessage.Message{
					Header:    dnsmessage.Header{ID: query.ID, Response: true, Authoritative: true},
					Questions: query.Questions,
				}
				for _, question := range query.Questions {
					header := dnsmessage.ResourceHeader{Name: question.Name, Type: question.Type, Class: dnsmessage.ClassINET}
					switch question.Type {
					case dnsmessage.TypeA:
						lastIPv4 := byte(dns.lastIPv4.Load())
						for _, last := range []byte{lastIPv4, lastIPv4 + 1} {
							response.Answers = append(response.Answers, dnsmessage.Resource{
								Header: header, Body: &dnsmessage.AResource{A: [4]byte{192, 0, 2, last}},
							})
						}
					case dnsmessage.TypeAAAA:
						if dns.ipv6.Load() {
							response.Answers = append(response.Answers, dnsmessage.Resource{
								Header: header, Body: &dnsmessage.AAAAResource{AAAA: [16]byte{0x20, 1, 0xd, 0xb8, 15: 1}},
							})
						}
					}
				}
				answer, err := response.Pack()
				if err != nil {
					t.Error(err)
					return
				}
				binary.BigEndian.PutUint16(length, uint16(len(answer)))
				if _, err = server.Write(append(length, answer...)); err != nil {
					t.Error(err)
				}
			}()
			return client, nil
		},
	}
	return dns
}

func TestAssociationFQDNSourceValidation(t *testing.T) {
	dns := controlledAssociationDNS(t)
	nodeID := pfcptype.NodeID{NodeIdType: pfcptype.NodeIdTypeFqdn, FQDN: "upf.free5gc.org"}
	for _, kind := range []string{sourceTestSetup, "update", "release"} {
		for _, tc := range []struct {
			name, claimed, source string
			want                  uint8
		}{
			{"fqdn-primary", nodeID.FQDN, "192.0.2.251", ie.CauseRequestAccepted},
			{"fqdn-secondary", nodeID.FQDN, "192.0.2.252", ie.CauseRequestAccepted},
			{"ipv4-secondary", "192.0.2.252", "192.0.2.252", ie.CauseRequestAccepted},
			{"ipv6", "2001:db8::1", "2001:db8::1", ie.CauseRequestAccepted},
			{"fqdn-wrong-source", nodeID.FQDN, "192.0.2.1", ie.CauseRequestRejected},
			{"ipv4-wrong-source", "192.0.2.252", "192.0.2.1", ie.CauseRequestRejected},
			{"unknown-fqdn", "attacker.invalid", "192.0.2.251", ie.CauseNoEstablishedPFCPAssociation},
			{"unknown-ip", "192.0.2.250", "192.0.2.250", ie.CauseNoEstablishedPFCPAssociation},
		} {
			t.Run(kind+"/"+tc.name, func(t *testing.T) {
				upf := smf_context.NewUPF(&nodeID, nil)
				t.Cleanup(func() { smf_context.RemoveUPFNodeByNodeID(nodeID) })
				t.Cleanup(upf.CancelAssociation)
				// Each case gets its own association: an accepted Release retires
				// that association's cached addresses.
				dns.fail.Store(false)
				activeAddr := upf.PFCPAddrForSetup()
				if activeAddr.IP == nil || activeAddr.Port != PfcpPort {
					t.Fatalf("invalid PFCP destination: %v", activeAddr)
				}
				resolvedCalls := dns.calls.Load()
				if resolvedCalls == 0 {
					t.Fatal("test did not exercise DNS")
				}
				upf.EstablishAssociation(context.Background())
				dns.fail.Store(true)
				s := NewPfcpServer(nil, "127.0.0.1")
				t.Cleanup(s.Stop)
				s.SetAssociationStateManager(&processor.Processor{})
				want := tc.want
				if kind == sourceTestSetup && want == ie.CauseNoEstablishedPFCPAssociation {
					want = ie.CauseRequestRejected
				}
				request := sourceTestRequest(kind, ie.NewNodeIDHeuristic(tc.claimed), time.Now(), false)
				response := dispatchAssociationSourceTest(t, s, request, &net.UDPAddr{IP: net.ParseIP(tc.source)})
				assertSourceTestResponse(t, response, want, true)
				if upf.IsAssociated() == nil {
					if got := upf.PFCPAddr(); !got.IP.Equal(activeAddr.IP) {
						t.Fatalf("DNS outage changed the active PFCP address: %v -> %v", activeAddr, got)
					}
					// Callers cannot mutate the pinned cache through PFCPAddr.
					activeAddr.IP[0] ^= 0xff
					if upf.PFCPAddr().IP.Equal(activeAddr.IP) {
						t.Fatal("PFCPAddr exposed mutable cached address storage")
					}
				}
				if got := dns.calls.Load(); got != resolvedCalls {
					t.Fatalf("association request performed new DNS lookups: before=%d after=%d", resolvedCalls, got)
				}
			})
		}
	}
}

func TestAssociationDNSFailureIsBoundedAndFailsClosed(t *testing.T) {
	dns := controlledAssociationDNS(t)
	dns.fail.Store(true)
	upf := &smf_context.UPF{NodeID: pfcptype.NodeID{
		NodeIdType: pfcptype.NodeIdTypeFqdn, FQDN: "unavailable.free5gc.org",
	}}
	start := time.Now()
	if upf.MatchesPFCPSource(net.ParseIP("192.0.2.251")) {
		t.Fatal("unresolved FQDN trusted the sender")
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("DNS failure took %v; expected a bounded lookup", elapsed)
	}
	if dns.calls.Load() == 0 {
		t.Fatal("test did not exercise failing DNS")
	}
	// Recovery must not bypass the failed lookup's cooldown. Checking the
	// returned addresses avoids depending on the resolver's background retries.
	dns.fail.Store(false)
	for range 3 {
		if upf.MatchesPFCPSource(net.ParseIP("192.0.2.251")) || upf.PFCPAddrForSetup().IP != nil {
			t.Fatal("failed DNS admitted an arbitrary PFCP address")
		}
	}
}

func TestAssociationDNSRefreshAfterCancellation(t *testing.T) {
	for _, cancellation := range []string{"explicit", "generation", "parent", "release"} {
		t.Run(cancellation, func(t *testing.T) {
			dns := controlledAssociationDNS(t)
			dns.ipv6.Store(false)
			nodeID := pfcptype.NodeID{NodeIdType: pfcptype.NodeIdTypeFqdn, FQDN: "upf.free5gc.org"}
			upf := smf_context.NewUPF(&nodeID, nil)
			t.Cleanup(func() { smf_context.RemoveUPFNodeByNodeID(nodeID) })
			t.Cleanup(upf.CancelAssociation)
			oldAddr := upf.PFCPAddrForSetup()
			if !oldAddr.IP.Equal(net.ParseIP("192.0.2.251")) {
				t.Fatalf("invalid initial PFCP destination: %v", oldAddr)
			}
			parent, cancelParent := context.WithCancel(context.Background())
			t.Cleanup(cancelParent)
			upf.EstablishAssociation(parent)
			if cancellation == "release" && !upf.BeginAssociationRelease() {
				t.Fatal("could not begin association release")
			}
			_, oldGeneration := upf.AssociationStateAndGeneration()
			resolvedCalls := dns.calls.Load()
			dns.lastIPv4.Store(11)
			newIP := net.ParseIP("192.0.2.11")

			// A DNS change must not rebind a live association or its source checks.
			if !upf.PFCPAddrForSetup().IP.Equal(oldAddr.IP) || upf.MatchesPFCPSource(newIP) {
				t.Fatal("DNS change rebound an established association")
			}
			if dns.calls.Load() != resolvedCalls {
				t.Fatal("established association queried DNS again")
			}
			switch cancellation {
			case "explicit", "release":
				upf.CancelAssociation()
			case "generation":
				if !upf.CancelAssociationIfGeneration(oldGeneration) {
					t.Fatal("current association generation was not canceled")
				}
			case "parent":
				cancelParent()
				deadline := time.Now().Add(time.Second)
				for upf.AssociationState() != smf_context.AssociationDown {
					if time.Now().After(deadline) {
						t.Fatal("parent cancellation did not retire the association")
					}
					time.Sleep(time.Millisecond)
				}
			}
			if got := upf.PFCPAddr(); !got.IP.Equal(newIP) {
				t.Fatalf("reconnect destination = %v, want %v", got, newIP)
			}
			if dns.calls.Load() == resolvedCalls {
				t.Fatal("reconnect did not refresh DNS")
			}
			upf.EstablishAssociation(context.Background())
			dns.fail.Store(true)
			resolvedCalls = dns.calls.Load()
			if upf.CancelAssociationIfGeneration(oldGeneration) {
				t.Fatal("stale cancellation affected the replacement association")
			}

			s := NewPfcpServer(nil, "127.0.0.1")
			t.Cleanup(s.Stop)
			s.SetAssociationStateManager(&processor.Processor{})
			for _, tc := range []struct {
				ip    net.IP
				cause uint8
			}{
				{oldAddr.IP, ie.CauseRequestRejected},
				{newIP, ie.CauseRequestAccepted},
			} {
				request := sourceTestRequest(sourceTestSetup, ie.NewNodeIDHeuristic(nodeID.FQDN), time.Now(), false)
				response := dispatchAssociationSourceTest(t, s, request, &net.UDPAddr{IP: tc.ip})
				assertSourceTestResponse(t, response, tc.cause, true)
			}
			if got := upf.PFCPAddr(); !got.IP.Equal(newIP) || dns.calls.Load() != resolvedCalls {
				t.Fatal("replacement association lost its pinned address during DNS outage")
			}
		})
	}
}

func TestAssociationSetupRetryRefreshesDNS(t *testing.T) {
	dns := controlledAssociationDNS(t)
	dns.ipv6.Store(false)
	upf := &smf_context.UPF{NodeID: pfcptype.NodeID{
		NodeIdType: pfcptype.NodeIdTypeFqdn, FQDN: "upf.free5gc.org",
	}}
	if !upf.BeginAssociationSetup() {
		t.Fatal("could not begin setup")
	}
	oldAddr := upf.PFCPAddrForSetup()
	if !oldAddr.IP.Equal(net.ParseIP("192.0.2.251")) {
		t.Fatalf("invalid initial PFCP destination: %v", oldAddr)
	}
	dns.lastIPv4.Store(11)
	newIP := net.ParseIP("192.0.2.11")
	if got := upf.PFCPAddrForSetup(); !got.IP.Equal(newIP) {
		t.Fatalf("setup retry retained %v instead of following DNS to %v", got, newIP)
	}
	if upf.MatchesPFCPSource(oldAddr.IP) || !upf.MatchesPFCPSource(newIP) {
		t.Fatal("setup retry did not replace the source allowlist")
	}
	// A failed refresh must not retain or fall back to the retired address.
	dns.fail.Store(true)
	if upf.PFCPAddrForSetup().IP != nil || upf.MatchesPFCPSource(newIP) {
		t.Fatal("failed setup refresh retained an obsolete address")
	}
	dns.fail.Store(false)
	for range 3 {
		if upf.PFCPAddrForSetup().IP != nil {
			t.Fatal("setup retries bypassed the failed DNS cooldown")
		}
	}
}

func TestAssociationTruncatedFQDNIsIncorrect(t *testing.T) {
	nodeID := pfcptype.NodeID{NodeIdType: pfcptype.NodeIdTypeFqdn, FQDN: "upf.free5gc.org"}
	for _, kind := range []string{sourceTestSetup, "update", "release"} {
		t.Run(kind, func(t *testing.T) {
			s := NewPfcpServer(nil, "127.0.0.1")
			t.Cleanup(s.Stop)
			spy := &associationSourceSpy{AssociationStateManager: &processor.Processor{}}
			s.SetAssociationStateManager(spy)
			node := ie.NewNodeIDHeuristic(nodeID.FQDN)
			// go-pfcp's decoder returns the valid prefix and silently drops this label.
			node = ie.New(ie.NodeID, append(node.Payload, 4, 'x'))
			response := dispatchAssociationSourceTest(t, s,
				sourceTestRequest(kind, node, time.Now(), true), &net.UDPAddr{IP: net.ParseIP("192.0.2.1")})
			assertSourceTestResponse(t, response, ie.CauseMandatoryIEIncorrect, true)
			if spy.calls != 0 {
				t.Fatal("malformed FQDN reached the processor")
			}
		})
	}
}
