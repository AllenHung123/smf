package pfcp

import (
	"context"
	"net"
	"reflect"
	"testing"
	"time"

	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"

	smf_context "github.com/free5gc/smf/internal/context"
	"github.com/free5gc/smf/internal/pfcp/pfcptype"
	"github.com/free5gc/smf/internal/sbi/processor"
	"github.com/free5gc/smf/pkg/factory"
)

const (
	sourceTestSetup    = "setup"
	sourceTestNilLocal = "nil-local-node"
)

// Count calls while exercising the real processor's lookup and source checks.
type associationSourceSpy struct {
	AssociationStateManager
	calls, callbacks int
}

func (s *associationSourceSpy) wrap(cause uint8, after func()) (uint8, func()) {
	s.calls++
	if after == nil {
		return cause, nil
	}
	return cause, func() { s.callbacks++; after() }
}

func (s *associationSourceSpy) SetupAssociation(
	peer pfcptype.NodeID, recovery time.Time, remote *net.UDPAddr,
) (uint8, func()) {
	return s.wrap(s.AssociationStateManager.SetupAssociation(peer, recovery, remote))
}

func (s *associationSourceSpy) UpdateAssociation(
	peer pfcptype.NodeID, request *message.AssociationUpdateRequest, remote *net.UDPAddr,
) (uint8, func()) {
	return s.wrap(s.AssociationStateManager.UpdateAssociation(peer, request, remote))
}

func (s *associationSourceSpy) ReleaseAssociation(peer pfcptype.NodeID, remote *net.UDPAddr) uint8 {
	s.calls++
	return s.AssociationStateManager.ReleaseAssociation(peer, remote)
}

// Complete a successful response send without a socket. Dispatch must return
// after its callback, so checks cannot race the afterResponse execution.
func dispatchAssociationSourceTest(
	t *testing.T, s *PfcpServer, request message.Message, remote *net.UDPAddr,
) message.Message {
	t.Helper()
	done := make(chan struct{})
	go func() { s.Dispatch(request, remote); close(done) }()
	var response message.Message
	select {
	case outgoing := <-s.txCh:
		response = outgoing.Msg
		outgoing.Done <- nil
	case <-time.After(2 * time.Second):
		s.Stop()
		t.Fatal("Dispatch did not send a response")
	}
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		s.Stop()
		t.Fatal("Dispatch did not finish")
	}
	packet := make([]byte, response.MarshalLen())
	if err := response.MarshalTo(packet); err != nil {
		t.Fatal(err)
	}
	parsed, err := message.Parse(packet)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Sequence() != request.Sequence() {
		t.Fatal("response changed request sequence")
	}
	return parsed
}

func sourceTestRequest(kind string, node *ie.IE, recovery time.Time, destructive bool) message.Message {
	switch kind {
	case sourceTestSetup:
		request := message.NewAssociationSetupRequest(251, ie.NewRecoveryTimeStamp(recovery))
		request.NodeID = node
		return request
	case "update":
		request := message.NewAssociationUpdateRequest(251)
		request.NodeID = node
		if destructive {
			request.UPFunctionFeatures = ie.NewUPFunctionFeatures(0x33, 0x44)
			request.PFCPAssociationReleaseRequest = ie.NewPFCPAssociationReleaseRequest(1, 0)
		}
		return request
	default:
		request := message.NewAssociationReleaseRequest(251, node)
		request.NodeID = node
		return request
	}
}

func assertSourceTestResponse(t *testing.T, response message.Message, cause uint8, localNode bool) {
	t.Helper()
	var node, causeIE *ie.IE
	switch r := response.(type) {
	case *message.AssociationSetupResponse:
		node, causeIE = r.NodeID, r.Cause
		if r.RecoveryTimeStamp == nil || r.CPFunctionFeatures == nil {
			t.Fatal("Setup response lost Recovery Time Stamp or CP Function Features")
		}
	case *message.AssociationUpdateResponse:
		node, causeIE = r.NodeID, r.Cause
		if r.CPFunctionFeatures == nil {
			t.Fatal("Update response lost CP Function Features")
		}
	case *message.AssociationReleaseResponse:
		node, causeIE = r.NodeID, r.Cause
	default:
		t.Fatalf("unexpected response %T", response)
	}
	assertCause(t, causeIE, cause)
	if (node != nil) != localNode {
		t.Fatalf("response local Node ID present = %t, want %t", node != nil, localNode)
	}
}

func TestAssociationDispatchSourceValidation(t *testing.T) {
	if err := smf_context.InitSmfContext(&factory.Config{
		Info: &factory.Info{Version: "1.0.7"},
		Configuration: &factory.Configuration{
			Sbi:                  &factory.Sbi{Scheme: "http", BindingIPv4: "127.0.0.1"},
			UserPlaneInformation: factory.UserPlaneInformation{UPNodes: map[string]*factory.UPNode{}},
		},
	}); err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{sourceTestSetup, "update", "release"} {
		for _, scenario := range []string{
			"trusted", "wrong-source", "missing-node", "invalid-node", "invalid-fqdn", "unknown-upf",
			"no-association", "no-manager", sourceTestNilLocal,
		} {
			t.Run(kind+"/"+scenario, func(t *testing.T) {
				nodeID := pfcptype.NodeID{NodeIdType: pfcptype.NodeIdTypeIpv4Address, IP: net.ParseIP("192.0.2.251")}
				upf := smf_context.NewUPF(&nodeID, nil)
				t.Cleanup(func() { smf_context.RemoveUPFNodeByNodeID(nodeID) })
				upf.SetUPFunctionFeatures([]byte{1, 2})
				recovery := time.Unix(1700000000, 0)
				upf.SetRecoveryTimeStamp(recovery)
				if scenario != "no-association" {
					upf.EstablishAssociation(context.Background())
				}
				t.Cleanup(upf.CancelAssociation)
				state, generation := upf.AssociationStateAndGeneration()
				session := smf_context.NewSMContext("imsi-source-validation", 1)
				t.Cleanup(func() { smf_context.RemoveSMContext(session.Ref) })
				session.PFCPContext[nodeID.String()] = &smf_context.PFCPSessionContext{
					NodeID: nodeID, LocalSEID: 251, RemoteSEID: 1195,
				}
				s := NewPfcpServer(nil, "127.0.0.1")
				t.Cleanup(s.Stop)
				spy := &associationSourceSpy{AssociationStateManager: &processor.Processor{}}
				s.SetAssociationStateManager(spy)
				node := ie.NewNodeIDHeuristic(nodeID.String())
				remote := &net.UDPAddr{IP: nodeID.IP, Port: 18805}
				want, calls := ie.CauseRequestAccepted, 1
				switch scenario {
				case "wrong-source", sourceTestNilLocal:
					remote.IP = net.ParseIP("192.0.2.1")
					want = ie.CauseRequestRejected
					if scenario == sourceTestNilLocal {
						s.addr = ""
					}
				case "missing-node":
					node, want, calls = nil, ie.CauseMandatoryIEMissing, 0
				case "invalid-node":
					node, want, calls = ie.New(ie.NodeID, []byte{ie.NodeIDIPv4Address, 192}), ie.CauseMandatoryIEIncorrect, 0
				case "invalid-fqdn":
					node = ie.New(ie.NodeID, []byte{ie.NodeIDFQDN, 4, 'u', 'p', 'f'})
					want, calls = ie.CauseMandatoryIEIncorrect, 0
				case "unknown-upf":
					node = ie.NewNodeIDHeuristic("192.0.2.250")
					want = ie.CauseNoEstablishedPFCPAssociation
					if kind == sourceTestSetup {
						want = ie.CauseRequestRejected
					}
				case "no-manager":
					s.SetAssociationStateManager(nil)
					calls, want = 0, ie.CauseNoEstablishedPFCPAssociation
					if kind == sourceTestSetup {
						want = ie.CauseRequestRejected
					}
				case "no-association":
					if kind != sourceTestSetup {
						want = ie.CauseNoEstablishedPFCPAssociation
					}
				}
				// New recovery time and SARR would invalidate sessions if allowed through.
				request := sourceTestRequest(kind, node, recovery.Add(time.Hour), want != ie.CauseRequestAccepted)
				response := dispatchAssociationSourceTest(t, s, request, remote)
				assertSourceTestResponse(t, response, want, scenario != sourceTestNilLocal)
				if spy.calls != calls {
					t.Fatalf("processor calls = %d, want %d (must never run twice)", spy.calls, calls)
				}
				if want != ie.CauseRequestAccepted {
					if spy.callbacks != 0 {
						t.Fatal("rejected request executed afterResponse")
					}
					gotState, gotGeneration := upf.AssociationStateAndGeneration()
					if gotState != state || gotGeneration != generation {
						t.Fatal("rejected request changed association state or generation")
					}
					if !upf.RecoveryTimeStamp().Equal(recovery) || !reflect.DeepEqual(upf.UPFunctionFeatures(), []byte{1, 2}) {
						t.Fatal("rejected request changed recovery time or UP function features")
					}
					if session.PFCPContext[nodeID.String()].RemoteSEID != 1195 {
						t.Fatal("rejected request invalidated a legitimate PDU session")
					}
				}
			})
		}
	}
}

func TestRejectedAssociationCallbackIsDiscarded(t *testing.T) {
	for _, kind := range []string{sourceTestSetup, "update"} {
		t.Run(kind, func(t *testing.T) {
			s := NewPfcpServer(nil, "127.0.0.1")
			t.Cleanup(s.Stop)
			called := false
			s.SetAssociationStateManager(&fakeAssociationState{
				setupCause: ie.CauseRequestRejected, updateCause: ie.CauseRequestRejected,
				after: func() { called = true },
			})
			request := sourceTestRequest(kind, ie.NewNodeIDHeuristic("192.0.2.251"), time.Now(), true)
			response := dispatchAssociationSourceTest(t, s, request, &net.UDPAddr{IP: net.ParseIP("192.0.2.1")})
			assertSourceTestResponse(t, response, ie.CauseRequestRejected, true)
			if called {
				t.Fatal("rejection executed a session-cleanup callback")
			}
		})
	}
}

func TestAssociationInvalidIEsCannotBypassSourceValidation(t *testing.T) {
	for _, scenario := range []string{"missing-recovery", "invalid-recovery", "invalid-features", "invalid-grace-period"} {
		t.Run(scenario, func(t *testing.T) {
			s := NewPfcpServer(nil, "127.0.0.1")
			t.Cleanup(s.Stop)
			spy := &associationSourceSpy{AssociationStateManager: &processor.Processor{}}
			s.SetAssociationStateManager(spy)
			node := ie.NewNodeIDHeuristic("192.0.2.251")
			var request message.Message
			var want uint8
			switch scenario {
			case "missing-recovery", "invalid-recovery":
				r := message.NewAssociationSetupRequest(251, node)
				want = ie.CauseMandatoryIEMissing
				if scenario == "invalid-recovery" {
					r.RecoveryTimeStamp = ie.New(ie.RecoveryTimeStamp, []byte{0})
					want = ie.CauseMandatoryIEIncorrect
				}
				request = r
			case "invalid-features":
				request = message.NewAssociationUpdateRequest(251, node,
					ie.New(ie.UPFunctionFeatures, []byte{0}), ie.NewPFCPAssociationReleaseRequest(1, 0))
				want = ie.CauseInvalidLength
			case "invalid-grace-period":
				request = message.NewAssociationUpdateRequest(251, node, ie.NewGracefulReleasePeriod(time.Minute))
				want = ie.CauseConditionalIEMissing
			}
			response := dispatchAssociationSourceTest(t, s, request, &net.UDPAddr{IP: net.ParseIP("192.0.2.1")})
			assertSourceTestResponse(t, response, want, true)
			if spy.calls != 0 || spy.callbacks != 0 {
				t.Fatal("invalid IE reached the state-changing processor or afterResponse")
			}
		})
	}
}
