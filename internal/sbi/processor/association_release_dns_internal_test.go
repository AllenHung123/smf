package processor

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync/atomic"
	"testing"

	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"
	"golang.org/x/net/dns/dnsmessage"

	smf_context "github.com/free5gc/smf/internal/context"
	"github.com/free5gc/smf/internal/pfcp/pfcptype"
	"github.com/free5gc/smf/pkg/factory"
)

// The same two UPF addresses are always advertised; only their order changes.
// This exercises multiple addresses discovered before association setup,
// rather than assuming that a new address appeared during the association.
func associationReleaseDNS(t *testing.T) *atomic.Bool {
	t.Helper()
	reverse := &atomic.Bool{}
	previous := net.DefaultResolver
	t.Cleanup(func() { net.DefaultResolver = previous })
	net.DefaultResolver = &net.Resolver{PreferGo: true, Dial: func(_ context.Context, _, _ string) (net.Conn, error) {
		client, server := net.Pipe()
		go func() {
			defer func() {
				if err := server.Close(); err != nil {
					t.Error(err)
				}
			}()
			length := make([]byte, 2)
			if _, err := io.ReadFull(server, length); err != nil {
				return
			}
			packet := make([]byte, binary.BigEndian.Uint16(length))
			if _, err := io.ReadFull(server, packet); err != nil {
				return
			}
			var query dnsmessage.Message
			if err := query.Unpack(packet); err != nil {
				return
			}
			response := dnsmessage.Message{
				Header: dnsmessage.Header{ID: query.ID, Response: true, Authoritative: true}, Questions: query.Questions,
			}
			for _, q := range query.Questions {
				if q.Type != dnsmessage.TypeA {
					continue
				}
				order := []byte{11, 12}
				if reverse.Load() {
					order = []byte{12, 11}
				}
				for _, last := range order {
					response.Answers = append(response.Answers, dnsmessage.Resource{
						Header: dnsmessage.ResourceHeader{Name: q.Name, Type: q.Type, Class: dnsmessage.ClassINET},
						Body:   &dnsmessage.AResource{A: [4]byte{192, 0, 2, last}},
					})
				}
			}
			answer, err := response.Pack()
			if err != nil {
				return
			}
			binary.BigEndian.PutUint16(length, uint16(len(answer)))
			if _, err = server.Write(append(length, answer...)); err != nil {
				t.Error(err)
			}
		}()
		return client, nil
	}}
	return reverse
}

type associationReleaseSessionPeer struct {
	fakeActivePFCPClient
	wantSessionIP net.IP
	t             *testing.T
}

func (f *associationReleaseSessionPeer) SendSessionEstablishmentRequest(
	_ context.Context, request *message.SessionEstablishmentRequest, addr *net.UDPAddr, localSEID uint64,
) (*message.SessionEstablishmentResponse, error) {
	f.t.Logf("Session Establishment destination=%s; UPF advertises F-SEID IP=%s", addr.IP, f.wantSessionIP)
	if request.NodeID == nil || request.CPFSEID == nil || len(request.CreatePDR) != 1 || len(request.CreateFAR) != 1 {
		return nil, fmt.Errorf("invalid fixture: establishment must carry Node ID, CP F-SEID, PDR and FAR")
	}
	if !addr.IP.Equal(f.wantSessionIP) {
		return nil, fmt.Errorf("invalid test setup: session establishment destination=%s", addr.IP)
	}
	response := message.NewSessionEstablishmentResponse(0, 0, localSEID, request.Sequence(), 0,
		ie.NewNodeIDHeuristic("upf.release.invalid"), ie.NewCause(ie.CauseRequestAccepted),
		ie.NewFSEID(4242, f.wantSessionIP, nil))
	packet, err := response.Marshal()
	if err != nil {
		return nil, err
	}
	return message.ParseSessionEstablishmentResponse(packet)
}

func TestAssociationReleaseSessionDeletionUsesSessionDestination(t *testing.T) {
	reverse := associationReleaseDNS(t)
	if err := smf_context.InitSmfContext(&factory.Config{
		Info: &factory.Info{Version: "1.0.7"},
		Configuration: &factory.Configuration{
			Sbi:  &factory.Sbi{Scheme: "http", RegisterIPv4: "127.0.0.1", BindingIPv4: "127.0.0.1"},
			PFCP: &factory.PFCP{NodeID: "127.0.0.1", ExternalAddr: "127.0.0.1"},
		},
	}); err != nil {
		t.Fatal(err)
	}
	node := pfcptype.NodeID{NodeIdType: pfcptype.NodeIdTypeFqdn, FQDN: "upf.release.invalid"}
	upf := smf_context.NewUPF(&node, nil)
	t.Cleanup(func() { smf_context.RemoveUPFNodeByNodeID(node) })
	initial := upf.PFCPAddr()
	if !initial.IP.Equal(net.ParseIP("192.0.2.11")) {
		t.Fatalf("invalid initial DNS order: %v", initial)
	}
	upf.EstablishAssociation(context.Background())
	t.Cleanup(upf.CancelAssociation)
	reverse.Store(true)
	sessionIP := net.ParseIP("192.0.2.12")
	peer := &associationReleaseSessionPeer{wantSessionIP: sessionIP, t: t}
	peer.deleteCtx = func(_ context.Context, request *message.SessionDeletionRequest, addr *net.UDPAddr,
		localSEID uint64,
	) (*message.SessionDeletionResponse, error) {
		t.Logf("Session Deletion destination=%s; session F-SEID IP=%s", addr.IP, sessionIP)
		if !addr.IP.Equal(sessionIP) {
			return nil, fmt.Errorf("Session Deletion sent to %s, but peer's UP F-SEID IP is %s", addr.IP, sessionIP)
		}
		if request.SEID() != 4242 {
			return nil, fmt.Errorf("Session Deletion used SEID=%d, want 4242", request.SEID())
		}
		return message.NewSessionDeletionResponse(0, 0, localSEID, request.Sequence(), 0,
			ie.NewCause(ie.CauseRequestAccepted)), nil
	}
	p := &Processor{}
	p.SetActivePFCPClient(peer)
	sm := smf_context.NewSMContext("imsi-208930000001195", 1)
	t.Cleanup(func() { smf_context.RemoveSMContext(sm.Ref) })
	far := &smf_context.FAR{FARID: 1, ApplyAction: pfcptype.ApplyAction{Drop: true}}
	pdr := &smf_context.PDR{
		PDRID: 1, Precedence: 1, FAR: far,
		PDI: smf_context.PDI{
			SourceInterface: pfcptype.SourceInterface{InterfaceValue: pfcptype.SourceInterfaceCore},
			UEIPAddress: &pfcptype.UEIPAddress{
				V4: true, Sd: true, Ipv4Address: net.ParseIP("10.60.0.1").To4(),
			},
		},
	}
	session := &smf_context.PFCPSessionContext{
		NodeID: node, LocalSEID: 1195, PDRs: map[uint16]*smf_context.PDR{1: pdr},
	}
	sm.PFCPContext[sessionIP.String()] = session
	results := make(chan SendPfcpResult, 1)
	p.establishPfcpSession(sm, &PFCPState{
		upf: upf, pdrList: []*smf_context.PDR{pdr}, farList: []*smf_context.FAR{far},
	}, results)
	result := <-results
	if result.Err != nil || session.RemoteSEID != 4242 {
		t.Fatalf("session establishment did not accept the returned F-SEID: %+v, RemoteSEID=%d", result, session.RemoteSEID)
	}
	if !upf.BeginAssociationRelease() {
		t.Fatal("could not begin association release")
	}
	if err := p.deleteAssociationPFCPSession(context.Background(), upf, sm, session); err != nil {
		t.Fatal(err)
	}
	if session.RemoteSEID != 0 {
		t.Fatal("accepted Session Deletion did not clear the remote SEID")
	}
	if cached := upf.PFCPAddr(); !cached.IP.Equal(initial.IP) {
		t.Fatalf("Session Deletion changed the association destination: %s, want %s", cached.IP, initial.IP)
	}
}
