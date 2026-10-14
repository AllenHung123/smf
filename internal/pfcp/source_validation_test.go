package pfcp

import (
	"net"
	"testing"
	"time"

	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"

	smf_context "github.com/free5gc/smf/internal/context"
	"github.com/free5gc/smf/internal/pfcp/pfcptype"
	"github.com/free5gc/smf/internal/sbi/processor"
)

type rejectingSourceState struct {
	*fakeAssociationState
}

func (f *rejectingSourceState) ValidateAssociationSource(
	_ pfcptype.NodeID,
	_ *net.UDPAddr,
) bool {
	return false
}

func TestAssociationSetupRejectsInvalidSource(t *testing.T) {
	s, _ := startTestPfcpServer(t)

	state := &fakeAssociationState{
		setupCause: ie.CauseRequestAccepted,
	}
	s.SetAssociationStateManager(&rejectingSourceState{state})

	conn, err := net.DialUDP("udp", nil, s.LocalAddr())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	req := message.NewAssociationSetupRequest(
		100,
		ie.NewNodeIDHeuristic("127.0.0.2"),
		ie.NewRecoveryTimeStamp(time.Now()),
	)

	data, err := req.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write(data); err != nil {
		t.Fatal(err)
	}

	if err := conn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}

	buf := make([]byte, 1500)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}

	parsed, err := message.Parse(buf[:n])
	if err != nil {
		t.Fatal(err)
	}

	resp, ok := parsed.(*message.AssociationSetupResponse)
	if !ok {
		t.Fatalf("Unexpected response: %T", parsed)
	}

	assertCause(t, resp.Cause, ie.CauseRequestRejected)

	state.mu.Lock()
	called := !state.recoveryTime.IsZero()
	state.mu.Unlock()
	if called {
		t.Fatal("SetupAssociation executed despite rejection")
	}
}
func TestAssociationUpdateRejectsInvalidSource(t *testing.T) {
	s, _ := startTestPfcpServer(t)

	state := &fakeAssociationState{
		updateCause: ie.CauseRequestAccepted,
	}
	s.SetAssociationStateManager(
		&rejectingSourceState{state},
	)

	conn, err := net.DialUDP("udp", nil, s.LocalAddr())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	req := message.NewAssociationUpdateRequest(
		101,
		ie.NewNodeIDHeuristic("127.0.0.2"),
		ie.NewPFCPAssociationReleaseRequest(1, 0),
	)

	data, err := req.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write(data); err != nil {
		t.Fatal(err)
	}

	conn.SetReadDeadline(time.Now().Add(time.Second))

	buf := make([]byte, 1500)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}

	parsed, err := message.Parse(buf[:n])
	if err != nil {
		t.Fatal(err)
	}

	resp, ok := parsed.(*message.AssociationUpdateResponse)
	if !ok {
		t.Fatalf("Unexpected response: %T", parsed)
	}

	assertCause(t, resp.Cause, ie.CauseRequestRejected)

	state.mu.Lock()
	called := state.updateCalled
	state.mu.Unlock()

	if called {
		t.Fatal("UpdateAssociation executed despite rejection")
	}
}
func TestAssociationReleaseRejectsInvalidSource(t *testing.T) {
	s, _ := startTestPfcpServer(t)

	state := &fakeAssociationState{
		releaseCause: ie.CauseRequestAccepted,
	}
	s.SetAssociationStateManager(
		&rejectingSourceState{state},
	)

	conn, err := net.DialUDP("udp", nil, s.LocalAddr())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	req := message.NewAssociationReleaseRequest(
		102,
		ie.NewNodeIDHeuristic("127.0.0.2"),
	)

	data, err := req.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write(data); err != nil {
		t.Fatal(err)
	}

	if err := conn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}

	buf := make([]byte, 1500)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}

	parsed, err := message.Parse(buf[:n])
	if err != nil {
		t.Fatal(err)
	}

	resp, ok := parsed.(*message.AssociationReleaseResponse)
	if !ok {
		t.Fatalf("Unexpected response: %T", parsed)
	}

	assertCause(t, resp.Cause, ie.CauseRequestRejected)

	state.mu.Lock()
	got := state.releasePeer.String()
	state.mu.Unlock()

	if got == "127.0.0.2" {
		t.Fatal("ReleaseAssociation executed despite rejection")
	}
}
func TestAssociationSetupAllowsTrustedSource(t *testing.T) {
	s, _ := startTestPfcpServer(t)

	nodeID := pfcptype.NodeID{
		NodeIdType: pfcptype.NodeIdTypeIpv4Address,
		IP:         net.ParseIP("127.0.0.1").To4(),
	}
	smf_context.NewUPF(&nodeID, nil)
	t.Cleanup(func() {
		smf_context.RemoveUPFNodeByNodeID(nodeID)
	})

	s.SetAssociationStateManager(&processor.Processor{})

	conn, err := net.DialUDP("udp", nil, s.LocalAddr())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	req := message.NewAssociationSetupRequest(
		201,
		ie.NewNodeIDHeuristic("127.0.0.1"),
		ie.NewRecoveryTimeStamp(time.Now()),
	)

	data, err := req.Marshal()
	if err != nil {
		t.Fatal(err)
	}

	if _, err := conn.Write(data); err != nil {
		t.Fatal(err)
	}

	if err := conn.SetReadDeadline(
		time.Now().Add(2 * time.Second),
	); err != nil {
		t.Fatal(err)
	}

	buf := make([]byte, 1500)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}

	parsed, err := message.Parse(buf[:n])
	if err != nil {
		t.Fatal(err)
	}

	resp, ok := parsed.(*message.AssociationSetupResponse)
	if !ok {
		t.Fatalf("unexpected response: %T", parsed)
	}

	assertCause(t, resp.Cause, ie.CauseRequestAccepted)
}
func TestAssociationSourceFailsClosed(t *testing.T) {
	s, _ := startTestPfcpServer(t)
	addr := &net.UDPAddr{
		IP: net.ParseIP("127.0.0.1"),
	}

	s.SetAssociationStateManager(&fakeAssociationState{})

	if s.validAssociationSource(nil, addr) {
		t.Fatal("missing Node ID was accepted")
	}

	if s.validAssociationSource(
		ie.NewCause(ie.CauseRequestRejected), addr,
	) {
		t.Fatal("invalid Node ID was accepted")
	}

	s.SetAssociationStateManager(nil)

	if s.validAssociationSource(
		ie.NewNodeIDHeuristic("127.0.0.1"), addr,
	) {
		t.Fatal("missing manager was accepted")
	}
}
