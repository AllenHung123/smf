package processor

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	nasie "github.com/free5gc/nas/ie"
	"github.com/free5gc/openapi"
	"github.com/free5gc/openapi/models"
	smf_context "github.com/free5gc/smf/internal/context"
	"github.com/free5gc/smf/internal/sbi/consumer"
	"github.com/free5gc/smf/pkg/app"
)

type reportOAuthApp struct {
	app.App
	consumer *consumer.Consumer
}

func (a *reportOAuthApp) Consumer() *consumer.Consumer { return a.consumer }

func TestDownlinkNotificationBindsAMFInstance(t *testing.T) {
	self := smf_context.GetSelf()
	previousID, previousURI, previousOAuth := self.NfInstanceID, self.NrfUri, self.OAuth2Required
	previousScheme, previousAddress, previousPort := self.URIScheme, self.RegisterIPv4, self.SBIPort
	t.Cleanup(func() {
		self.NfInstanceID, self.NrfUri, self.OAuth2Required = previousID, previousURI, previousOAuth
		self.URIScheme, self.RegisterIPv4, self.SBIPort = previousScheme, previousAddress, previousPort
	})

	tokenRequests := make(chan url.Values, 8)
	nrf := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Errorf("parse token request: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		tokenRequests <- r.PostForm
		w.Header().Set("Content-Type", "application/json")
		_, err := w.Write([]byte(`{"access_token":"report-token","token_type":"Bearer","expires_in":60}`))
		if err != nil {
			t.Errorf("write token response: %v", err)
		}
	}))
	nrf.EnableHTTP2 = true
	nrf.StartTLS()
	t.Cleanup(nrf.Close)

	transferTokens := make(chan string, 8)
	transferBodies := make(chan models.N1N2MessageTransferRequestBody, 8)
	const amfTransferLocation = "https://amf.example/namf-comm/v1/ue-contexts/ue/n1-n2-messages/42"
	amf := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		transferTokens <- r.Header.Get("Authorization")
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read transfer: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		var transfer models.N1N2MessageTransferRequestBody
		if err := openapi.Deserialize(&transfer, body, r.Header.Get("Content-Type")); err != nil {
			t.Errorf("decode transfer: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		transferBodies <- transfer
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasPrefix(r.URL.Path, "/dummy"):
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"cause":"N1_N2_TRANSFER_INITIATED"}`))
			return
		case strings.HasPrefix(r.URL.Path, "/missing"):
		case strings.HasPrefix(r.URL.Path, "/invalid"):
			w.Header().Set("Location", "not-an-absolute-resource-uri")
		default:
			w.Header().Set("Location", amfTransferLocation)
		}
		w.WriteHeader(http.StatusAccepted)
		_, err = w.Write([]byte(`{"cause":"ATTEMPTING_TO_REACH_UE"}`))
		if err != nil {
			t.Errorf("write AMF response: %v", err)
		}
	}))
	amf.EnableHTTP2 = true
	amf.StartTLS()
	t.Cleanup(amf.Close)

	self.NfInstanceID, self.NrfUri, self.OAuth2Required = uuid.NewString(), nrf.URL, true
	self.URIScheme, self.RegisterIPv4, self.SBIPort = models.UriScheme_HTTP, "127.0.0.2", 8000
	amfID := uuid.NewString()
	smContext := &smf_context.SMContext{
		Ref:                             uuid.New().URN(),
		Smf_PDUSess_SmContextCreateData: &models.Smf_PDUSess_SmContextCreateData{Supi: "imsi-208930000000001"},
		PDUSessionID:                    1,
		AMFProfile:                      models.Nrf_NFDisc_NFProfile{NfInstanceId: amfID},
		CommunicationClientApiPrefix:    amf.URL,
		SelectedPDUSessionType:          nasie.PDUSessType_IPv4,
		SelectedSessionRuleID:           "default",
		SessionRules: map[string]*smf_context.SessionRule{
			"default": smf_context.NewSessionRule(&models.Pcf_SMPolCtrl_SessionRule{
				AuthSessAmbr: &models.Ambr{Uplink: "1 Mbps", Downlink: "1 Mbps"},
				AuthDefQos: &models.Pcf_SMPolCtrl_AuthorizedDefaultQos{
					Var5qi: 9, Arp: &models.Arp{PriorityLevel: 1},
				},
			}),
		},
		Tunnel: &smf_context.UPTunnel{DataPathPool: smf_context.DataPathPool{
			1: {IsDefaultPath: true, FirstDPNode: &smf_context.DataPathNode{
				UPF: &smf_context.UPF{N3Interfaces: []*smf_context.UPFInterfaceInfo{
					{IPv4EndPointAddresses: []net.IP{net.ParseIP("192.0.2.1").To4()}},
				}},
			}},
		}},
	}
	application := &reportOAuthApp{}
	var err error
	application.consumer, err = consumer.NewConsumer(application)
	require.NoError(t, err)
	p, err := NewProcessor(application)
	require.NoError(t, err)
	smContext.SMLock.Lock()
	require.NoError(t, p.notifyAMFOfDownlinkData(smContext))
	smContext.SMLock.Unlock()
	require.Equal(t, amfTransferLocation, smContext.N1N2TransferURI)
	require.NotEmpty(t, smContext.N1N2TransferID)
	select {
	case transfer := <-transferBodies:
		require.NotNil(t, transfer.JsonData)
		require.Equal(t, self.NfInstanceID, transfer.JsonData.NfId)
		require.Equal(t, "http://127.0.0.2:8000/nsmf-callback/v1/n1n2-failure/"+smContext.Ref+"/"+smContext.N1N2TransferID,
			transfer.JsonData.N1n2FailureTxfNotifURI)
	default:
		t.Fatal("AMF did not receive a decodable transfer request")
	}

	select {
	case request := <-tokenRequests:
		require.Equal(t, self.NfInstanceID, request.Get("nfInstanceId"))
		require.Equal(t, "namf-comm", request.Get("scope"))
		require.Equal(t, "AMF", request.Get("targetNfType"))
		require.Equal(t, amfID, request.Get("targetNfInstanceId"))
	default:
		t.Fatal("downlink notification did not request an NRF token")
	}
	select {
	case token := <-transferTokens:
		require.Equal(t, "Bearer report-token", token)
	default:
		t.Fatal("downlink notification did not reach AMF")
	}
	previousTransferID := smContext.N1N2TransferID
	for _, tc := range []struct {
		path, wantURI string
		wantError     bool
	}{
		{"/dummy", "http:", false},
		{"/missing", "", true},
		{"/invalid", "", true},
		{"/", amfTransferLocation, false},
	} {
		t.Run(tc.path, func(t *testing.T) {
			smContext.CommunicationClientApiPrefix = amf.URL + tc.path
			smContext.SMLock.Lock()
			err := p.notifyAMFOfDownlinkData(smContext)
			smContext.SMLock.Unlock()
			if tc.wantError {
				require.Error(t, err)
				require.Empty(t, smContext.N1N2TransferID, "failed transfer must invalidate old correlation")
			} else {
				require.NoError(t, err)
				require.NotEmpty(t, smContext.N1N2TransferID)
				require.NotEqual(t, previousTransferID, smContext.N1N2TransferID, "new transfer gets a fresh callback ID")
				previousTransferID = smContext.N1N2TransferID
			}
			require.Equal(t, tc.wantURI, smContext.N1N2TransferURI)
		})
	}

}
