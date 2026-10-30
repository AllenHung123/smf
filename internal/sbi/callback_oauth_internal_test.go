package sbi

import (
	"bytes"
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"testing"

	smf_context "github.com/free5gc/smf/internal/context"
	"github.com/free5gc/smf/pkg/factory"
	"github.com/free5gc/util/idgenerator"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func TestCallbackDoesNotRequireOAuth(t *testing.T) {
	self := smf_context.GetSelf()
	old := self.OAuth2Required
	self.OAuth2Required = true
	t.Cleanup(func() { self.OAuth2Required = old })
	router := gin.New()
	mountCallbackRoutes(router, &Server{})
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodPost,
		factory.SmfCallbackUriPrefix+"/sm-policies/ref/terminate", nil))
	require.Equal(t, http.StatusNotImplemented, response.Code)
	// The ordinary service authorization check remains active with OAuth enabled.
	require.Error(t, self.AuthorizationCheck("", "nsmf-pdusession"))
}

func TestN1N2TransferFailureCallback(t *testing.T) {
	oldGenerator := smf_context.TeidGenerator
	smf_context.TeidGenerator = idgenerator.NewGenerator(1, math.MaxUint32)
	t.Cleanup(func() { smf_context.TeidGenerator = oldGenerator })
	const resource = "https://amf.example/namf-comm/v1/ue-contexts/ue/n1-n2-messages/1"
	for _, tt := range []struct {
		name, storedURI, notifiedURI                   string
		noTransfer, stale, unknown, malformed, missing bool
		want                                           int
	}{
		{name: "matched without token", storedURI: resource, notifiedURI: resource, want: 204},
		{name: "unrelated transfer", storedURI: resource, notifiedURI: resource + "-other", want: 404},
		{name: "no pending transfer", notifiedURI: resource, noTransfer: true, want: 404},
		{name: "superseded callback", storedURI: resource, notifiedURI: resource, stale: true, want: 404},
		{name: "dummy without Location", storedURI: "http:", notifiedURI: "http:", want: 204},
		{name: "alternate dummy scheme", storedURI: "http:", notifiedURI: "https:", want: 204},
		{name: "dummy cannot match real Location", storedURI: resource, notifiedURI: "http:", want: 404},
		{name: "real URI cannot match dummy", storedURI: "http:", notifiedURI: resource, want: 404},
		{name: "unknown session", storedURI: resource, notifiedURI: resource, unknown: true, want: 404},
		{name: "malformed JSON", malformed: true, want: 400},
		{name: "missing fields", missing: true, want: 400},
	} {
		t.Run(tt.name, func(t *testing.T) {
			sm := smf_context.NewSMContext("imsi-r17-callback", 1)
			t.Cleanup(func() { smf_context.RemoveSMContext(sm.Ref) })
			transferID := uuid.NewString()
			sm.N1N2TransferID, sm.N1N2TransferURI = transferID, tt.storedURI
			if tt.noTransfer {
				sm.N1N2TransferID = ""
			}
			if tt.stale {
				sm.N1N2TransferID = uuid.NewString()
			}
			ref := sm.Ref
			if tt.unknown {
				ref = uuid.NewString()
			}
			router := gin.New()
			mountCallbackRoutes(router, &Server{})
			body := fmt.Sprintf(`{"cause":"UE_NOT_RESPONDING","n1n2MsgDataUri":%q}`, tt.notifiedURI)
			if tt.malformed {
				body = "{"
			}
			if tt.missing {
				body = "{}"
			}
			send := func(body string) int {
				req := httptest.NewRequest(http.MethodPost, factory.SmfCallbackUriPrefix+"/n1n2-failure/"+ref+"/"+transferID, bytes.NewBufferString(body))
				req.Header.Set("Content-Type", "application/json")
				response := httptest.NewRecorder()
				router.ServeHTTP(response, req)
				return response.Code
			}
			require.Equal(t, tt.want, send(body))
			if tt.want != 204 {
				require.Nil(t, sm.N1N2TransferFailure)
				return
			}
			first := sm.N1N2TransferFailure
			require.NotNil(t, first)
			require.Equal(t, tt.notifiedURI, first.N1n2MsgDataUri)
			require.Equal(t, 204, send(body), "exact retry is idempotent")
			require.Same(t, first, sm.N1N2TransferFailure)
			require.Equal(t, 409, send(fmt.Sprintf(`{"cause":"AN_NOT_RESPONDING","n1n2MsgDataUri":%q}`, tt.notifiedURI)))
			require.Same(t, first, sm.N1N2TransferFailure, "conflicting retry cannot overwrite outcome")
		})
	}
}
