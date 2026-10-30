package sbi

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/free5gc/openapi"
	"github.com/free5gc/openapi/models"
	smf_context "github.com/free5gc/smf/internal/context"
	"github.com/free5gc/smf/internal/logger"
)

func (s *Server) getCallbackRoutes() []Route {
	return []Route{
		{
			Name:    "N1N2TransferFailureNotification",
			Method:  http.MethodPost,
			Pattern: "/n1n2-failure/:smContextRef/:transferId",
			APIFunc: s.HTTPN1N2TransferFailureNotification,
		},
		{
			Name:    "SmPolicyUpdateNotification",
			Method:  http.MethodPost,
			Pattern: "/sm-policies/:smContextRef/update",
			APIFunc: s.HTTPSmPolicyUpdateNotification,
		},
		{
			Name:    "SmPolicyControlTerminationRequestNotification",
			Method:  http.MethodPost,
			Pattern: "/sm-policies/:smContextRef/terminate",
			APIFunc: s.SmPolicyControlTerminationRequestNotification,
		},
		{
			Name:    "ChargingNotification",
			Method:  http.MethodPost,
			Pattern: "/:notifyUri",
			APIFunc: s.HTTPChargingNotification,
		},
	}
}

// HTTPN1N2TransferFailureNotification receives the asynchronous outcome of
// paging initiated by notifyAMFOfDownlinkData, correlated with the original
// transfer Location and per-request callback identifier.
func (s *Server) HTTPN1N2TransferFailureNotification(c *gin.Context) {
	var notification models.Amf_Comm_N1N2MsgTxfrFailureNotification
	if err := c.ShouldBindJSON(&notification); err != nil || notification.Cause == "" || notification.N1n2MsgDataUri == "" {
		c.JSON(http.StatusBadRequest, models.ProblemDetails{
			Status: http.StatusBadRequest, Cause: "INVALID_MSG_FORMAT",
			Detail: "cause and n1n2MsgDataUri are required",
		})
		return
	}
	smContext := smf_context.GetSMContextByRef(c.Param("smContextRef"))
	if smContext == nil {
		c.JSON(http.StatusNotFound, models.ProblemDetails{
			Status: http.StatusNotFound, Cause: "CONTEXT_NOT_FOUND",
		})
		return
	}
	smContext.SMLock.Lock()
	defer smContext.SMLock.Unlock()
	matches := notification.N1n2MsgDataUri == smContext.N1N2TransferURI
	if smContext.N1N2TransferURI == "http:" {
		// The standard permits any dummy URI with no authority and an empty path.
		uri, err := url.Parse(notification.N1n2MsgDataUri)
		matches = err == nil && uri.Scheme != "" && uri.Host == "" && uri.Path == "" && uri.Opaque == "" &&
			uri.User == nil && uri.RawQuery == "" && uri.Fragment == ""
	}
	if smContext.N1N2TransferID == "" || c.Param("transferId") != smContext.N1N2TransferID || !matches {
		c.JSON(http.StatusNotFound, models.ProblemDetails{Status: http.StatusNotFound, Cause: "CONTEXT_NOT_FOUND",
			Detail: "notification does not match an outstanding N1/N2 transfer"})
		return
	}
	if previous := smContext.N1N2TransferFailure; previous != nil {
		if previous.Cause != notification.Cause || previous.N1n2MsgDataUri != notification.N1n2MsgDataUri {
			c.JSON(http.StatusConflict, models.ProblemDetails{Status: http.StatusConflict, Cause: "CONFLICTING_REQUEST"})
			return
		}
		c.Status(http.StatusNoContent)
		return
	}
	smContext.N1N2TransferFailure = &notification
	smContext.Log.Warnf("N1/N2 transfer failed: cause=%s, resource=%s", notification.Cause, notification.N1n2MsgDataUri)
	c.Status(http.StatusNoContent)
}

// SubscriptionsPost -
func (s *Server) HTTPSmPolicyUpdateNotification(c *gin.Context) {
	var request models.Pcf_SMPolCtrl_SmPolicyNotification

	reqBody, err := c.GetRawData()
	if err != nil {
		logger.PduSessLog.Errorln("GetRawData failed")
	}

	err = openapi.Deserialize(&request, reqBody, c.ContentType())
	if err != nil {
		logger.PduSessLog.Errorln("Deserialize request failed")
	}

	smContextRef := c.Params.ByName("smContextRef")
	s.Processor().HandleSMPolicyUpdateNotify(c, request, smContextRef)
}

func (s *Server) SmPolicyControlTerminationRequestNotification(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{})
}

func (s *Server) HTTPChargingNotification(c *gin.Context) {
	var req models.Chf_ConvCharging_ChargingNotifyRequest

	requestBody, err := c.GetRawData()
	if err != nil {
		logger.PduSessLog.Errorln("GetRawData failed")
	}

	err = openapi.Deserialize(&req, requestBody, APPLICATION_JSON)
	if err != nil {
		logger.PduSessLog.Errorln("Deserialize request failed")
	}

	notifyURI := c.Params.ByName("notifyUri")
	uriparts := strings.SplitN(notifyURI, "_", 2)
	if len(uriparts) != 2 || uriparts[0] != "notify" || uriparts[1] == "" {
		logger.PduSessLog.Warnf("Invalid notifyUri format: %s", notifyURI)
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid notifyUri format"})
		return
	}

	smContextRef := uriparts[1]

	s.Processor().HandleChargingNotification(c, req, smContextRef)
}
