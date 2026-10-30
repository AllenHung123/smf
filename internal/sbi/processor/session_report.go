package processor

import (
	"fmt"
	"github.com/google/uuid"
	"net/url"

	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"

	"github.com/free5gc/openapi/mediatype/multipart"
	"github.com/free5gc/openapi/models"
	smf_context "github.com/free5gc/smf/internal/context"
	"github.com/free5gc/smf/internal/logger"
	"github.com/free5gc/smf/pkg/factory"
)

// HandleSessionReportRequest executes the SMF procedure for one already parsed
// go-pfcp Session Report Request. It runs in the bounded PFCP worker pool, so a
// report burst cannot create one unbounded goroutine per Usage Report.
func (p *Processor) HandleSessionReportRequest(
	request *message.SessionReportRequest,
) (cause uint8, remoteSEID uint64) {
	if request == nil {
		return ie.CauseMandatoryIEMissing, 0
	}

	localSEID := request.SEID()
	smContext := smf_context.GetSMContextBySEID(localSEID)
	if smContext == nil {
		logger.PfcpLog.Errorf("PFCP Session SEID[%d] not found", localSEID)
		return ie.CauseSessionContextNotFound, 0
	}

	smContext.SMLock.Lock()
	defer smContext.SMLock.Unlock()

	upfNodeID := smContext.GetNodeIDByLocalSEID(localSEID)
	upfAddress := upfNodeID.ResolveNodeIdToIp()
	if upfAddress.IsUnspecified() {
		logger.PfcpLog.Errorf("no PFCP session found with local SEID %d", localSEID)
		return ie.CauseNoEstablishedPFCPAssociation, 0
	}

	pfcpContext := smContext.PFCPContext[upfAddress.String()]
	if pfcpContext == nil {
		logger.PfcpLog.Errorf("PFCP context for Node ID %s and local SEID %d not found", upfNodeID.String(), localSEID)
		return ie.CauseNoEstablishedPFCPAssociation, 0
	}
	remoteSEID = pfcpContext.RemoteSEID

	if request.ReportType == nil {
		logger.PfcpLog.Error("PFCP Session Report Request is missing Report Type")
		return ie.CauseMandatoryIEMissing, remoteSEID
	}
	if _, err := request.ReportType.ReportType(); err != nil {
		logger.PfcpLog.Errorf("decode PFCP Session Report Request Report Type: %v", err)
		return ie.CauseMandatoryIEIncorrect, remoteSEID
	}

	upf := smf_context.RetrieveUPFNodeByNodeID(upfNodeID)
	if upf == nil {
		logger.PfcpLog.Errorf("UPF[%s] not found", upfAddress)
		return ie.CauseNoEstablishedPFCPAssociation, remoteSEID
	}
	if err := upf.IsAssociated(); err != nil {
		logger.PfcpLog.Warnf("PFCP Session Report Request rejected: %v", err)
		return ie.CauseNoEstablishedPFCPAssociation, remoteSEID
	}

	if request.ReportType.HasDLDR() && smContext.UpCnxState == models.Smf_PDUSess_UpCnxState_DEACTIVATED {
		if request.DownlinkDataReport == nil {
			logger.PfcpLog.Error("PFCP Session Report Request has DLDR but no Downlink Data Report")
			return ie.CauseMandatoryIEMissing, remoteSEID
		}
		children, err := request.DownlinkDataReport.DownlinkDataReport()
		if err != nil {
			logger.PfcpLog.Errorf("decode PFCP Downlink Data Report: %v", err)
			return ie.CauseMandatoryIEIncorrect, remoteSEID
		}
		for _, child := range children {
			if child != nil && child.Type == ie.DownlinkDataServiceInformation {
				logger.PfcpLog.Warn("PFCP Downlink Data Service Information handling is not implemented")
				break
			}
		}
		if err = p.notifyAMFOfDownlinkData(smContext); err != nil {
			logger.PfcpLog.Errorf("notify AMF for PFCP Downlink Data Report: %v", err)
			return ie.CauseSystemFailure, remoteSEID
		}
	}

	if request.ReportType.HasUSAR() {
		if len(request.UsageReport) == 0 {
			logger.PfcpLog.Error("PFCP Session Report Request has USAR but no Usage Report")
			return ie.CauseMandatoryIEMissing, remoteSEID
		}
		if err := smContext.HandleReportsAtomically(request.UsageReport, upfNodeID, ""); err != nil {
			logger.PfcpLog.Errorf("decode PFCP Session Report Usage Report: %v", err)
			return ie.CauseMandatoryIEIncorrect, remoteSEID
		}
		p.ReportUsageAndUpdateQuota(smContext)
	}

	return ie.CauseRequestAccepted, remoteSEID
}

// The caller holds SMLock across the request and correlation state update so a
// callback arriving before the HTTP response is read waits for its Location.
func (p *Processor) notifyAMFOfDownlinkData(smContext *smf_context.SMContext) error {
	smContext.N1N2TransferID, smContext.N1N2TransferURI = "", ""
	smContext.N1N2TransferFailure = nil
	transferID := uuid.NewString()
	n2SM, err := smf_context.BuildPDUSessionResourceSetupRequestTransfer(smContext)
	if err != nil {
		return fmt.Errorf("build PDU Session Resource Setup Request Transfer: %w", err)
	}

	request := models.N1N2MessageTransferRequestBody{
		BinaryDataN2Information: &multipart.RelatedContent{
			ContentID: "N2SmInformation",
			Content:   n2SM,
		},
		JsonData: &models.Amf_Comm_N1N2MessageTransferReqData{
			NfId:         smf_context.GetSelf().NfInstanceID,
			PduSessionId: smContext.PDUSessionID,
			N1n2FailureTxfNotifURI: fmt.Sprintf("%s://%s:%d%s/n1n2-failure/%s/%s",
				smf_context.GetSelf().URIScheme,
				smf_context.GetSelf().RegisterIPv4,
				smf_context.GetSelf().SBIPort,
				factory.SmfCallbackUriPrefix,
				smContext.Ref,
				transferID,
			),
			N2InfoContainer: &models.Amf_Comm_N2InfoContainer{
				N2InformationClass: models.Amf_Comm_N2InformationClass_SM,
				SmInfo: &models.Amf_Comm_N2SmInformation{
					PduSessionId: smContext.PDUSessionID,
					N2InfoContent: &models.Amf_Comm_N2InfoContent{
						NgapIeType: models.Amf_Comm_NgapIeType_PDU_RES_SETUP_REQ,
						NgapData:   &models.RefToBinaryData{ContentId: "N2SmInformation"},
					},
					SNssai: smContext.SNssai,
				},
			},
		},
	}

	ctx, _, err := smf_context.GetSelf().GetTokenCtxForNFInstance(
		models.Nrf_NFMgmt_ServiceName_NAMF_COMM,
		models.Nrf_NFMgmt_NFType_AMF,
		smContext.AMFProfile.NfInstanceId,
	)
	if err != nil {
		return fmt.Errorf("get NAMF_COMM token context: %w", err)
	}
	response, err := p.Consumer().N1N2MessageTransferWithLocation(
		ctx, smContext.Supi, request, smContext.CommunicationClientApiPrefix,
	)
	if err != nil {
		return fmt.Errorf("N1N2 Message Transfer: %w", err)
	}
	if response == nil || response.Amf_Comm_N1N2MessageTransferRspData == nil {
		return fmt.Errorf("N1N2 Message Transfer returned no response")
	}

	rspData := response.Amf_Comm_N1N2MessageTransferRspData
	if rspData.Cause == models.Amf_Comm_N1N2MessageTransferCause_ATTEMPTING_TO_REACH_UE ||
		rspData.Cause == models.Amf_Comm_N1N2MessageTransferCause_N1_N2_TRANSFER_INITIATED {
		resourceURI := response.Location
		if resourceURI == "" {
			if rspData.Cause == models.Amf_Comm_N1N2MessageTransferCause_ATTEMPTING_TO_REACH_UE {
				return fmt.Errorf("AMF accepted paging without a Location header")
			}
			// TS 29.518 6.1.6.2.30: no Location (e.g. RRC inactive) uses a dummy URI.
			resourceURI = "http:"
		} else {
			parsed, parseErr := url.Parse(resourceURI)
			if parseErr != nil || (parsed.Scheme != "https" && parsed.Scheme != "http") || parsed.Host == "" {
				return fmt.Errorf("AMF returned invalid transfer Location %q", resourceURI)
			}
		}
		smContext.N1N2TransferID, smContext.N1N2TransferURI = transferID, resourceURI
	}
	switch rspData.Cause {
	case models.Amf_Comm_N1N2MessageTransferCause_ATTEMPTING_TO_REACH_UE:
		logger.PfcpLog.Infof("AMF is attempting to reach the UE")
	case models.Amf_Comm_N1N2MessageTransferCause_UE_NOT_RESPONDING:
		logger.PfcpLog.Warn("UE is not responding to AMF paging")
	}
	return nil
}
