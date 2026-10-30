package consumer

import (
	"context"
	"fmt"
	"sync"

	"github.com/free5gc/openapi/amf/Comm"
	"github.com/free5gc/openapi/models"
	sbi_metrics "github.com/free5gc/util/metrics/sbi"
)

type namfService struct {
	consumer *Consumer

	CommunicationMu sync.RWMutex

	CommunicationClients map[string]*Comm.APIClient
}

func (s *namfService) getCommunicationClient(uri string) *Comm.APIClient {
	if uri == "" {
		return nil
	}
	s.CommunicationMu.RLock()
	client, ok := s.CommunicationClients[uri]
	if ok {
		s.CommunicationMu.RUnlock()
		return client
	}

	configuration := Comm.NewConfiguration()
	configuration.SetBasePath(uri)
	configuration.SetMetrics(sbi_metrics.SbiMetricHook)
	client = Comm.NewAPIClient(configuration)

	s.CommunicationMu.RUnlock()
	s.CommunicationMu.Lock()
	defer s.CommunicationMu.Unlock()
	s.CommunicationClients[uri] = client
	return client
}

func (s *namfService) N1N2MessageTransfer(
	ctx context.Context, supi string, n1n2Request models.N1N2MessageTransferRequestBody, apiPrefix string,
) (*models.Amf_Comm_N1N2MessageTransferRspData, error) {
	rsp, err := s.N1N2MessageTransferWithLocation(ctx, supi, n1n2Request, apiPrefix)
	if err != nil || rsp == nil {
		return nil, err
	}
	return rsp.Amf_Comm_N1N2MessageTransferRspData, nil
}

// N1N2MessageTransferWithLocation preserves the resource URI used to correlate
// asynchronous failure notifications, without changing existing callers.
func (s *namfService) N1N2MessageTransferWithLocation(
	ctx context.Context, supi string, n1n2Request models.N1N2MessageTransferRequestBody, apiPrefix string,
) (*Comm.N1N2MessageTransferResponse, error) {
	client := s.getCommunicationClient(apiPrefix)
	if client == nil {
		return nil, fmt.Errorf("N1N2MessageTransfer client is nil: (%v)", apiPrefix)
	}

	n1n2MessageTransferRequest := &Comm.N1N2MessageTransferRequest{
		UeContextId: &supi,
		RequestBody: &n1n2Request,
	}

	rsp, err := client.N1N2MessageCollectionCollectionApi.N1N2MessageTransfer(ctx, n1n2MessageTransferRequest)
	if err != nil || rsp == nil {
		return nil, err
	}

	return rsp, nil
}
