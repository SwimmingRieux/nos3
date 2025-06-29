package grpcclient

import (
	"context"

	mpb "nos3/internal/infrastructure/grpcclient/gen"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type Client struct {
	RegistryService mpb.ServiceRegistryClient
	LogService      mpb.LogClient
	ReportService   mpb.ReportClient
	config          ClientConfig
	conn            *grpc.ClientConn
}

func New(cfg ClientConfig) (*Client, error) {
	conn, err := grpc.NewClient(cfg.Endpoint, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, err
	}

	return &Client{
		RegistryService: mpb.NewServiceRegistryClient(conn),
		LogService:      mpb.NewLogClient(conn),
		config:          cfg,
		conn:            conn,
	}, nil
}

func (c *Client) RegisterService(ctx context.Context,
	port, region string,
) (*mpb.RegisterServiceResponse, error) {
	return c.RegistryService.RegisterService(ctx, &mpb.RegisterServiceRequest{
		Type:                   mpb.ServiceTypeEnum_STORAGE,
		Port:                   port,
		HeartbeatDurationInSec: c.config.Heartbeat,
		Region:                 region,
	})
}

func (c *Client) AddLog(ctx context.Context, msg, stack string) (*mpb.AddLogResponse, error) {
	return c.LogService.AddLog(ctx, &mpb.AddLogRequest{
		Message: msg,
		Stack:   stack,
	})
}

func (c *Client) AddReport(ctx context.Context, pubKey string, blobHashes []string,
	reportType, eventID, content, serverURL string,
) (*mpb.AddReportResponse, error) {
	req := &mpb.AddReportRequest{
		PubKey:     pubKey,
		BlobHashes: blobHashes,
		ReportType: reportType,
	}
	if eventID != "" {
		req.EventId = &eventID
	}
	if content != "" {
		req.Content = &content
	}
	if serverURL != "" {
		req.ServerUrl = &serverURL
	}

	return c.ReportService.AddReport(ctx, req)
}
