package jobs

import (
	"context"

	"github.com/khulnasoft/tunnel-operator/pkg/operator/etc"
	"github.com/khulnasoft/tunnel-operator/pkg/tunneloperator"
	batchv1 "k8s.io/api/batch/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const ScannerName = "Tunnel"

type LimitChecker interface {
	Check(ctx context.Context) (bool, int, error)
	CheckNodes(ctx context.Context) (bool, int, error)
}

func NewLimitChecker(config etc.Config, c client.Client, tunnelOperatorConfig tunneloperator.ConfigData) LimitChecker {
	return &checker{
		config:              config,
		client:              c,
		tunnelOperatorConfig: tunnelOperatorConfig,
	}
}

type checker struct {
	config              etc.Config
	client              client.Client
	tunnelOperatorConfig tunneloperator.ConfigData
}

func (c *checker) Check(ctx context.Context) (bool, int, error) {
	matchinglabels := client.MatchingLabels{
		tunneloperator.LabelK8SAppManagedBy:            tunneloperator.AppTunnelOperator,
		tunneloperator.LabelVulnerabilityReportScanner: ScannerName,
	}
	scanJobsCount, err := c.countJobs(ctx, matchinglabels)
	if err != nil {
		return false, 0, err
	}

	return scanJobsCount >= c.config.ConcurrentScanJobsLimit, scanJobsCount, nil
}

func (c *checker) CheckNodes(ctx context.Context) (bool, int, error) {
	matchinglabels := client.MatchingLabels{
		tunneloperator.LabelK8SAppManagedBy:   tunneloperator.AppTunnelOperator,
		tunneloperator.LabelNodeInfoCollector: ScannerName,
	}
	scanJobsCount, err := c.countJobs(ctx, matchinglabels)
	if err != nil {
		return false, 0, err
	}

	return scanJobsCount >= c.config.ConcurrentNodeCollectorLimit, scanJobsCount, nil
}

func (c *checker) countJobs(ctx context.Context, matchingLabels client.MatchingLabels) (int, error) {
	var scanJobs batchv1.JobList
	listOptions := []client.ListOption{matchingLabels}
	if !c.tunnelOperatorConfig.VulnerabilityScanJobsInSameNamespace() {
		// scan jobs are running in only tunneloperator operator namespace
		listOptions = append(listOptions, client.InNamespace(c.config.Namespace))
	}
	err := c.client.List(ctx, &scanJobs, listOptions...)
	if err != nil {
		return 0, err
	}

	return len(scanJobs.Items), nil
}
