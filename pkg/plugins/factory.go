package plugins

import (
	"github.com/khulnasoft/tunnel-operator/pkg/configauditreport"
	"github.com/khulnasoft/tunnel-operator/pkg/ext"
	"github.com/khulnasoft/tunnel-operator/pkg/kube"
	"github.com/khulnasoft/tunnel-operator/pkg/plugins/tunnel"
	"github.com/khulnasoft/tunnel-operator/pkg/tunneloperator"
	"github.com/khulnasoft/tunnel-operator/pkg/vulnerabilityreport"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type Resolver struct {
	buildInfo          tunneloperator.BuildInfo
	config             tunneloperator.ConfigData
	namespace          string
	serviceAccountName string
	client             client.Client
	objectResolver     *kube.ObjectResolver
}

func NewResolver() *Resolver {
	return &Resolver{}
}

func (r *Resolver) WithBuildInfo(buildInfo tunneloperator.BuildInfo) *Resolver {
	r.buildInfo = buildInfo
	return r
}

func (r *Resolver) WithConfig(config tunneloperator.ConfigData) *Resolver {
	r.config = config
	return r
}

func (r *Resolver) WithNamespace(namespace string) *Resolver {
	r.namespace = namespace
	return r
}

func (r *Resolver) WithServiceAccountName(name string) *Resolver {
	r.serviceAccountName = name
	return r
}

func (r *Resolver) WithClient(c client.Client) *Resolver {
	r.client = c
	return r
}
func (r *Resolver) WithObjectResolver(objectResolver *kube.ObjectResolver) *Resolver {
	r.objectResolver = objectResolver
	return r
}

// GetVulnerabilityPlugin is a factory method that instantiates the vulnerabilityreport.Plugin.
//
// Tunnel-Operator currently supports Tunnel scanner in Standalone and ClientServer
// mode.
//
// You could add your own scanner by implementing the vulnerabilityreport.Plugin interface.
func (r *Resolver) GetVulnerabilityPlugin() (vulnerabilityreport.Plugin, tunneloperator.PluginContext, error) {
	scanner, err := r.config.GetVulnerabilityReportsScanner()
	if err != nil {
		return nil, nil, err
	}

	pluginContext := tunneloperator.NewPluginContext().
		WithName(string(scanner)).
		WithClient(r.client).
		WithNamespace(r.namespace).
		WithServiceAccountName(r.serviceAccountName).
		WithTunnelOperatorConfig(r.config).
		Get()

	return tunnel.NewPlugin(ext.NewSystemClock(), ext.NewGoogleUUIDGenerator(), r.objectResolver), pluginContext, nil
}

// GetConfigAuditPlugin is a factory method that instantiates the configauditreport.Plugin.
func (r *Resolver) GetConfigAuditPlugin() (configauditreport.PluginInMemory, tunneloperator.PluginContext, error) {
	scanner, err := r.config.GetConfigAuditReportsScanner()
	if err != nil {
		return nil, nil, err
	}

	pluginContext := tunneloperator.NewPluginContext().
		WithName(string(scanner)).
		WithClient(r.client).
		WithNamespace(r.namespace).
		WithServiceAccountName(r.serviceAccountName).
		WithTunnelOperatorConfig(r.config).
		Get()

	return tunnel.NewTunnelConfigAuditPlugin(ext.NewSystemClock(), ext.NewGoogleUUIDGenerator(), r.objectResolver), pluginContext, nil
}
