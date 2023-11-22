package configauditreport

import (
	"github.com/khulnasoft/tunnel-operator/pkg/tunneloperator"
)

// PluginInMemory defines the interface between tunnel-operator and tunnel configuration
type PluginInMemory interface {

	// Init is a callback to initialize this plugin, e.g. ensure the default
	// configuration.
	Init(ctx tunneloperator.PluginContext) error

	NewConfigForConfigAudit(ctx tunneloperator.PluginContext) (ConfigAuditConfig, error)
}

// ConfigAuditConfig defines the interface between tunnel-operator and tunnel configuration which related to configauditreport
type ConfigAuditConfig interface {

	// GetUseBuiltinRegoPolicies return tunnel config which associated to configauditreport plugin
	GetUseBuiltinRegoPolicies() bool
	// GetSupportedConfigAuditKinds list of supported kinds to be scanned by the config audit scanner
	GetSupportedConfigAuditKinds() []string

	// GetSeverity get security level
	GetSeverity() string
}
