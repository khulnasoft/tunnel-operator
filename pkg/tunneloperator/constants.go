package tunneloperator

const (
	// NamespaceName the name of the namespace in which Trivy-operator stores its
	// configuration and where it runs scan jobs.
	NamespaceName = "tunnel-operator"

	// ConfigMapName the name of the ConfigMap where Trivy-operator stores its
	// configuration.
	ConfigMapName = "tunnel-operator"

	// SecretName the name of the secret where Trivy-operator stores is sensitive
	// configuration.
	SecretName = "tunnel-operator"

	// PoliciesConfigMapName the name of the ConfigMap used to store OPA Rego
	// policies.
	PoliciesConfigMapName = "tunnel-operator-policies-config"
)

const (
	LabelResourceKind      = "tunnel-operator.resource.kind"
	LabelResourceName      = "tunnel-operator.resource.name"
	LabelResourceNameHash  = "tunnel-operator.resource.name-hash"
	LabelResourceNamespace = "tunnel-operator.resource.namespace"
	LabelContainerName     = "tunnel-operator.container.name"
	LabelResourceSpecHash  = "resource-spec-hash"
	LabelPluginConfigHash  = "plugin-config-hash"

	LabelVulnerabilityReportScanner = "vulnerabilityReport.scanner"
	LabelNodeInfoCollector          = "node-info.collector"

	LabelK8SAppManagedBy = "app.kubernetes.io/managed-by"
	AppTrivyOperator     = "tunnel-operator"
)

const (
	AnnotationContainerImages = "tunnel-operator.container-images"
)
