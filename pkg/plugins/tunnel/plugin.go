package tunnel

import (
	"encoding/json"
	"io"

	"github.com/khulnasoft/tunnel-operator/pkg/exposedsecretreport"
	"github.com/khulnasoft/tunnel-operator/pkg/sbomreport"
	"github.com/khulnasoft/tunnel-operator/pkg/utils"

	containerimage "github.com/google/go-containerregistry/pkg/name"

	"github.com/khulnasoft/tunnel-operator/pkg/apis/khulnasoft/v1alpha1"
	"github.com/khulnasoft/tunnel-operator/pkg/configauditreport"
	"github.com/khulnasoft/tunnel-operator/pkg/docker"
	"github.com/khulnasoft/tunnel-operator/pkg/ext"
	"github.com/khulnasoft/tunnel-operator/pkg/kube"
	"github.com/khulnasoft/tunnel-operator/pkg/tunneloperator"
	"github.com/khulnasoft/tunnel-operator/pkg/vulnerabilityreport"
	ty "github.com/khulnasoft/tunnel/pkg/types"
	corev1 "k8s.io/api/core/v1"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	// Plugin the name of this plugin.
	Plugin = "Tunnel"
)

const (
	SupportedConfigAuditKinds = "Workload,Service,Role,ClusterRole,NetworkPolicy,Ingress,LimitRange,ResourceQuota"
)

const (
	DefaultImageRepository  = "ghcr.io/khulnasoft/tunnel"
	DefaultDBRepository     = "ghcr.io/khulnasoft-lab/tunnel-db"
	DefaultJavaDBRepository = "ghcr.io/khulnasoft-lab/tunnel-java-db"
	DefaultSeverity         = "UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL"
)

type plugin struct {
	clock          ext.Clock
	idGenerator    ext.IDGenerator
	objectResolver *kube.ObjectResolver
}

// NewPlugin constructs a new vulnerabilityreport.Plugin, which is using an
// upstream Tunnel container image to scan Kubernetes workloads.
//
// The plugin supports Image and Filesystem commands. The Filesystem command may
// be used to scan workload images cached on cluster nodes by scheduling
// scan jobs on a particular node.
//
// The Image command supports both Standalone and ClientServer modes depending
// on the settings returned by Config.GetMode. The ClientServer mode is usually
// more performant, however it requires a Tunnel server accessible at the
// configurable Config.GetServerURL.
func NewPlugin(clock ext.Clock, idGenerator ext.IDGenerator, objectResolver *kube.ObjectResolver) vulnerabilityreport.Plugin {
	plugin := &plugin{
		clock:          clock,
		idGenerator:    idGenerator,
		objectResolver: objectResolver,
	}
	return plugin
}

// NewTunnelConfigAuditPlugin constructs a new configAudit.Plugin, which is using an
// upstream Tunnel config audit scanner lib.
func NewTunnelConfigAuditPlugin(clock ext.Clock, idGenerator ext.IDGenerator, objectResolver *kube.ObjectResolver) configauditreport.PluginInMemory {
	return &plugin{
		clock:          clock,
		idGenerator:    idGenerator,
		objectResolver: objectResolver,
	}
}

// Init ensures the default Config required by this plugin.
func (p *plugin) Init(ctx tunneloperator.PluginContext) error {
	return ctx.EnsureConfig(tunneloperator.PluginConfig{
		Data: map[string]string{
			keyTunnelImageRepository:           DefaultImageRepository,
			keyTunnelImageTag:                  "0.47.0",
			KeyTunnelSeverity:                  DefaultSeverity,
			keyTunnelSlow:                      "true",
			keyTunnelMode:                      string(Standalone),
			keyTunnelTimeout:                   "5m0s",
			keyTunnelDBRepository:              DefaultDBRepository,
			keyTunnelJavaDBRepository:          DefaultJavaDBRepository,
			keyTunnelUseBuiltinRegoPolicies:    "true",
			keyTunnelSupportedConfigAuditKinds: SupportedConfigAuditKinds,
			keyResourcesRequestsCPU:           "100m",
			keyResourcesRequestsMemory:        "100M",
			keyResourcesLimitsCPU:             "500m",
			keyResourcesLimitsMemory:          "500M",
		},
	})
}

func (p *plugin) GetScanJobSpec(ctx tunneloperator.PluginContext, workload client.Object, credentials map[string]docker.Auth, securityContext *corev1.SecurityContext, sbomClusterReport map[string]v1alpha1.SbomReportData) (corev1.PodSpec, []*corev1.Secret, error) {
	config, err := getConfig(ctx)
	if err != nil {
		return corev1.PodSpec{}, nil, err
	}
	var podSpec corev1.PodSpec
	var secrets []*corev1.Secret
	podSpec, secrets, err = NewPodSpecMgr(config).GetPodSpec(ctx, config, workload, credentials, securityContext, p, sbomClusterReport)

	// add image pull secret to be used when pulling tunnel image fom private registry
	podSpec.ImagePullSecrets = config.GetImagePullSecret()
	return podSpec, secrets, err
}

const (
	tmpVolumeName               = "tmp"
	ignoreFileVolumeName        = "ignorefile"
	sslCertDirVolumeName        = "ssl-cert-dir"
	ignoreFileName              = ".tunnelignore"
	ignoreFileMountPath         = "/etc/tunnel/" + ignoreFileName
	ignorePolicyVolumeName      = "ignorepolicy"
	ignorePolicyName            = "policy.rego"
	ignorePolicyMountPath       = "/etc/tunnel/" + ignorePolicyName
	scanResultVolumeName        = "scanresult"
	FsSharedVolumeName          = "tunneloperator"
	SharedVolumeLocationOfTunnel = "/var/tunneloperator/tunnel"
	SslCertDir                  = "/var/ssl-cert"
)

func (p *plugin) ParseReportData(ctx tunneloperator.PluginContext, imageRef string, logsReader io.ReadCloser) (v1alpha1.VulnerabilityReportData, v1alpha1.ExposedSecretReportData, *v1alpha1.SbomReportData, error) {
	var vulnReport v1alpha1.VulnerabilityReportData
	var secretReport v1alpha1.ExposedSecretReportData
	var sbomReport v1alpha1.SbomReportData

	config, err := getConfig(ctx)
	if err != nil {
		return vulnReport, secretReport, &sbomReport, err
	}
	cmd := config.GetCommand()
	if err != nil {
		return vulnReport, secretReport, &sbomReport, err
	}
	compressedLogs := ctx.GetTunnelOperatorConfig().CompressLogs()
	if compressedLogs && cmd != Filesystem && cmd != Rootfs {
		var errCompress error
		logsReader, errCompress = utils.ReadCompressData(logsReader)
		if errCompress != nil {
			return vulnReport, secretReport, &sbomReport, errCompress
		}
	}

	var reports ty.Report
	err = json.NewDecoder(logsReader).Decode(&reports)
	if err != nil {
		return vulnReport, secretReport, &sbomReport, err
	}

	registry, artifact, err := p.parseImageRef(imageRef, reports.Metadata.ImageID)
	if err != nil {
		return vulnReport, secretReport, &sbomReport, err
	}

	tunnelImageRef, err := config.GetImageRef()
	if err != nil {
		return vulnReport, secretReport, &sbomReport, err
	}

	version, err := tunneloperator.GetVersionFromImageRef(tunnelImageRef)
	if err != nil {
		return vulnReport, secretReport, &sbomReport, err
	}
	var sbomData *v1alpha1.SbomReportData
	if ctx.GetTunnelOperatorConfig().GenerateSbomEnabled() {
		sbomData, err = sbomreport.BuildSbomReportData(reports, p.clock, registry, artifact, version)
		if err != nil {
			return vulnReport, secretReport, &sbomReport, err
		}
	}
	vulnerabilities := make([]v1alpha1.Vulnerability, 0)
	secrets := make([]v1alpha1.ExposedSecret, 0)
	for _, report := range reports.Results {
		addFields := config.GetAdditionalVulnerabilityReportFields()
		vulnerabilities = append(vulnerabilities, vulnerabilityreport.GetVulnerabilitiesFromScanResult(report, addFields)...)
		secrets = append(secrets, getExposedSecretsFromScanResult(report)...)
	}
	vulnerabilitiesData := vulnerabilityreport.BuildVulnerabilityReportData(p.clock, registry, artifact, version, vulnerabilities)
	exposedSecretsData := exposedsecretreport.BuildExposedSecretsReportData(p.clock, registry, artifact, version, secrets)
	return vulnerabilitiesData, exposedSecretsData, sbomData, nil

}

func getExposedSecretsFromScanResult(report ty.Result) []v1alpha1.ExposedSecret {
	secrets := make([]v1alpha1.ExposedSecret, 0)

	for _, sr := range report.Secrets {
		secrets = append(secrets, v1alpha1.ExposedSecret{
			Target:   report.Target,
			RuleID:   sr.RuleID,
			Title:    sr.Title,
			Severity: v1alpha1.Severity(sr.Severity),
			Category: string(sr.Category),
			Match:    sr.Match,
		})
	}

	return secrets
}

// NewConfigForConfigAudit and interface which expose related configaudit report configuration
func (p *plugin) NewConfigForConfigAudit(ctx tunneloperator.PluginContext) (configauditreport.ConfigAuditConfig, error) {
	return getConfig(ctx)
}

func (p *plugin) parseImageRef(imageRef string, imageID string) (v1alpha1.Registry, v1alpha1.Artifact, error) {
	ref, err := containerimage.ParseReference(imageRef)
	if err != nil {
		return v1alpha1.Registry{}, v1alpha1.Artifact{}, err
	}
	registry := v1alpha1.Registry{
		Server: ref.Context().RegistryStr(),
	}
	artifact := v1alpha1.Artifact{
		Repository: ref.Context().RepositoryStr(),
	}
	switch t := ref.(type) {
	case containerimage.Tag:
		artifact.Tag = t.TagStr()
	case containerimage.Digest:
		artifact.Digest = t.DigestStr()
	}
	if len(artifact.Digest) == 0 {
		artifact.Digest = imageID
	}
	return registry, artifact, nil
}
