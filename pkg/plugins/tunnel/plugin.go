package tunnel

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/khulnasoft-lab/tunnel-db/pkg/types"
	"github.com/khulnasoft/tunnel-operator/pkg/utils"
	fg "github.com/khulnasoft/tunnel/pkg/flag"
	tr "github.com/khulnasoft/tunnel/pkg/report"
	ty "github.com/khulnasoft/tunnel/pkg/types"
	containerimage "github.com/google/go-containerregistry/pkg/name"

	"github.com/khulnasoft/tunnel-operator/pkg/configauditreport"

	"github.com/khulnasoft/tunnel-operator/pkg/apis/khulnasoft/v1alpha1"
	"github.com/khulnasoft/tunnel-operator/pkg/docker"
	"github.com/khulnasoft/tunnel-operator/pkg/ext"
	"github.com/khulnasoft/tunnel-operator/pkg/kube"
	"github.com/khulnasoft/tunnel-operator/pkg/tunneloperator"
	"github.com/khulnasoft/tunnel-operator/pkg/vulnerabilityreport"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/pointer"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	// Plugin the name of this plugin.
	Plugin = "Tunnel"
)

const (
	AWSECR_Image_Regex        = "^\\d+\\.dkr\\.ecr\\.(\\w+-\\w+-\\d+)\\.amazonaws\\.com\\/"
	SupportedConfigAuditKinds = "Workload,Service,Role,ClusterRole,NetworkPolicy,Ingress,LimitRange,ResourceQuota"
	// SkipDirsAnnotation annotation  example: tunnel-operator.khulnasoft.github.io/skip-dirs: "/tmp,/home"
	SkipDirsAnnotation = "tunnel-operator.khulnasoft.github.io/skip-dirs"
	// SkipFilesAnnotation example: tunnel-operator.khulnasoft.github.io/skip-files: "/src/Gemfile.lock,/examplebinary"
	SkipFilesAnnotation = "tunnel-operator.khulnasoft.github.io/skip-files"
)

const (
	keyTunnelImageRepository = "tunnel.repository"
	keyTunnelImageTag        = "tunnel.tag"
	//nolint:gosec
	keyTunnelImagePullSecret                     = "tunnel.imagePullSecret"
	keyTunnelMode                                = "tunnel.mode"
	keyTunnelAdditionalVulnerabilityReportFields = "tunnel.additionalVulnerabilityReportFields"
	keyTunnelCommand                             = "tunnel.command"
	KeyTunnelSeverity                            = "tunnel.severity"
	keyTunnelSlow                                = "tunnel.slow"
	keyTunnelVulnType                            = "tunnel.vulnType"
	keyTunnelIgnoreUnfixed                       = "tunnel.ignoreUnfixed"
	keyTunnelOfflineScan                         = "tunnel.offlineScan"
	keyTunnelTimeout                             = "tunnel.timeout"
	keyTunnelIgnoreFile                          = "tunnel.ignoreFile"
	keyTunnelIgnorePolicy                        = "tunnel.ignorePolicy"
	keyTunnelInsecureRegistryPrefix              = "tunnel.insecureRegistry."
	keyTunnelNonSslRegistryPrefix                = "tunnel.nonSslRegistry."
	keyTunnelMirrorPrefix                        = "tunnel.registry.mirror."
	keyTunnelHTTPProxy                           = "tunnel.httpProxy"
	keyTunnelHTTPSProxy                          = "tunnel.httpsProxy"
	keyTunnelNoProxy                             = "tunnel.noProxy"
	keyTunnelSslCertDir                          = "tunnel.sslCertDir"
	// nolint:gosec // This is not a secret, but a configuration value.
	keyTunnelGitHubToken          = "tunnel.githubToken"
	keyTunnelSkipFiles            = "tunnel.skipFiles"
	keyTunnelSkipDirs             = "tunnel.skipDirs"
	keyTunnelDBRepository         = "tunnel.dbRepository"
	keyTunnelJavaDBRepository     = "tunnel.javaDbRepository"
	keyTunnelDBRepositoryInsecure = "tunnel.dbRepositoryInsecure"

	keyTunnelUseBuiltinRegoPolicies    = "tunnel.useBuiltinRegoPolicies"
	keyTunnelSupportedConfigAuditKinds = "tunnel.supportedConfigAuditKinds"

	keyTunnelServerURL              = "tunnel.serverURL"
	keyTunnelClientServerSkipUpdate = "tunnel.clientServerSkipUpdate"
	keyTunnelSkipJavaDBUpdate       = "tunnel.skipJavaDBUpdate"
	// nolint:gosec // This is not a secret, but a configuration value.
	keyTunnelServerTokenHeader = "tunnel.serverTokenHeader"
	keyTunnelServerInsecure    = "tunnel.serverInsecure"
	// nolint:gosec // This is not a secret, but a configuration value.
	keyTunnelServerToken         = "tunnel.serverToken"
	keyTunnelServerCustomHeaders = "tunnel.serverCustomHeaders"

	keyResourcesRequestsCPU             = "tunnel.resources.requests.cpu"
	keyResourcesRequestsMemory          = "tunnel.resources.requests.memory"
	keyResourcesLimitsCPU               = "tunnel.resources.limits.cpu"
	keyResourcesLimitsMemory            = "tunnel.resources.limits.memory"
	keyResourcesRequestEphemeralStorage = "tunnel.resources.requests.ephemeral-storage"
	keyResourcesLimitEphemeralStorage   = "tunnel.resources.limits.ephemeral-storage"
)

const (
	DefaultImageRepository  = "ghcr.io/khulnasoft/tunnel"
	DefaultDBRepository     = "ghcr.io/khulnasoft-lab/tunnel-db"
	DefaultJavaDBRepository = "ghcr.io/khulnasoft/tunnel-java-db"
	DefaultSeverity         = "UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL"
)

// Mode in which Tunnel client operates.
type Mode string

const (
	Standalone   Mode = "Standalone"
	ClientServer Mode = "ClientServer"
)

// Command to scan image or filesystem.
type Command string

const (
	Filesystem Command = "filesystem"
	Image      Command = "image"
	Rootfs     Command = "rootfs"
)

type AdditionalFields struct {
	Description bool
	Links       bool
	CVSS        bool
	Target      bool
	Class       bool
	PackageType bool
	PkgPath     bool
}

// Config defines configuration params for this plugin.
type Config struct {
	tunneloperator.PluginConfig
}

func (c Config) GetAdditionalVulnerabilityReportFields() AdditionalFields {
	addFields := AdditionalFields{}

	fields, ok := c.Data[keyTunnelAdditionalVulnerabilityReportFields]
	if !ok {
		return addFields
	}
	for _, field := range strings.Split(fields, ",") {
		switch strings.TrimSpace(field) {
		case "Description":
			addFields.Description = true
		case "Links":
			addFields.Links = true
		case "CVSS":
			addFields.CVSS = true
		case "Target":
			addFields.Target = true
		case "Class":
			addFields.Class = true
		case "PackageType":
			addFields.PackageType = true
		case "PackagePath":
			addFields.PkgPath = true
		}
	}
	return addFields
}

// GetImageRef returns upstream Tunnel container image reference.
func (c Config) GetImageRef() (string, error) {
	repository, err := c.GetRequiredData(keyTunnelImageRepository)
	if err != nil {
		return "", err
	}
	tag, err := c.GetImageTag()
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("%s:%s", repository, tag), nil
}

// GetImageTag returns upstream Tunnel container image tag.
func (c Config) GetImageTag() (string, error) {
	tag, err := c.GetRequiredData(keyTunnelImageTag)
	if err != nil {
		return "", err
	}
	return tag, nil
}

func (c Config) GetImagePullSecret() []corev1.LocalObjectReference {
	ips, ok := c.Data[keyTunnelImagePullSecret]
	if !ok {
		return []corev1.LocalObjectReference{}
	}
	return []corev1.LocalObjectReference{{Name: ips}}
}

func (c Config) GetMode() (Mode, error) {
	var ok bool
	var value string
	if value, ok = c.Data[keyTunnelMode]; !ok {
		return "", fmt.Errorf("property %s not set", keyTunnelMode)
	}

	switch Mode(value) {
	case Standalone:
		return Standalone, nil
	case ClientServer:
		return ClientServer, nil
	}

	return "", fmt.Errorf("invalid value (%s) of %s; allowed values (%s, %s)",
		value, keyTunnelMode, Standalone, ClientServer)
}

func (c Config) GetCommand() (Command, error) {
	var ok bool
	var value string
	if value, ok = c.Data[keyTunnelCommand]; !ok {
		// for backward compatibility, fallback to ImageScan
		return Image, nil
	}
	switch Command(value) {
	case Image:
		return Image, nil
	case Filesystem:
		return Filesystem, nil
	case Rootfs:
		return Rootfs, nil
	}
	return "", fmt.Errorf("invalid value (%s) of %s; allowed values (%s, %s, %s)",
		value, keyTunnelCommand, Image, Filesystem, Rootfs)
}

func (c Config) GetServerURL() (string, error) {
	return c.GetRequiredData(keyTunnelServerURL)
}

func (c Config) GetClientServerSkipUpdate() bool {
	val, ok := c.Data[keyTunnelClientServerSkipUpdate]
	if !ok {
		return false
	}
	boolVal, err := strconv.ParseBool(val)
	if err != nil {
		return false
	}
	return boolVal
}

func (c Config) GetSkipJavaDBUpdate() bool {
	val, ok := c.Data[keyTunnelSkipJavaDBUpdate]
	if !ok {
		return false
	}
	boolVal, err := strconv.ParseBool(val)
	if err != nil {
		return false
	}
	return boolVal
}

func (c Config) GetServerInsecure() bool {
	_, ok := c.Data[keyTunnelServerInsecure]
	return ok
}

func (c Config) GetDBRepositoryInsecure() bool {
	val, ok := c.Data[keyTunnelDBRepositoryInsecure]
	if !ok {
		return false
	}
	boolVal, _ := strconv.ParseBool(val)
	return boolVal
}
func (c Config) GetUseBuiltinRegoPolicies() bool {
	val, ok := c.Data[keyTunnelUseBuiltinRegoPolicies]
	if !ok {
		return true
	}
	boolVal, err := strconv.ParseBool(val)
	if err != nil {
		return true
	}
	return boolVal
}
func (c Config) GetSslCertDir() string {
	val, ok := c.Data[keyTunnelSslCertDir]
	if !ok {
		return ""
	}
	return val
}

func (c Config) GetSeverity() string {
	val, ok := c.Data[KeyTunnelSeverity]
	if !ok {
		return ""
	}
	return val
}

func (c Config) GetSlow() bool {
	val, ok := c.Data[keyTunnelSlow]
	if !ok {
		return true
	}
	boolVal, err := strconv.ParseBool(val)
	if err != nil {
		return true
	}
	return boolVal
}

func (c Config) GetVulnType() string {
	val, ok := c.Data[keyTunnelVulnType]
	if !ok {
		return ""
	}
	trimmedVulnType := strings.TrimSpace(val)
	if !(trimmedVulnType == "os" || trimmedVulnType == "library") {
		return ""
	}
	return trimmedVulnType
}

func (c Config) GetSupportedConfigAuditKinds() []string {
	val, ok := c.Data[keyTunnelSupportedConfigAuditKinds]
	if !ok {
		return utils.MapKinds(strings.Split(SupportedConfigAuditKinds, ","))
	}
	return utils.MapKinds(strings.Split(val, ","))
}

func (c Config) IgnoreFileExists() bool {
	_, ok := c.Data[keyTunnelIgnoreFile]
	return ok
}

func (c Config) FindIgnorePolicyKey(workload client.Object) string {
	keysByPrecedence := []string{
		keyTunnelIgnorePolicy + "." + workload.GetNamespace() + "." + workload.GetName(),
		keyTunnelIgnorePolicy + "." + workload.GetNamespace(),
		keyTunnelIgnorePolicy,
	}
	for _, key := range keysByPrecedence {
		for key2 := range c.Data {
			if key2 == keyTunnelIgnorePolicy || strings.HasPrefix(key2, keyTunnelIgnorePolicy) {
				tempKey := key2
				if key2 != keyTunnelIgnorePolicy {
					// replace dot with astrix for regex matching
					tempKey = fmt.Sprintf("%s%s", keyTunnelIgnorePolicy, strings.ReplaceAll(tempKey[len(keyTunnelIgnorePolicy):], ".", "*"))
				}
				matched, err := filepath.Match(tempKey, key)
				if err == nil && matched {
					return key2
				}
			}
		}
	}
	return ""
}

func (c Config) GenerateIgnoreFileVolumeIfAvailable(tunnelConfigName string) (*corev1.Volume, *corev1.VolumeMount) {
	if !c.IgnoreFileExists() {
		return nil, nil
	}
	volume := corev1.Volume{
		Name: ignoreFileVolumeName,
		VolumeSource: corev1.VolumeSource{
			ConfigMap: &corev1.ConfigMapVolumeSource{
				LocalObjectReference: corev1.LocalObjectReference{
					Name: tunnelConfigName,
				},
				Items: []corev1.KeyToPath{
					{
						Key:  keyTunnelIgnoreFile,
						Path: ignoreFileName,
					},
				},
			},
		},
	}
	volumeMount := corev1.VolumeMount{
		Name:      ignoreFileVolumeName,
		MountPath: ignoreFileMountPath,
		SubPath:   ignoreFileName,
	}
	return &volume, &volumeMount
}

func (c Config) GenerateSslCertDirVolumeIfAvailable(tunnelConfigName string) (*corev1.Volume, *corev1.VolumeMount) {
	var sslCertDirHost string
	if sslCertDirHost = c.GetSslCertDir(); len(sslCertDirHost) == 0 {
		return nil, nil
	}
	volume := corev1.Volume{
		Name: sslCertDirVolumeName,
		VolumeSource: corev1.VolumeSource{
			HostPath: &corev1.HostPathVolumeSource{
				Path: sslCertDirHost,
			},
		},
	}
	volumeMount := corev1.VolumeMount{
		Name:      sslCertDirVolumeName,
		MountPath: SslCertDir,
		ReadOnly:  true,
	}
	return &volume, &volumeMount
}

func (c Config) GenerateIgnorePolicyVolumeIfAvailable(tunnelConfigName string, workload client.Object) (*corev1.Volume, *corev1.VolumeMount) {
	ignorePolicyKey := c.FindIgnorePolicyKey(workload)
	if ignorePolicyKey == "" {
		return nil, nil
	}
	volume := corev1.Volume{
		Name: ignorePolicyVolumeName,
		VolumeSource: corev1.VolumeSource{
			ConfigMap: &corev1.ConfigMapVolumeSource{
				LocalObjectReference: corev1.LocalObjectReference{
					Name: tunnelConfigName,
				},
				Items: []corev1.KeyToPath{
					{
						Key:  c.FindIgnorePolicyKey(workload),
						Path: ignorePolicyName,
					},
				},
			},
		},
	}
	volumeMounts := corev1.VolumeMount{
		Name:      ignorePolicyVolumeName,
		MountPath: ignorePolicyMountPath,
		SubPath:   ignorePolicyName,
	}
	return &volume, &volumeMounts
}

func (c Config) IgnoreUnfixed() bool {
	_, ok := c.Data[keyTunnelIgnoreUnfixed]
	return ok
}

func (c Config) OfflineScan() bool {
	_, ok := c.Data[keyTunnelOfflineScan]
	return ok
}

func (c Config) GetInsecureRegistries() map[string]bool {
	insecureRegistries := make(map[string]bool)
	for key, val := range c.Data {
		if strings.HasPrefix(key, keyTunnelInsecureRegistryPrefix) {
			insecureRegistries[val] = true
		}
	}

	return insecureRegistries
}

func (c Config) GetNonSSLRegistries() map[string]bool {
	nonSSLRegistries := make(map[string]bool)
	for key, val := range c.Data {
		if strings.HasPrefix(key, keyTunnelNonSslRegistryPrefix) {
			nonSSLRegistries[val] = true
		}
	}

	return nonSSLRegistries
}

func (c Config) GetMirrors() map[string]string {
	res := make(map[string]string)
	for registryKey, mirror := range c.Data {
		if !strings.HasPrefix(registryKey, keyTunnelMirrorPrefix) {
			continue
		}
		res[strings.TrimPrefix(registryKey, keyTunnelMirrorPrefix)] = mirror
	}
	return res
}

// GetResourceRequirements creates ResourceRequirements from the Config.
func (c Config) GetResourceRequirements() (corev1.ResourceRequirements, error) {
	requirements := corev1.ResourceRequirements{
		Requests: corev1.ResourceList{},
		Limits:   corev1.ResourceList{},
	}

	err := c.setResourceLimit(keyResourcesRequestsCPU, &requirements.Requests, corev1.ResourceCPU)
	if err != nil {
		return requirements, err
	}

	err = c.setResourceLimit(keyResourcesRequestsMemory, &requirements.Requests, corev1.ResourceMemory)
	if err != nil {
		return requirements, err
	}

	err = c.setResourceLimit(keyResourcesRequestEphemeralStorage, &requirements.Requests, corev1.ResourceEphemeralStorage)
	if err != nil {
		return requirements, err
	}

	err = c.setResourceLimit(keyResourcesLimitsCPU, &requirements.Limits, corev1.ResourceCPU)
	if err != nil {
		return requirements, err
	}

	err = c.setResourceLimit(keyResourcesLimitsMemory, &requirements.Limits, corev1.ResourceMemory)
	if err != nil {
		return requirements, err
	}

	err = c.setResourceLimit(keyResourcesLimitEphemeralStorage, &requirements.Limits, corev1.ResourceEphemeralStorage)
	if err != nil {
		return requirements, err
	}

	return requirements, nil
}

func (c Config) setResourceLimit(configKey string, k8sResourceList *corev1.ResourceList, k8sResourceName corev1.ResourceName) error {
	if value, found := c.Data[configKey]; found {
		quantity, err := resource.ParseQuantity(value)
		if err != nil {
			return fmt.Errorf("parsing resource definition %s: %s %w", configKey, value, err)
		}

		(*k8sResourceList)[k8sResourceName] = quantity
	}
	return nil
}

func (c Config) GetDBRepository() (string, error) {
	return c.GetRequiredData(keyTunnelDBRepository)
}

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
	return &plugin{
		clock:          clock,
		idGenerator:    idGenerator,
		objectResolver: objectResolver,
	}
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
			keyTunnelImageTag:                  "0.44.1",
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

func (p *plugin) GetScanJobSpec(ctx tunneloperator.PluginContext, workload client.Object, credentials map[string]docker.Auth, securityContext *corev1.SecurityContext) (corev1.PodSpec, []*corev1.Secret, error) {
	config, err := p.newConfigFrom(ctx)
	if err != nil {
		return corev1.PodSpec{}, nil, err
	}

	mode, err := config.GetMode()
	if err != nil {
		return corev1.PodSpec{}, nil, err
	}
	command, err := config.GetCommand()
	if err != nil {
		return corev1.PodSpec{}, nil, err
	}

	var podSpec corev1.PodSpec
	var secrets []*corev1.Secret
	if command == Image {
		switch mode {
		case Standalone:
			podSpec, secrets, err = p.getPodSpecForStandaloneMode(ctx, config, workload, credentials, securityContext)
		case ClientServer:
			podSpec, secrets, err = p.getPodSpecForClientServerMode(ctx, config, workload, credentials, securityContext)
		default:
			return corev1.PodSpec{}, nil, fmt.Errorf("unrecognized tunnel mode %q for command %q", mode, command)
		}
	}
	if command == Filesystem || command == Rootfs {
		switch mode {
		case Standalone:
			podSpec, secrets, err = p.getPodSpecForStandaloneFSMode(ctx, command, config, workload, securityContext)
		case ClientServer:
			podSpec, secrets, err = p.getPodSpecForClientServerFSMode(ctx, command, config, workload, securityContext)
		default:
			return corev1.PodSpec{}, nil, fmt.Errorf("unrecognized tunnel mode %q for command %q", mode, command)
		}
	}
	// add image pull secret to be used when pulling tunnel image fom private registry
	podSpec.ImagePullSecrets = config.GetImagePullSecret()
	return podSpec, secrets, err
}

func (p *plugin) newSecretWithAggregateImagePullCredentials(obj client.Object, containerImages kube.ContainerImages, credentials map[string]docker.Auth) *corev1.Secret {
	secretData := kube.AggregateImagePullSecretsData(containerImages, credentials)

	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name: vulnerabilityreport.RegistryCredentialsSecretName(obj),
		},
		Data: secretData,
	}
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

// In the Standalone mode there is the init container responsible for
// downloading the latest Tunnel DB file from GitHub and storing it to the
// emptyDir volume shared with main containers. In other words, the init
// container runs the following Tunnel command:
//
//	tunnel --cache-dir /tmp/tunnel/.cache image --download-db-only
//
// The number of main containers correspond to the number of containers
// defined for the scanned workload. Each container runs the Tunnel image scan
// command and skips the database download:
//
//	tunnel --cache-dir /tmp/tunnel/.cache image --skip-update \
//	  --format json <container image>
func (p *plugin) getPodSpecForStandaloneMode(ctx tunneloperator.PluginContext, config Config, workload client.Object, credentials map[string]docker.Auth, securityContext *corev1.SecurityContext) (corev1.PodSpec, []*corev1.Secret, error) {
	var secret *corev1.Secret
	var secrets []*corev1.Secret
	var containersSpec []corev1.Container

	spec, err := kube.GetPodSpec(workload)
	if err != nil {
		return corev1.PodSpec{}, nil, err
	}

	for _, c := range getContainers(spec) {
		optionalMirroredImage, err := GetMirroredImage(c.Image, config.GetMirrors())
		if err != nil {
			return corev1.PodSpec{}, nil, err
		}
		c.Image = optionalMirroredImage
		containersSpec = append(containersSpec, c)
	}

	containerImages := kube.GetContainerImagesFromContainersList(containersSpec)
	containersCredentials, err := kube.MapContainerNamesToDockerAuths(containerImages, credentials)
	if err != nil {
		return corev1.PodSpec{}, nil, err
	}
	if len(containersCredentials) > 0 {
		secret = p.newSecretWithAggregateImagePullCredentials(workload, containerImages, containersCredentials)
		secrets = append(secrets, secret)
	}

	tunnelImageRef, err := config.GetImageRef()
	if err != nil {
		return corev1.PodSpec{}, nil, err
	}

	tunnelConfigName := tunneloperator.GetPluginConfigMapName(Plugin)

	dbRepository, err := config.GetDBRepository()
	if err != nil {
		return corev1.PodSpec{}, nil, err
	}

	requirements, err := config.GetResourceRequirements()
	if err != nil {
		return corev1.PodSpec{}, nil, err
	}

	initContainer := corev1.Container{
		Name:                     p.idGenerator.GenerateID(),
		Image:                    tunnelImageRef,
		ImagePullPolicy:          corev1.PullIfNotPresent,
		TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
		Env:                      p.initContainerEnvVar(tunnelConfigName, config),
		Command: []string{
			"tunnel",
		},
		Args: []string{
			"--cache-dir",
			"/tmp/tunnel/.cache",
			"image",
			"--download-db-only",
			"--db-repository",
			dbRepository,
		},
		Resources:       requirements,
		SecurityContext: securityContext,
		VolumeMounts: []corev1.VolumeMount{
			{
				Name:      tmpVolumeName,
				MountPath: "/tmp",
				ReadOnly:  false,
			},
		},
	}

	var containers []corev1.Container

	volumeMounts := []corev1.VolumeMount{
		{
			Name:      tmpVolumeName,
			ReadOnly:  false,
			MountPath: "/tmp",
		},
	}
	volumes := []corev1.Volume{
		{
			Name: tmpVolumeName,
			VolumeSource: corev1.VolumeSource{
				EmptyDir: &corev1.EmptyDirVolumeSource{
					Medium: corev1.StorageMediumDefault,
				},
			},
		},
	}
	volumeMounts = append(volumeMounts, getScanResultVolumeMount())
	volumes = append(volumes, getScanResultVolume())

	if volume, volumeMount := config.GenerateIgnoreFileVolumeIfAvailable(tunnelConfigName); volume != nil && volumeMount != nil {
		volumes = append(volumes, *volume)
		volumeMounts = append(volumeMounts, *volumeMount)
	}
	if volume, volumeMount := config.GenerateIgnorePolicyVolumeIfAvailable(tunnelConfigName, workload); volume != nil && volumeMount != nil {
		volumes = append(volumes, *volume)
		volumeMounts = append(volumeMounts, *volumeMount)
	}
	if volume, volumeMount := config.GenerateSslCertDirVolumeIfAvailable(tunnelConfigName); volume != nil && volumeMount != nil {
		volumes = append(volumes, *volume)
		volumeMounts = append(volumeMounts, *volumeMount)
	}

	for _, c := range containersSpec {
		env := []corev1.EnvVar{
			constructEnvVarSourceFromConfigMap("TUNNEL_SEVERITY", tunnelConfigName, KeyTunnelSeverity),
			constructEnvVarSourceFromConfigMap("TUNNEL_IGNORE_UNFIXED", tunnelConfigName, keyTunnelIgnoreUnfixed),
			constructEnvVarSourceFromConfigMap("TUNNEL_OFFLINE_SCAN", tunnelConfigName, keyTunnelOfflineScan),
			constructEnvVarSourceFromConfigMap("TUNNEL_JAVA_DB_REPOSITORY", tunnelConfigName, keyTunnelJavaDBRepository),
			constructEnvVarSourceFromConfigMap("TUNNEL_TIMEOUT", tunnelConfigName, keyTunnelTimeout),
			ConfigWorkloadAnnotationEnvVars(workload, SkipFilesAnnotation, "TUNNEL_SKIP_FILES", tunnelConfigName, keyTunnelSkipFiles),
			ConfigWorkloadAnnotationEnvVars(workload, SkipDirsAnnotation, "TUNNEL_SKIP_DIRS", tunnelConfigName, keyTunnelSkipDirs),
			constructEnvVarSourceFromConfigMap("HTTP_PROXY", tunnelConfigName, keyTunnelHTTPProxy),
			constructEnvVarSourceFromConfigMap("HTTPS_PROXY", tunnelConfigName, keyTunnelHTTPSProxy),
			constructEnvVarSourceFromConfigMap("NO_PROXY", tunnelConfigName, keyTunnelNoProxy),
		}

		if len(config.GetSslCertDir()) > 0 {
			env = append(env, corev1.EnvVar{
				Name:  "SSL_CERT_DIR",
				Value: SslCertDir,
			})
		}
		if config.IgnoreFileExists() {
			env = append(env, corev1.EnvVar{
				Name:  "TUNNEL_IGNOREFILE",
				Value: ignoreFileMountPath,
			})
		}
		if config.FindIgnorePolicyKey(workload) != "" {
			env = append(env, corev1.EnvVar{
				Name:  "TUNNEL_IGNORE_POLICY",
				Value: ignorePolicyMountPath,
			})
		}

		region := CheckAwsEcrPrivateRegistry(c.Image)
		if region != "" {
			env = append(env, corev1.EnvVar{
				Name:  "AWS_REGION",
				Value: region,
			})
		}
		if config.GetDBRepositoryInsecure() {
			env = append(env, corev1.EnvVar{
				Name:  "TUNNEL_INSECURE",
				Value: "true",
			})
		}

		if _, ok := containersCredentials[c.Name]; ok && secret != nil {
			registryUsernameKey := fmt.Sprintf("%s.username", c.Name)
			registryPasswordKey := fmt.Sprintf("%s.password", c.Name)

			env = append(env, corev1.EnvVar{
				Name: "TUNNEL_USERNAME",
				ValueFrom: &corev1.EnvVarSource{
					SecretKeyRef: &corev1.SecretKeySelector{
						LocalObjectReference: corev1.LocalObjectReference{
							Name: secret.Name,
						},
						Key: registryUsernameKey,
					},
				},
			}, corev1.EnvVar{
				Name: "TUNNEL_PASSWORD",
				ValueFrom: &corev1.EnvVarSource{
					SecretKeyRef: &corev1.SecretKeySelector{
						LocalObjectReference: corev1.LocalObjectReference{
							Name: secret.Name,
						},
						Key: registryPasswordKey,
					},
				},
			})
		}

		env, err = p.appendTunnelInsecureEnv(config, c.Image, env)
		if err != nil {
			return corev1.PodSpec{}, nil, err
		}

		env, err = p.appendTunnelNonSSLEnv(config, c.Image, env)
		if err != nil {
			return corev1.PodSpec{}, nil, err
		}

		resourceRequirements, err := config.GetResourceRequirements()
		if err != nil {
			return corev1.PodSpec{}, nil, err
		}

		imageRef, err := containerimage.ParseReference(c.Image)
		if err != nil {
			return corev1.PodSpec{}, nil, err
		}
		resultFileName := getUniqueScanResultFileName(c.Name)
		cmd, args := p.getCommandAndArgs(ctx, Standalone, imageRef.String(), "", resultFileName)
		containers = append(containers, corev1.Container{
			Name:                     c.Name,
			Image:                    tunnelImageRef,
			ImagePullPolicy:          corev1.PullIfNotPresent,
			TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
			Env:                      env,
			Command:                  cmd,
			Args:                     args,
			Resources:                resourceRequirements,
			SecurityContext:          securityContext,
			VolumeMounts:             volumeMounts,
		})
	}

	return corev1.PodSpec{
		Affinity:                     tunneloperator.LinuxNodeAffinity(),
		RestartPolicy:                corev1.RestartPolicyNever,
		ServiceAccountName:           ctx.GetServiceAccountName(),
		AutomountServiceAccountToken: pointer.Bool(getAutomountServiceAccountToken(ctx)),
		Volumes:                      volumes,
		InitContainers:               []corev1.Container{initContainer},
		Containers:                   containers,
		SecurityContext:              &corev1.PodSecurityContext{},
	}, secrets, nil
}

func (p *plugin) initContainerEnvVar(tunnelConfigName string, config Config) []corev1.EnvVar {
	envs := []corev1.EnvVar{
		constructEnvVarSourceFromConfigMap("HTTP_PROXY", tunnelConfigName, keyTunnelHTTPProxy),
		constructEnvVarSourceFromConfigMap("HTTPS_PROXY", tunnelConfigName, keyTunnelHTTPSProxy),
		constructEnvVarSourceFromConfigMap("NO_PROXY", tunnelConfigName, keyTunnelNoProxy),
		constructEnvVarSourceFromSecret("GITHUB_TOKEN", tunnelConfigName, keyTunnelGitHubToken),
	}

	if config.GetDBRepositoryInsecure() {
		envs = append(envs, corev1.EnvVar{
			Name:  "TUNNEL_INSECURE",
			Value: "true",
		})
	}
	return envs
}

// In the ClientServer mode the number of containers of the pod created by the
// scan job equals the number of containers defined for the scanned workload.
// Each container runs Tunnel image scan command and refers to Tunnel server URL
// returned by Config.GetServerURL:
//
//	tunnel image --server <server URL> \
//	  --format json <container image>
func (p *plugin) getPodSpecForClientServerMode(ctx tunneloperator.PluginContext, config Config, workload client.Object, credentials map[string]docker.Auth, securityContext *corev1.SecurityContext) (corev1.PodSpec, []*corev1.Secret, error) {
	var secret *corev1.Secret
	var secrets []*corev1.Secret
	var containersSpec []corev1.Container
	spec, err := kube.GetPodSpec(workload)
	if err != nil {
		return corev1.PodSpec{}, nil, err
	}

	tunnelImageRef, err := config.GetImageRef()
	if err != nil {
		return corev1.PodSpec{}, nil, err
	}

	tunnelServerURL, err := config.GetServerURL()
	if err != nil {
		return corev1.PodSpec{}, nil, err
	}

	for _, c := range getContainers(spec) {
		optionalMirroredImage, err := GetMirroredImage(c.Image, config.GetMirrors())
		if err != nil {
			return corev1.PodSpec{}, nil, err
		}
		c.Image = optionalMirroredImage
		containersSpec = append(containersSpec, c)
	}

	containerImages := kube.GetContainerImagesFromContainersList(containersSpec)
	containersCredentials, err := kube.MapContainerNamesToDockerAuths(containerImages, credentials)
	if err != nil {
		return corev1.PodSpec{}, nil, err
	}
	if len(containersCredentials) > 0 {
		secret = p.newSecretWithAggregateImagePullCredentials(workload, containerImages, containersCredentials)
		secrets = append(secrets, secret)
	}

	var containers []corev1.Container

	tunnelConfigName := tunneloperator.GetPluginConfigMapName(Plugin)
	// add tmp volume mount
	volumeMounts := []corev1.VolumeMount{
		{
			Name:      tmpVolumeName,
			ReadOnly:  false,
			MountPath: "/tmp",
		},
	}

	// add tmp volume
	volumes := []corev1.Volume{
		{
			Name: tmpVolumeName,
			VolumeSource: corev1.VolumeSource{
				EmptyDir: &corev1.EmptyDirVolumeSource{
					Medium: corev1.StorageMediumDefault,
				},
			},
		},
	}

	volumeMounts = append(volumeMounts, getScanResultVolumeMount())
	volumes = append(volumes, getScanResultVolume())

	if volume, volumeMount := config.GenerateIgnoreFileVolumeIfAvailable(tunnelConfigName); volume != nil && volumeMount != nil {
		volumes = append(volumes, *volume)
		volumeMounts = append(volumeMounts, *volumeMount)
	}
	if volume, volumeMount := config.GenerateIgnorePolicyVolumeIfAvailable(tunnelConfigName, workload); volume != nil && volumeMount != nil {
		volumes = append(volumes, *volume)
		volumeMounts = append(volumeMounts, *volumeMount)
	}

	if volume, volumeMount := config.GenerateSslCertDirVolumeIfAvailable(tunnelConfigName); volume != nil && volumeMount != nil {
		volumes = append(volumes, *volume)
		volumeMounts = append(volumeMounts, *volumeMount)
	}

	for _, container := range containersSpec {
		env := []corev1.EnvVar{
			constructEnvVarSourceFromConfigMap("HTTP_PROXY", tunnelConfigName, keyTunnelHTTPProxy),
			constructEnvVarSourceFromConfigMap("HTTPS_PROXY", tunnelConfigName, keyTunnelHTTPSProxy),
			constructEnvVarSourceFromConfigMap("NO_PROXY", tunnelConfigName, keyTunnelNoProxy),
			constructEnvVarSourceFromConfigMap("TUNNEL_SEVERITY", tunnelConfigName, KeyTunnelSeverity),
			constructEnvVarSourceFromConfigMap("TUNNEL_IGNORE_UNFIXED", tunnelConfigName, keyTunnelIgnoreUnfixed),
			constructEnvVarSourceFromConfigMap("TUNNEL_OFFLINE_SCAN", tunnelConfigName, keyTunnelOfflineScan),
			constructEnvVarSourceFromConfigMap("TUNNEL_JAVA_DB_REPOSITORY", tunnelConfigName, keyTunnelJavaDBRepository),
			constructEnvVarSourceFromConfigMap("TUNNEL_TIMEOUT", tunnelConfigName, keyTunnelTimeout),
			ConfigWorkloadAnnotationEnvVars(workload, SkipFilesAnnotation, "TUNNEL_SKIP_FILES", tunnelConfigName, keyTunnelSkipFiles),
			ConfigWorkloadAnnotationEnvVars(workload, SkipDirsAnnotation, "TUNNEL_SKIP_DIRS", tunnelConfigName, keyTunnelSkipDirs),
			constructEnvVarSourceFromConfigMap("TUNNEL_TOKEN_HEADER", tunnelConfigName, keyTunnelServerTokenHeader),
			constructEnvVarSourceFromSecret("TUNNEL_TOKEN", tunnelConfigName, keyTunnelServerToken),
			constructEnvVarSourceFromSecret("TUNNEL_CUSTOM_HEADERS", tunnelConfigName, keyTunnelServerCustomHeaders),
		}
		if len(config.GetSslCertDir()) > 0 {
			env = append(env, corev1.EnvVar{
				Name:  "SSL_CERT_DIR",
				Value: SslCertDir,
			})
		}
		if config.IgnoreFileExists() {
			env = append(env, corev1.EnvVar{
				Name:  "TUNNEL_IGNOREFILE",
				Value: ignoreFileMountPath,
			})
		}
		if config.FindIgnorePolicyKey(workload) != "" {
			env = append(env, corev1.EnvVar{
				Name:  "TUNNEL_IGNORE_POLICY",
				Value: ignorePolicyMountPath,
			})
		}

		if _, ok := containersCredentials[container.Name]; ok && secret != nil {
			registryUsernameKey := fmt.Sprintf("%s.username", container.Name)
			registryPasswordKey := fmt.Sprintf("%s.password", container.Name)

			env = append(env, corev1.EnvVar{
				Name: "TUNNEL_USERNAME",
				ValueFrom: &corev1.EnvVarSource{
					SecretKeyRef: &corev1.SecretKeySelector{
						LocalObjectReference: corev1.LocalObjectReference{
							Name: secret.Name,
						},
						Key: registryUsernameKey,
					},
				},
			}, corev1.EnvVar{
				Name: "TUNNEL_PASSWORD",
				ValueFrom: &corev1.EnvVarSource{
					SecretKeyRef: &corev1.SecretKeySelector{
						LocalObjectReference: corev1.LocalObjectReference{
							Name: secret.Name,
						},
						Key: registryPasswordKey,
					},
				},
			})
		}

		env, err = p.appendTunnelInsecureEnv(config, container.Image, env)
		if err != nil {
			return corev1.PodSpec{}, nil, err
		}

		env, err = p.appendTunnelNonSSLEnv(config, container.Image, env)
		if err != nil {
			return corev1.PodSpec{}, nil, err
		}

		if config.GetServerInsecure() {
			env = append(env, corev1.EnvVar{
				Name:  "TUNNEL_INSECURE",
				Value: "true",
			})
		}

		requirements, err := config.GetResourceRequirements()
		if err != nil {
			return corev1.PodSpec{}, nil, err
		}

		encodedTunnelServerURL, err := url.Parse(tunnelServerURL)
		if err != nil {
			return corev1.PodSpec{}, nil, err
		}
		imageRef, err := containerimage.ParseReference(container.Image)
		if err != nil {
			return corev1.PodSpec{}, nil, err
		}
		resultFileName := getUniqueScanResultFileName(container.Name)
		cmd, args := p.getCommandAndArgs(ctx, ClientServer, imageRef.String(), encodedTunnelServerURL.String(), resultFileName)
		containers = append(containers, corev1.Container{
			Name:                     container.Name,
			Image:                    tunnelImageRef,
			ImagePullPolicy:          corev1.PullIfNotPresent,
			TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
			Env:                      env,
			Command:                  cmd,
			Args:                     args,
			Resources:                requirements,
			SecurityContext:          securityContext,
			VolumeMounts:             volumeMounts,
		})
	}

	return corev1.PodSpec{
		Affinity:                     tunneloperator.LinuxNodeAffinity(),
		RestartPolicy:                corev1.RestartPolicyNever,
		ServiceAccountName:           ctx.GetServiceAccountName(),
		AutomountServiceAccountToken: pointer.Bool(getAutomountServiceAccountToken(ctx)),
		Containers:                   containers,
		Volumes:                      volumes,
	}, secrets, nil
}

func (p *plugin) getCommandAndArgs(ctx tunneloperator.PluginContext, mode Mode, imageRef string, tunnelServerURL string, resultFileName string) ([]string, []string) {
	command := []string{
		"tunnel",
	}
	tunnelConfig := ctx.GetTunnelOperatorConfig()
	compressLogs := tunnelConfig.CompressLogs()
	c, err := p.getConfig(ctx)
	if err != nil {
		return []string{}, []string{}
	}
	slow := Slow(c)
	skipJavaDBUpdate := SkipJavaDBUpdate(c)
	vulnTypeArgs := p.vulnTypeFilter(ctx)
	scanners := Scanners(c)
	var vulnTypeFlag string
	if len(vulnTypeArgs) == 2 {
		vulnTypeFlag = fmt.Sprintf("%s %s ", vulnTypeArgs[0], vulnTypeArgs[1])
	}
	imcs := p.imageConfigSecretScanner(tunnelConfig)
	var imageconfigSecretScannerFlag string
	if len(imcs) == 2 {
		imageconfigSecretScannerFlag = fmt.Sprintf("%s %s ", imcs[0], imcs[1])
	}
	var skipUpdate string
	if mode == ClientServer {
		if c.GetClientServerSkipUpdate() {
			skipUpdate = SkipDBUpdate(c)
		}
		if !compressLogs {
			args := []string{
				"--cache-dir",
				"/tmp/tunnel/.cache",
				"--quiet",
				"image",
				scanners,
				getSecurityChecks(ctx),
				skipUpdate,
				skipJavaDBUpdate,
				"--format",
				"json",
				"--server",
				tunnelServerURL,
				imageRef,
			}
			if len(slow) > 0 {
				args = append(args, slow)
			}
			if len(vulnTypeArgs) > 0 {
				args = append(args, vulnTypeArgs...)
			}
			if len(imcs) > 0 {
				args = append(args, imcs...)
			}
			pkgList := getPkgList(ctx)
			if len(pkgList) > 0 {
				args = append(args, pkgList)
			}
			return command, args
		}
		return []string{"/bin/sh"}, []string{"-c", fmt.Sprintf(`tunnel image %s '%s' %s %s %s %s %s %s --cache-dir /tmp/tunnel/.cache --quiet %s --format json --server '%s' > /tmp/scan/%s &&  bzip2 -c /tmp/scan/%s | base64`, slow, imageRef, scanners, getSecurityChecks(ctx), imageconfigSecretScannerFlag, vulnTypeFlag, skipUpdate, skipJavaDBUpdate, getPkgList(ctx), tunnelServerURL, resultFileName, resultFileName)}
	}
	skipUpdate = SkipDBUpdate(c)
	if !compressLogs {
		args := []string{
			"--cache-dir",
			"/tmp/tunnel/.cache",
			"--quiet",
			"image",
			scanners,
			getSecurityChecks(ctx),
			skipUpdate,
			skipJavaDBUpdate,
			"--format",
			"json",
			imageRef,
		}
		if len(slow) > 0 {
			args = append(args, slow)
		}
		if len(vulnTypeArgs) > 0 {
			args = append(args, vulnTypeArgs...)
		}
		if len(imcs) > 0 {
			args = append(args, imcs...)
		}
		pkgList := getPkgList(ctx)
		if len(pkgList) > 0 {
			args = append(args, pkgList)
		}
		return command, args
	}
	return []string{"/bin/sh"}, []string{"-c", fmt.Sprintf(`tunnel image %s '%s' %s %s %s %s %s %s --cache-dir /tmp/tunnel/.cache --quiet %s --format json > /tmp/scan/%s &&  bzip2 -c /tmp/scan/%s | base64`, slow, imageRef, scanners, getSecurityChecks(ctx), imageconfigSecretScannerFlag, vulnTypeFlag, skipUpdate, skipJavaDBUpdate, getPkgList(ctx), resultFileName, resultFileName)}
}

func (p *plugin) vulnTypeFilter(ctx tunneloperator.PluginContext) []string {
	config, err := p.newConfigFrom(ctx)
	if err != nil {
		return []string{}
	}
	vulnType := config.GetVulnType()
	if len(vulnType) == 0 {
		return []string{}
	}
	return []string{"--vuln-type", vulnType}
}

func (p *plugin) imageConfigSecretScanner(tc tunneloperator.ConfigData) []string {

	if tc.ExposedSecretsScannerEnabled() {
		return []string{"--image-config-scanners", "secret"}
	}
	return []string{}
}

func getAutomountServiceAccountToken(ctx tunneloperator.PluginContext) bool {
	return ctx.GetTunnelOperatorConfig().GetScanJobAutomountServiceAccountToken()
}
func getUniqueScanResultFileName(name string) string {
	return fmt.Sprintf("result_%s.json", name)
}

func getScanResultVolume() corev1.Volume {
	return corev1.Volume{
		Name: scanResultVolumeName,
		VolumeSource: corev1.VolumeSource{
			EmptyDir: &corev1.EmptyDirVolumeSource{
				Medium: corev1.StorageMediumDefault,
			},
		},
	}
}

func getScanResultVolumeMount() corev1.VolumeMount {
	return corev1.VolumeMount{
		Name:      scanResultVolumeName,
		ReadOnly:  false,
		MountPath: "/tmp/scan",
	}
}

// FileSystem scan option with standalone mode.
// The only difference is that instead of scanning the resource by name,
// We scanning the resource place on a specific file system location using the following command.
//
//	tunnel --quiet fs  --format json --ignore-unfixed  file/system/location
func (p *plugin) getPodSpecForStandaloneFSMode(ctx tunneloperator.PluginContext, command Command, config Config,
	workload client.Object, securityContext *corev1.SecurityContext) (corev1.PodSpec, []*corev1.Secret, error) {
	var secrets []*corev1.Secret
	spec, err := kube.GetPodSpec(workload)
	if err != nil {
		return corev1.PodSpec{}, nil, err
	}
	pullPolicy := corev1.PullIfNotPresent
	// nodeName to schedule scan job explicitly on specific node.
	var nodeName string
	if !ctx.GetTunnelOperatorConfig().VulnerabilityScanJobsInSameNamespace() {
		// get nodeName from running pods.
		nodeName, err = p.objectResolver.GetNodeName(context.Background(), workload)
		if err != nil {
			return corev1.PodSpec{}, nil, fmt.Errorf("failed resolving node name for workload %q: %w",
				workload.GetNamespace()+"/"+workload.GetName(), err)
		}
		pullPolicy = corev1.PullNever
	}

	tunnelImageRef, err := config.GetImageRef()
	if err != nil {
		return corev1.PodSpec{}, nil, err
	}

	tunnelConfigName := tunneloperator.GetPluginConfigMapName(Plugin)

	dbRepository, err := config.GetDBRepository()
	if err != nil {
		return corev1.PodSpec{}, nil, err
	}

	requirements, err := config.GetResourceRequirements()
	if err != nil {
		return corev1.PodSpec{}, nil, err
	}

	volumeMounts := []corev1.VolumeMount{
		{
			Name:      FsSharedVolumeName,
			ReadOnly:  false,
			MountPath: "/var/tunneloperator",
		},
		{
			Name:      tmpVolumeName,
			MountPath: "/tmp",
			ReadOnly:  false,
		},
	}

	initContainerCopyBinary := corev1.Container{
		Name:                     p.idGenerator.GenerateID(),
		Image:                    tunnelImageRef,
		ImagePullPolicy:          corev1.PullIfNotPresent,
		TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
		Command: []string{
			"cp",
			"-v",
			"/usr/local/bin/tunnel",
			SharedVolumeLocationOfTunnel,
		},
		Resources:       requirements,
		SecurityContext: securityContext,
		VolumeMounts:    volumeMounts,
	}

	initContainerDB := corev1.Container{
		Name:                     p.idGenerator.GenerateID(),
		Image:                    tunnelImageRef,
		ImagePullPolicy:          corev1.PullIfNotPresent,
		TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
		Env:                      p.initContainerFSEnvVar(tunnelConfigName, config),
		Command: []string{
			"tunnel",
		},
		Args: []string{
			"--cache-dir",
			"/var/tunneloperator/tunnel-db",
			"image",
			"--download-db-only",
			"--db-repository",
			dbRepository,
		},
		Resources:       requirements,
		SecurityContext: securityContext,
		VolumeMounts:    volumeMounts,
	}

	var containers []corev1.Container

	volumes := []corev1.Volume{
		{
			Name: FsSharedVolumeName,
			VolumeSource: corev1.VolumeSource{
				EmptyDir: &corev1.EmptyDirVolumeSource{
					Medium: corev1.StorageMediumDefault,
				},
			},
		},
		{
			Name: tmpVolumeName,
			VolumeSource: corev1.VolumeSource{
				EmptyDir: &corev1.EmptyDirVolumeSource{
					Medium: corev1.StorageMediumDefault,
				},
			},
		},
	}

	volumeMounts = append(volumeMounts, getScanResultVolumeMount())
	volumes = append(volumes, getScanResultVolume())

	if volume, volumeMount := config.GenerateIgnoreFileVolumeIfAvailable(tunnelConfigName); volume != nil && volumeMount != nil {
		volumes = append(volumes, *volume)
		volumeMounts = append(volumeMounts, *volumeMount)
	}
	if volume, volumeMount := config.GenerateIgnorePolicyVolumeIfAvailable(tunnelConfigName, workload); volume != nil && volumeMount != nil {
		volumes = append(volumes, *volume)
		volumeMounts = append(volumeMounts, *volumeMount)
	}
	if volume, volumeMount := config.GenerateSslCertDirVolumeIfAvailable(tunnelConfigName); volume != nil && volumeMount != nil {
		volumes = append(volumes, *volume)
		volumeMounts = append(volumeMounts, *volumeMount)
	}

	for _, c := range getContainers(spec) {
		env := []corev1.EnvVar{
			constructEnvVarSourceFromConfigMap("TUNNEL_SEVERITY", tunnelConfigName, KeyTunnelSeverity),
			ConfigWorkloadAnnotationEnvVars(workload, SkipFilesAnnotation, "TUNNEL_SKIP_FILES", tunnelConfigName, keyTunnelSkipFiles),
			ConfigWorkloadAnnotationEnvVars(workload, SkipDirsAnnotation, "TUNNEL_SKIP_DIRS", tunnelConfigName, keyTunnelSkipDirs),
			constructEnvVarSourceFromConfigMap("HTTP_PROXY", tunnelConfigName, keyTunnelHTTPProxy),
			constructEnvVarSourceFromConfigMap("HTTPS_PROXY", tunnelConfigName, keyTunnelHTTPSProxy),
			constructEnvVarSourceFromConfigMap("NO_PROXY", tunnelConfigName, keyTunnelNoProxy),
			constructEnvVarSourceFromConfigMap("TUNNEL_JAVA_DB_REPOSITORY", tunnelConfigName, keyTunnelJavaDBRepository),
		}
		if len(config.GetSslCertDir()) > 0 {
			env = append(env, corev1.EnvVar{
				Name:  "SSL_CERT_DIR",
				Value: SslCertDir,
			})
		}
		if config.IgnoreFileExists() {
			env = append(env, corev1.EnvVar{
				Name:  "TUNNEL_IGNOREFILE",
				Value: ignoreFileMountPath,
			})
		}
		if config.FindIgnorePolicyKey(workload) != "" {
			env = append(env, corev1.EnvVar{
				Name:  "TUNNEL_IGNORE_POLICY",
				Value: ignorePolicyMountPath,
			})
		}
		if config.IgnoreUnfixed() {
			env = append(env, constructEnvVarSourceFromConfigMap("TUNNEL_IGNORE_UNFIXED",
				tunnelConfigName, keyTunnelIgnoreUnfixed))
		}
		if config.GetDBRepositoryInsecure() {
			env = append(env, corev1.EnvVar{
				Name:  "TUNNEL_INSECURE",
				Value: "true",
			})
		}

		if config.OfflineScan() {
			env = append(env, constructEnvVarSourceFromConfigMap("TUNNEL_OFFLINE_SCAN",
				tunnelConfigName, keyTunnelOfflineScan))
		}

		env, err = p.appendTunnelInsecureEnv(config, c.Image, env)
		if err != nil {
			return corev1.PodSpec{}, nil, err
		}

		resourceRequirements, err := config.GetResourceRequirements()
		if err != nil {
			return corev1.PodSpec{}, nil, err
		}
		containers = append(containers, corev1.Container{
			Name:                     c.Name,
			Image:                    c.Image,
			ImagePullPolicy:          pullPolicy,
			TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
			Env:                      env,
			Command: []string{
				SharedVolumeLocationOfTunnel,
			},
			Args:            p.getFSScanningArgs(ctx, command, Standalone, ""),
			Resources:       resourceRequirements,
			SecurityContext: securityContext,
			VolumeMounts:    volumeMounts,
		})
	}

	podSpec := corev1.PodSpec{
		Affinity:                     tunneloperator.LinuxNodeAffinity(),
		RestartPolicy:                corev1.RestartPolicyNever,
		ServiceAccountName:           ctx.GetServiceAccountName(),
		AutomountServiceAccountToken: pointer.Bool(getAutomountServiceAccountToken(ctx)),
		Volumes:                      volumes,
		InitContainers:               []corev1.Container{initContainerCopyBinary, initContainerDB},
		Containers:                   containers,
		SecurityContext:              &corev1.PodSecurityContext{},
	}

	if !ctx.GetTunnelOperatorConfig().VulnerabilityScanJobsInSameNamespace() {
		// schedule scan job explicitly on specific node.
		podSpec.NodeName = nodeName
	}

	return podSpec, secrets, nil
}

// FileSystem scan option with ClientServer mode.
// The only difference is that instead of scanning the resource by name,
// We scanning the resource place on a specific file system location using the following command.
//
//	tunnel --quiet fs  --server TUNNEL_SERVER  --format json --ignore-unfixed  file/system/location
func (p *plugin) getPodSpecForClientServerFSMode(ctx tunneloperator.PluginContext, command Command, config Config,
	workload client.Object, securityContext *corev1.SecurityContext) (corev1.PodSpec, []*corev1.Secret, error) {
	var secrets []*corev1.Secret
	spec, err := kube.GetPodSpec(workload)
	if err != nil {
		return corev1.PodSpec{}, nil, err
	}
	pullPolicy := corev1.PullIfNotPresent
	// nodeName to schedule scan job explicitly on specific node.
	var nodeName string
	if !ctx.GetTunnelOperatorConfig().VulnerabilityScanJobsInSameNamespace() {
		// get nodeName from running pods.
		nodeName, err = p.objectResolver.GetNodeName(context.Background(), workload)
		if err != nil {
			return corev1.PodSpec{}, nil, fmt.Errorf("failed resolving node name for workload %q: %w",
				workload.GetNamespace()+"/"+workload.GetName(), err)
		}
		pullPolicy = corev1.PullNever
	}

	tunnelImageRef, err := config.GetImageRef()
	if err != nil {
		return corev1.PodSpec{}, nil, err
	}

	tunnelServerURL, err := config.GetServerURL()
	if err != nil {
		return corev1.PodSpec{}, nil, err
	}

	encodedTunnelServerURL, err := url.Parse(tunnelServerURL)
	if err != nil {
		return corev1.PodSpec{}, nil, err
	}

	tunnelConfigName := tunneloperator.GetPluginConfigMapName(Plugin)

	requirements, err := config.GetResourceRequirements()
	if err != nil {
		return corev1.PodSpec{}, nil, err
	}

	volumeMounts := []corev1.VolumeMount{
		{
			Name:      FsSharedVolumeName,
			ReadOnly:  false,
			MountPath: "/var/tunneloperator",
		},
		{
			Name:      tmpVolumeName,
			MountPath: "/tmp",
			ReadOnly:  false,
		},
	}

	initContainerCopyBinary := corev1.Container{
		Name:                     p.idGenerator.GenerateID(),
		Image:                    tunnelImageRef,
		ImagePullPolicy:          corev1.PullIfNotPresent,
		TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
		Command: []string{
			"cp",
			"-v",
			"/usr/local/bin/tunnel",
			SharedVolumeLocationOfTunnel,
		},
		Resources:       requirements,
		SecurityContext: securityContext,
		VolumeMounts:    volumeMounts,
	}

	var containers []corev1.Container

	volumes := []corev1.Volume{
		{
			Name: FsSharedVolumeName,
			VolumeSource: corev1.VolumeSource{
				EmptyDir: &corev1.EmptyDirVolumeSource{
					Medium: corev1.StorageMediumDefault,
				},
			},
		},
		{
			Name: tmpVolumeName,
			VolumeSource: corev1.VolumeSource{
				EmptyDir: &corev1.EmptyDirVolumeSource{
					Medium: corev1.StorageMediumDefault,
				},
			},
		},
	}
	volumeMounts = append(volumeMounts, getScanResultVolumeMount())
	volumes = append(volumes, getScanResultVolume())

	if volume, volumeMount := config.GenerateIgnoreFileVolumeIfAvailable(tunnelConfigName); volume != nil && volumeMount != nil {
		volumes = append(volumes, *volume)
		volumeMounts = append(volumeMounts, *volumeMount)
	}
	if volume, volumeMount := config.GenerateIgnorePolicyVolumeIfAvailable(tunnelConfigName, workload); volume != nil && volumeMount != nil {
		volumes = append(volumes, *volume)
		volumeMounts = append(volumeMounts, *volumeMount)
	}
	if volume, volumeMount := config.GenerateSslCertDirVolumeIfAvailable(tunnelConfigName); volume != nil && volumeMount != nil {
		volumes = append(volumes, *volume)
		volumeMounts = append(volumeMounts, *volumeMount)
	}

	for _, c := range getContainers(spec) {
		env := []corev1.EnvVar{
			constructEnvVarSourceFromConfigMap("TUNNEL_SEVERITY", tunnelConfigName, KeyTunnelSeverity),
			ConfigWorkloadAnnotationEnvVars(workload, SkipFilesAnnotation, "TUNNEL_SKIP_FILES", tunnelConfigName, keyTunnelSkipFiles),
			ConfigWorkloadAnnotationEnvVars(workload, SkipDirsAnnotation, "TUNNEL_SKIP_DIRS", tunnelConfigName, keyTunnelSkipDirs),
			constructEnvVarSourceFromConfigMap("HTTP_PROXY", tunnelConfigName, keyTunnelHTTPProxy),
			constructEnvVarSourceFromConfigMap("HTTPS_PROXY", tunnelConfigName, keyTunnelHTTPSProxy),
			constructEnvVarSourceFromConfigMap("NO_PROXY", tunnelConfigName, keyTunnelNoProxy),
			constructEnvVarSourceFromConfigMap("TUNNEL_TOKEN_HEADER", tunnelConfigName, keyTunnelServerTokenHeader),
			constructEnvVarSourceFromSecret("TUNNEL_TOKEN", tunnelConfigName, keyTunnelServerToken),
			constructEnvVarSourceFromSecret("TUNNEL_CUSTOM_HEADERS", tunnelConfigName, keyTunnelServerCustomHeaders),
			constructEnvVarSourceFromConfigMap("TUNNEL_JAVA_DB_REPOSITORY", tunnelConfigName, keyTunnelJavaDBRepository),
		}
		if len(config.GetSslCertDir()) > 0 {
			env = append(env, corev1.EnvVar{
				Name:  "SSL_CERT_DIR",
				Value: SslCertDir,
			})
		}
		if config.IgnoreFileExists() {
			env = append(env, corev1.EnvVar{
				Name:  "TUNNEL_IGNOREFILE",
				Value: ignoreFileMountPath,
			})
		}
		if config.FindIgnorePolicyKey(workload) != "" {
			env = append(env, corev1.EnvVar{
				Name:  "TUNNEL_IGNORE_POLICY",
				Value: ignorePolicyMountPath,
			})
		}
		if config.IgnoreUnfixed() {
			env = append(env, constructEnvVarSourceFromConfigMap("TUNNEL_IGNORE_UNFIXED",
				tunnelConfigName, keyTunnelIgnoreUnfixed))
		}

		if config.OfflineScan() {
			env = append(env, constructEnvVarSourceFromConfigMap("TUNNEL_OFFLINE_SCAN",
				tunnelConfigName, keyTunnelOfflineScan))
		}

		env, err = p.appendTunnelInsecureEnv(config, c.Image, env)
		if err != nil {
			return corev1.PodSpec{}, nil, err
		}

		if config.GetServerInsecure() {
			env = append(env, corev1.EnvVar{
				Name:  "TUNNEL_INSECURE",
				Value: "true",
			})
		}

		resourceRequirements, err := config.GetResourceRequirements()
		if err != nil {
			return corev1.PodSpec{}, nil, err
		}
		containers = append(containers, corev1.Container{
			Name:                     c.Name,
			Image:                    c.Image,
			ImagePullPolicy:          pullPolicy,
			TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
			Env:                      env,
			Command: []string{
				SharedVolumeLocationOfTunnel,
			},
			Args:            p.getFSScanningArgs(ctx, command, ClientServer, encodedTunnelServerURL.String()),
			Resources:       resourceRequirements,
			SecurityContext: securityContext,
			VolumeMounts:    volumeMounts,
		})
	}

	podSpec := corev1.PodSpec{
		Affinity:                     tunneloperator.LinuxNodeAffinity(),
		RestartPolicy:                corev1.RestartPolicyNever,
		ServiceAccountName:           ctx.GetServiceAccountName(),
		AutomountServiceAccountToken: pointer.Bool(getAutomountServiceAccountToken(ctx)),
		Volumes:                      volumes,
		InitContainers:               []corev1.Container{initContainerCopyBinary},
		Containers:                   containers,
		SecurityContext:              &corev1.PodSecurityContext{},
	}

	if !ctx.GetTunnelOperatorConfig().VulnerabilityScanJobsInSameNamespace() {
		// schedule scan job explicitly on specific node.
		podSpec.NodeName = nodeName
	}

	return podSpec, secrets, nil
}

func (p *plugin) getFSScanningArgs(ctx tunneloperator.PluginContext, command Command, mode Mode, tunnelServerURL string) []string {
	c, err := p.getConfig(ctx)
	if err != nil {
		return []string{}
	}
	scanners := Scanners(c)
	imcs := p.imageConfigSecretScanner(c.Data)
	skipUpdate := SkipDBUpdate(c)
	args := []string{
		"--cache-dir",
		"/var/tunneloperator/tunnel-db",
		"--quiet",
		string(command),
		scanners,
		getSecurityChecks(ctx),
		skipUpdate,
		"--format",
		"json",
		"/",
	}
	if len(imcs) > 0 {
		args = append(args, imcs...)
	}
	if mode == ClientServer {
		args = append(args, "--server", tunnelServerURL)
	}
	slow := Slow(c)
	if len(slow) > 0 {
		args = append(args, slow)
	}
	pkgList := getPkgList(ctx)
	if len(pkgList) > 0 {
		args = append(args, pkgList)
	}
	return args
}

func (p *plugin) initContainerFSEnvVar(tunnelConfigName string, config Config) []corev1.EnvVar {
	envs := []corev1.EnvVar{
		constructEnvVarSourceFromConfigMap("HTTP_PROXY", tunnelConfigName, keyTunnelHTTPProxy),
		constructEnvVarSourceFromConfigMap("HTTPS_PROXY", tunnelConfigName, keyTunnelHTTPSProxy),
		constructEnvVarSourceFromConfigMap("NO_PROXY", tunnelConfigName, keyTunnelNoProxy),
		constructEnvVarSourceFromSecret("GITHUB_TOKEN", tunnelConfigName, keyTunnelGitHubToken),
	}
	if config.GetDBRepositoryInsecure() {
		envs = append(envs, corev1.EnvVar{
			Name:  "TUNNEL_INSECURE",
			Value: "true",
		})
	}
	return envs
}

func (p *plugin) appendTunnelInsecureEnv(config Config, image string, env []corev1.EnvVar) ([]corev1.EnvVar, error) {
	ref, err := containerimage.ParseReference(image)
	if err != nil {
		return nil, err
	}

	insecureRegistries := config.GetInsecureRegistries()
	if insecureRegistries[ref.Context().RegistryStr()] {
		env = append(env, corev1.EnvVar{
			Name:  "TUNNEL_INSECURE",
			Value: "true",
		})
	}

	return env, nil
}

func (p *plugin) appendTunnelNonSSLEnv(config Config, image string, env []corev1.EnvVar) ([]corev1.EnvVar, error) {
	ref, err := containerimage.ParseReference(image)
	if err != nil {
		return nil, err
	}

	nonSSLRegistries := config.GetNonSSLRegistries()
	if nonSSLRegistries[ref.Context().RegistryStr()] {
		env = append(env, corev1.EnvVar{
			Name:  "TUNNEL_NON_SSL",
			Value: "true",
		})
	}

	return env, nil
}

func (p *plugin) ParseReportData(ctx tunneloperator.PluginContext, imageRef string, logsReader io.ReadCloser) (v1alpha1.VulnerabilityReportData, v1alpha1.ExposedSecretReportData, *v1alpha1.SbomReportData, error) {
	var vulnReport v1alpha1.VulnerabilityReportData
	var secretReport v1alpha1.ExposedSecretReportData
	var sbomReport v1alpha1.SbomReportData

	config, err := p.newConfigFrom(ctx)
	if err != nil {
		return vulnReport, secretReport, &sbomReport, err
	}
	cmd, err := config.GetCommand()
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

	vulnerabilities := make([]v1alpha1.Vulnerability, 0)
	secrets := make([]v1alpha1.ExposedSecret, 0)
	addFields := config.GetAdditionalVulnerabilityReportFields()

	for _, report := range reports.Results {
		vulnerabilities = append(vulnerabilities, getVulnerabilitiesFromScanResult(report, addFields)...)
		secrets = append(secrets, getExposedSecretsFromScanResult(report)...)
	}
	var bom *v1alpha1.BOM
	if ctx.GetTunnelOperatorConfig().GenerateSbomEnabled() {
		bom, err = generateSbomFromScanResult(reports)
		if err != nil {
			return vulnReport, secretReport, &sbomReport, err
		}
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
	if bom != nil {
		sbomData = &v1alpha1.SbomReportData{
			UpdateTimestamp: metav1.NewTime(p.clock.Now()),
			Scanner: v1alpha1.Scanner{
				Name:    v1alpha1.ScannerNameTunnel,
				Vendor:  "Khulnasoft Security",
				Version: version,
			},
			Registry: registry,
			Artifact: artifact,
			Summary:  bomSummary(*bom),
			Bom:      *bom,
		}
	}
	return v1alpha1.VulnerabilityReportData{
			UpdateTimestamp: metav1.NewTime(p.clock.Now()),
			Scanner: v1alpha1.Scanner{
				Name:    v1alpha1.ScannerNameTunnel,
				Vendor:  "Khulnasoft Security",
				Version: version,
			},
			Registry:        registry,
			Artifact:        artifact,
			Summary:         p.vulnerabilitySummary(vulnerabilities),
			Vulnerabilities: vulnerabilities,
		}, v1alpha1.ExposedSecretReportData{
			UpdateTimestamp: metav1.NewTime(p.clock.Now()),
			Scanner: v1alpha1.Scanner{
				Name:    v1alpha1.ScannerNameTunnel,
				Vendor:  "Khulnasoft Security",
				Version: version,
			},
			Registry: registry,
			Artifact: artifact,
			Summary:  p.secretSummary(secrets),
			Secrets:  secrets,
		}, sbomData, nil

}

func bomSummary(bom v1alpha1.BOM) v1alpha1.SbomSummary {
	return v1alpha1.SbomSummary{
		ComponentsCount:   len(bom.Components) + 1,
		DependenciesCount: len(*bom.Dependencies),
	}

}

func getVulnerabilitiesFromScanResult(report ty.Result, addFields AdditionalFields) []v1alpha1.Vulnerability {
	vulnerabilities := make([]v1alpha1.Vulnerability, 0)

	for _, sr := range report.Vulnerabilities {
		var pd, lmd string
		if sr.PublishedDate != nil {
			pd = sr.PublishedDate.Format(time.RFC3339)
		}
		if sr.LastModifiedDate != nil {
			lmd = sr.LastModifiedDate.Format(time.RFC3339)
		}
		vulnerability := v1alpha1.Vulnerability{
			VulnerabilityID:  sr.VulnerabilityID,
			Resource:         sr.PkgName,
			InstalledVersion: sr.InstalledVersion,
			FixedVersion:     sr.FixedVersion,
			PublishedDate:    pd,
			LastModifiedDate: lmd,
			Severity:         v1alpha1.Severity(sr.Severity),
			Title:            sr.Title,
			PrimaryLink:      sr.PrimaryURL,
			Links:            []string{},
			Score:            GetScoreFromCVSS(GetCvssV3(sr.CVSS)),
		}

		if addFields.Description {
			vulnerability.Description = sr.Description
		}
		if addFields.Links && sr.References != nil {
			vulnerability.Links = sr.References
		}
		if addFields.CVSS {
			vulnerability.CVSS = sr.CVSS
		}
		if addFields.Target {
			vulnerability.Target = report.Target
		}
		if addFields.Class {
			vulnerability.Class = string(report.Class)
		}
		if addFields.PackageType {
			vulnerability.PackageType = report.Type
		}
		if addFields.PkgPath {
			vulnerability.PkgPath = sr.PkgPath
		}

		vulnerabilities = append(vulnerabilities, vulnerability)
	}

	return vulnerabilities
}

func generateSbomFromScanResult(report ty.Report) (*v1alpha1.BOM, error) {
	var bom *v1alpha1.BOM
	if len(report.Results) > 0 && len(report.Results[0].Packages) > 0 {
		// capture os.Stdout with a writer
		done := capture()
		err := tr.Write(report, fg.Options{
			ReportOptions: fg.ReportOptions{
				Format: ty.FormatCycloneDX,
			},
		})
		if err != nil {
			return nil, err
		}
		bomWriter, err := done()
		if err != nil {
			return nil, err
		}
		var bom cdx.BOM
		err = json.Unmarshal([]byte(bomWriter), &bom)
		if err != nil {
			return nil, err
		}
		return cycloneDxBomToReport(bom), nil
	}
	return bom, nil
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

func (p *plugin) newConfigFrom(ctx tunneloperator.PluginContext) (Config, error) {
	return p.getConfig(ctx)
}

func (p *plugin) getConfig(ctx tunneloperator.PluginContext) (Config, error) {
	pluginConfig, err := ctx.GetConfig()
	if err != nil {
		return Config{}, err
	}
	return Config{PluginConfig: pluginConfig}, nil
}

// NewConfigForConfigAudit and interface which expose related configaudit report configuration
func (p *plugin) NewConfigForConfigAudit(ctx tunneloperator.PluginContext) (configauditreport.ConfigAuditConfig, error) {
	return p.getConfig(ctx)
}

func (p *plugin) vulnerabilitySummary(vulnerabilities []v1alpha1.Vulnerability) v1alpha1.VulnerabilitySummary {
	var vs v1alpha1.VulnerabilitySummary
	for _, v := range vulnerabilities {
		switch v.Severity {
		case v1alpha1.SeverityCritical:
			vs.CriticalCount++
		case v1alpha1.SeverityHigh:
			vs.HighCount++
		case v1alpha1.SeverityMedium:
			vs.MediumCount++
		case v1alpha1.SeverityLow:
			vs.LowCount++
		default:
			vs.UnknownCount++
		}
	}
	return vs
}

func (p *plugin) secretSummary(secrets []v1alpha1.ExposedSecret) v1alpha1.ExposedSecretSummary {
	var s v1alpha1.ExposedSecretSummary
	for _, v := range secrets {
		switch v.Severity {
		case v1alpha1.SeverityCritical:
			s.CriticalCount++
		case v1alpha1.SeverityHigh:
			s.HighCount++
		case v1alpha1.SeverityMedium:
			s.MediumCount++
		case v1alpha1.SeverityLow:
			s.LowCount++
		}
	}
	return s
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

func GetCvssV3(findingCvss types.VendorCVSS) map[string]*CVSS {
	cvssV3 := make(map[string]*CVSS)
	for vendor, cvss := range findingCvss {
		var v3Score *float64
		if cvss.V3Score != 0.0 {
			v3Score = pointer.Float64(cvss.V3Score)
		}
		cvssV3[string(vendor)] = &CVSS{v3Score}
	}
	return cvssV3
}

func GetScoreFromCVSS(CVSSs map[string]*CVSS) *float64 {
	var nvdScore, vendorScore *float64

	for name, cvss := range CVSSs {
		if name == "nvd" {
			nvdScore = cvss.V3Score
		} else {
			vendorScore = cvss.V3Score
		}
	}

	if nvdScore != nil {
		return nvdScore
	}

	return vendorScore
}

func GetMirroredImage(image string, mirrors map[string]string) (string, error) {
	ref, err := containerimage.ParseReference(image)
	if err != nil {
		return "", err
	}
	mirroredImage := ref.Name()
	for k, v := range mirrors {
		if strings.HasPrefix(mirroredImage, k) {
			mirroredImage = strings.Replace(mirroredImage, k, v, 1)
			return mirroredImage, nil
		}
	}
	// If nothing is mirrored, we can simply use the input image.
	return image, nil
}

func constructEnvVarSourceFromConfigMap(envName, configName, configKey string) (res corev1.EnvVar) {
	res = corev1.EnvVar{
		Name: envName,
		ValueFrom: &corev1.EnvVarSource{
			ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
				LocalObjectReference: corev1.LocalObjectReference{
					Name: configName,
				},
				Key:      configKey,
				Optional: pointer.Bool(true),
			},
		},
	}
	return
}

func constructEnvVarSourceFromSecret(envName, secretName, secretKey string) (res corev1.EnvVar) {
	res = corev1.EnvVar{
		Name: envName,
		ValueFrom: &corev1.EnvVarSource{
			SecretKeyRef: &corev1.SecretKeySelector{
				LocalObjectReference: corev1.LocalObjectReference{
					Name: secretName,
				},
				Key:      secretKey,
				Optional: pointer.Bool(true),
			},
		},
	}
	return
}

func getContainers(spec corev1.PodSpec) []corev1.Container {
	containers := append(spec.Containers, spec.InitContainers...)

	// ephemeral container are not the same type as Containers/InitContainers,
	// then we add it in a different loop
	for _, c := range spec.EphemeralContainers {
		containers = append(containers, corev1.Container(c.EphemeralContainerCommon))
	}

	return containers
}

func CheckAwsEcrPrivateRegistry(ImageUrl string) string {
	if len(regexp.MustCompile(AWSECR_Image_Regex).FindAllStringSubmatch(ImageUrl, -1)) != 0 {
		return regexp.MustCompile(AWSECR_Image_Regex).FindAllStringSubmatch(ImageUrl, -1)[0][1]
	}
	return ""
}

func getSecurityChecks(ctx tunneloperator.PluginContext) string {
	securityChecks := make([]string, 0)

	c := ctx.GetTunnelOperatorConfig()
	if c.VulnerabilityScannerEnabled() {
		securityChecks = append(securityChecks, "vuln")
	}

	if c.ExposedSecretsScannerEnabled() {
		securityChecks = append(securityChecks, "secret")
	}

	return strings.Join(securityChecks, ",")
}

func getPkgList(ctx tunneloperator.PluginContext) string {
	c := ctx.GetTunnelOperatorConfig()
	if c.GenerateSbomEnabled() {
		return "--list-all-pkgs"
	}
	return ""
}

func ConfigWorkloadAnnotationEnvVars(workload client.Object, annotation string, envVarName string, tunnelConfigName string, configKey string) corev1.EnvVar {
	if value, ok := workload.GetAnnotations()[annotation]; ok {
		return corev1.EnvVar{
			Name:  envVarName,
			Value: value,
		}
	}
	return constructEnvVarSourceFromConfigMap(envVarName, tunnelConfigName, configKey)
}

type CVSS struct {
	V3Score *float64 `json:"V3Score,omitempty"`
}
