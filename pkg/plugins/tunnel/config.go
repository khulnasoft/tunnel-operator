package tunnel

import (
	"fmt"

	"path/filepath"

	"strconv"
	"strings"

	"github.com/khulnasoft/tunnel-operator/pkg/utils"
	"github.com/khulnasoft/tunnel-operator/pkg/vulnerabilityreport"

	"github.com/khulnasoft/tunnel-operator/pkg/tunneloperator"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	keyTunnelImageRepository = "tunnel.repository"
	keyTunnelImageTag        = "tunnel.tag"
	//nolint:gosec
	keyTunnelImagePullSecret                     = "tunnel.imagePullSecret"
	keyTunnelImagePullPolicy                     = "tunnel.imagePullPolicy"
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
	keyTunnelImageScanCacheDir      = "tunnel.imageScanCacheDir"
	keyTunnelFilesystemScanCacheDir = "tunnel.filesystemScanCacheDir"
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

// Config defines configuration params for this plugin.
type Config struct {
	tunneloperator.PluginConfig
}

func (c Config) GetAdditionalVulnerabilityReportFields() vulnerabilityreport.AdditionalFields {
	addFields := vulnerabilityreport.AdditionalFields{}

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

func (c Config) GetImagePullPolicy() string {
	ipp, ok := c.Data[keyTunnelImagePullPolicy]
	if !ok {
		return "IfNotPresent"
	}
	return ipp
}

func (c Config) GetMode() Mode {
	var ok bool
	var value string
	if value, ok = c.Data[keyTunnelMode]; !ok {
		return Standalone
	}

	switch Mode(value) {
	case Standalone:
		return Standalone
	case ClientServer:
		return ClientServer
	}
	return Standalone
}

func (c Config) GetCommand() Command {
	var ok bool
	var value string
	if value, ok = c.Data[keyTunnelCommand]; !ok {
		// for backward compatibility, fallback to ImageScan
		return Image
	}
	switch Command(value) {
	case Image:
		return Image
	case Filesystem:
		return Filesystem
	case Rootfs:
		return Rootfs
	}
	return Image
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

func (c Config) GetImageScanCacheDir() string {
	val, ok := c.Data[keyTunnelImageScanCacheDir]
	if !ok || val == "" {
		return "/tmp/tunnel/.cache"
	}
	return val
}

func (c Config) GetFilesystemScanCacheDir() string {
	val, ok := c.Data[keyTunnelFilesystemScanCacheDir]
	if !ok || val == "" {
		return "/var/tunneloperator/tunnel-db"
	}
	return val
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
