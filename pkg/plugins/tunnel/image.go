package tunnel

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/utils/ptr"

	"github.com/khulnasoft/tunnel-operator/pkg/apis/khulnasoft/v1alpha1"
	"github.com/khulnasoft/tunnel-operator/pkg/docker"
	"github.com/khulnasoft/tunnel-operator/pkg/kube"
	"github.com/khulnasoft/tunnel-operator/pkg/tunneloperator"
	"github.com/khulnasoft/tunnel-operator/pkg/vulnerabilityreport"
	containerimage "github.com/google/go-containerregistry/pkg/name"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type ImageJobSpecMgr struct {
	getPodSpecFunc GetPodSpecFunc
}

func NewImageJobSpecMgr() PodSpecMgr {
	return &ImageJobSpecMgr{}
}

func (j *ImageJobSpecMgr) GetPodSpec(ctx tunneloperator.PluginContext, config Config, workload client.Object, credentials map[string]docker.Auth, securityContext *corev1.SecurityContext, p *plugin, clusterSboms map[string]v1alpha1.SbomReportData) (corev1.PodSpec, []*corev1.Secret, error) {
	return j.getPodSpecFunc(ctx, config, workload, credentials, securityContext, p, clusterSboms)
}

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
func GetPodSpecForStandaloneMode(ctx tunneloperator.PluginContext, config Config, workload client.Object, credentials map[string]docker.Auth, securityContext *corev1.SecurityContext, p *plugin, clusterSboms map[string]v1alpha1.SbomReportData) (corev1.PodSpec, []*corev1.Secret, error) {
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

	cacheDir := config.GetImageScanCacheDir()

	initContainer := corev1.Container{
		Name:                     p.idGenerator.GenerateID(),
		Image:                    tunnelImageRef,
		ImagePullPolicy:          corev1.PullPolicy(config.GetImagePullPolicy()),
		TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
		Env:                      initContainerEnvVar(tunnelConfigName, config),
		Command: []string{
			"tunnel",
		},
		Args: []string{
			"--cache-dir",
			cacheDir,
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
		gcrImage := checkGcpCrOrPivateRegistry(c.Image)
		if _, ok := containersCredentials[c.Name]; ok && secret != nil {
			registryUsernameKey := fmt.Sprintf("%s.username", c.Name)
			registryPasswordKey := fmt.Sprintf("%s.password", c.Name)
			secretName := secret.Name
			if gcrImage {
				createEnvandVolumeForGcr(&env, &volumeMounts, &volumes, &registryPasswordKey, &secretName)
			} else {
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

		}

		env, err = appendTunnelInsecureEnv(config, c.Image, env)
		if err != nil {
			return corev1.PodSpec{}, nil, err
		}

		env, err = appendTunnelNonSSLEnv(config, c.Image, env)
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
		cmd, args := getCommandAndArgs(ctx, Standalone, imageRef.String(), "", resultFileName)
		if len(clusterSboms) > 0 { // tunnel sbom ...
			if sbomreportData, ok := clusterSboms[c.Name]; ok {
				secretName := fmt.Sprintf("sbom-%s", c.Name)
				secret, err := CreateSbomDataAsSecret(sbomreportData.Bom, secretName)
				if err != nil {
					return corev1.PodSpec{}, nil, err
				}
				secrets = append(secrets, &secret)
				fileName := fmt.Sprintf("%s.json", secretName)
				CreateVolumeSbomFiles(&volumeMounts, &volumes, &secretName, fileName)
				cmd, args = GetSbomScanCommandAndArgs(ctx, Standalone, fmt.Sprintf("/sbom/%s", fileName), "", resultFileName)
			}
		}
		containers = append(containers, corev1.Container{
			Name:                     c.Name,
			Image:                    tunnelImageRef,
			ImagePullPolicy:          corev1.PullPolicy(config.GetImagePullPolicy()),
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
		AutomountServiceAccountToken: ptr.To[bool](getAutomountServiceAccountToken(ctx)),
		Volumes:                      volumes,
		InitContainers:               []corev1.Container{initContainer},
		Containers:                   containers,
		SecurityContext:              &corev1.PodSecurityContext{},
	}, secrets, nil
}

// In the ClientServer mode the number of containers of the pod created by the
// scan job equals the number of containers defined for the scanned workload.
// Each container runs Tunnel image scan command and refers to Tunnel server URL
// returned by Config.GetServerURL:
//
//	tunnel image --server <server URL> \
//	  --format json <container image>
func GetPodSpecForClientServerMode(ctx tunneloperator.PluginContext, config Config, workload client.Object, credentials map[string]docker.Auth, securityContext *corev1.SecurityContext, p *plugin, clusterSboms map[string]v1alpha1.SbomReportData) (corev1.PodSpec, []*corev1.Secret, error) {
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
		// fmt.Sprintf("sbom-%s.json", imageName),
		//createVolumeSbomFiles(&volumeMounts, &volumes, &registryServiceAccountAuthKey, &secret.Name)

		region := CheckAwsEcrPrivateRegistry(container.Image)
		if region != "" {
			env = append(env, corev1.EnvVar{
				Name:  "AWS_REGION",
				Value: region,
			})
		}

		if auth, ok := containersCredentials[container.Name]; ok && secret != nil {
			if checkGcpCrOrPivateRegistry(container.Image) && auth.Username == "_json_key" {
				registryServiceAccountAuthKey := fmt.Sprintf("%s.password", container.Name)
				createEnvandVolumeForGcr(&env, &volumeMounts, &volumes, &registryServiceAccountAuthKey, &secret.Name)
			} else {
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
		}

		env, err = appendTunnelInsecureEnv(config, container.Image, env)
		if err != nil {
			return corev1.PodSpec{}, nil, err
		}

		env, err = appendTunnelNonSSLEnv(config, container.Image, env)
		if err != nil {
			return corev1.PodSpec{}, nil, err
		}

		if config.GetServerInsecure() {
			env = append(env, corev1.EnvVar{
				Name:  "TUNNEL_INSECURE",
				Value: "true",
			})
		}
		if config.GetDBRepositoryInsecure() {
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
		cmd, args := getCommandAndArgs(ctx, ClientServer, imageRef.String(), encodedTunnelServerURL.String(), resultFileName)
		if len(clusterSboms) > 0 { // tunnel sbom ...
			if sbomreportData, ok := clusterSboms[container.Name]; ok {
				secretName := fmt.Sprintf("sbom-%s", container.Name)
				secret, err := CreateSbomDataAsSecret(sbomreportData.Bom, secretName)
				if err != nil {
					return corev1.PodSpec{}, nil, err
				}
				secrets = append(secrets, &secret)
				fileName := fmt.Sprintf("%s.json", secretName)
				CreateVolumeSbomFiles(&volumeMounts, &volumes, &secretName, fileName)
				cmd, args = GetSbomScanCommandAndArgs(ctx, ClientServer, fmt.Sprintf("/sbom/%s", fileName), "", resultFileName)
			}
		}
		containers = append(containers, corev1.Container{
			Name:                     container.Name,
			Image:                    tunnelImageRef,
			ImagePullPolicy:          corev1.PullPolicy(config.GetImagePullPolicy()),
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
		AutomountServiceAccountToken: ptr.To[bool](getAutomountServiceAccountToken(ctx)),
		Containers:                   containers,
		Volumes:                      volumes,
	}, secrets, nil
}

func initContainerEnvVar(tunnelConfigName string, config Config) []corev1.EnvVar {
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

func getCommandAndArgs(ctx tunneloperator.PluginContext, mode Mode, imageRef string, tunnelServerURL string, resultFileName string) ([]string, []string) {
	command := []string{
		"tunnel",
	}
	tunnelConfig := ctx.GetTunnelOperatorConfig()
	compressLogs := tunnelConfig.CompressLogs()
	c, err := getConfig(ctx)
	if err != nil {
		return []string{}, []string{}
	}
	slow := Slow(c)
	skipJavaDBUpdate := SkipJavaDBUpdate(c)
	cacheDir := c.GetImageScanCacheDir()
	vulnTypeArgs := vulnTypeFilter(ctx)
	scanners := Scanners(c)
	var vulnTypeFlag string
	if len(vulnTypeArgs) == 2 {
		vulnTypeFlag = fmt.Sprintf("%s %s ", vulnTypeArgs[0], vulnTypeArgs[1])
	}
	imcs := imageConfigSecretScanner(tunnelConfig)
	var imageconfigSecretScannerFlag string
	if len(imcs) == 2 {
		imageconfigSecretScannerFlag = fmt.Sprintf("%s %s ", imcs[0], imcs[1])
	}
	var skipUpdate string
	if c.GetClientServerSkipUpdate() && mode == ClientServer {
		skipUpdate = SkipDBUpdate(c)
	} else if mode != ClientServer {
		skipUpdate = SkipDBUpdate(c)
	}
	if !compressLogs {
		args := []string{
			"--cache-dir",
			cacheDir,
			"--quiet",
			"image",
			scanners,
			getSecurityChecks(ctx),
			"--format",
			"json",
		}
		if len(tunnelServerURL) > 0 {
			args = append(args, []string{"--server", tunnelServerURL}...)
		}
		args = append(args, imageRef)

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
		if len(skipUpdate) > 0 {
			args = append(args, skipUpdate)
		}
		if len(skipJavaDBUpdate) > 0 {
			args = append(args, skipJavaDBUpdate)
		}

		return command, args
	}
	var serverUrlParms string
	if mode == ClientServer {
		serverUrlParms = fmt.Sprintf("--server '%s' ", tunnelServerURL)
	}
	return []string{"/bin/sh"}, []string{"-c", fmt.Sprintf(`tunnel image %s '%s' %s %s %s %s %s %s --cache-dir %s --quiet %s --format json %s> /tmp/scan/%s &&  bzip2 -c /tmp/scan/%s | base64`, slow, imageRef, scanners, getSecurityChecks(ctx), imageconfigSecretScannerFlag, vulnTypeFlag, skipUpdate, skipJavaDBUpdate, cacheDir, getPkgList(ctx), serverUrlParms, resultFileName, resultFileName)}
}

func GetSbomScanCommandAndArgs(ctx tunneloperator.PluginContext, mode Mode, sbomFile string, tunnelServerURL string, resultFileName string) ([]string, []string) {
	command := []string{
		"tunnel",
	}
	tunnelConfig := ctx.GetTunnelOperatorConfig()
	compressLogs := tunnelConfig.CompressLogs()
	c, err := getConfig(ctx)
	if err != nil {
		return []string{}, []string{}
	}
	slow := Slow(c)
	vulnTypeArgs := vulnTypeFilter(ctx)
	var vulnTypeFlag string
	if len(vulnTypeArgs) == 2 {
		vulnTypeFlag = fmt.Sprintf("%s %s ", vulnTypeArgs[0], vulnTypeArgs[1])
	}

	var skipUpdate string
	if c.GetClientServerSkipUpdate() && mode == ClientServer {
		skipUpdate = SkipDBUpdate(c)
	} else if mode != ClientServer {
		skipUpdate = SkipDBUpdate(c)
	}
	if !compressLogs {
		args := []string{
			"--cache-dir",
			"/tmp/tunnel/.cache",
			"--quiet",
			"sbom",
			"--format",
			"json",
		}

		if len(tunnelServerURL) > 0 {
			args = append(args, []string{"--server", tunnelServerURL}...)
		}
		args = append(args, sbomFile)
		if len(slow) > 0 {
			args = append(args, slow)
		}
		if len(vulnTypeArgs) > 0 {
			args = append(args, vulnTypeArgs...)
		}
		if len(skipUpdate) > 0 {
			args = append(args, skipUpdate)
		}
		return command, args
	}
	var serverUrlParms string
	if mode == ClientServer {
		serverUrlParms = fmt.Sprintf("--server '%s' ", tunnelServerURL)
	}
	return []string{"/bin/sh"}, []string{"-c", fmt.Sprintf(`tunnel sbom %s %s %s %s  --cache-dir /tmp/tunnel/.cache --quiet --format json %s> /tmp/scan/%s &&  bzip2 -c /tmp/scan/%s | base64`, slow, sbomFile, vulnTypeFlag, skipUpdate, serverUrlParms, resultFileName, resultFileName)}
}

func vulnTypeFilter(ctx tunneloperator.PluginContext) []string {
	config, err := getConfig(ctx)
	if err != nil {
		return []string{}
	}
	vulnType := config.GetVulnType()
	if len(vulnType) == 0 {
		return []string{}
	}
	return []string{"--vuln-type", vulnType}
}

func appendTunnelNonSSLEnv(config Config, image string, env []corev1.EnvVar) ([]corev1.EnvVar, error) {
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

func createEnvandVolumeForGcr(env *[]corev1.EnvVar, volumeMounts *[]corev1.VolumeMount, volumes *[]corev1.Volume, registryPasswordKey *string, secretName *string) {
	*env = append(*env, corev1.EnvVar{
		Name:  "TUNNEL_USERNAME",
		Value: "",
	})
	*env = append(*env, corev1.EnvVar{
		Name:  "GOOGLE_APPLICATION_CREDENTIALS",
		Value: "/cred/credential.json",
	})
	googlecredMount := corev1.VolumeMount{
		Name:      "gcrvol",
		MountPath: "/cred",
		ReadOnly:  true,
	}
	googlecredVolume := corev1.Volume{
		Name: "gcrvol",
		VolumeSource: corev1.VolumeSource{
			Secret: &corev1.SecretVolumeSource{
				SecretName: *secretName,
				Items: []corev1.KeyToPath{
					{
						Key:  *registryPasswordKey,
						Path: "credential.json",
					},
				},
			},
		},
	}
	*volumes = append(*volumes, googlecredVolume)
	*volumeMounts = append(*volumeMounts, googlecredMount)
}

func checkGcpCrOrPivateRegistry(imageUrl string) bool {
	imageRegex := regexp.MustCompile(GCPCR_Inage_Regex)
	return imageRegex.MatchString(imageUrl)
}

func getUniqueScanResultFileName(name string) string {
	return fmt.Sprintf("result_%s.json", name)
}

func CheckAwsEcrPrivateRegistry(ImageUrl string) string {
	if len(regexp.MustCompile(AWSECR_Image_Regex).FindAllStringSubmatch(ImageUrl, -1)) != 0 {
		return regexp.MustCompile(AWSECR_Image_Regex).FindAllStringSubmatch(ImageUrl, -1)[0][1]
	}
	return ""
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

func (p *plugin) newSecretWithAggregateImagePullCredentials(obj client.Object, containerImages kube.ContainerImages, credentials map[string]docker.Auth) *corev1.Secret {
	secretData := kube.AggregateImagePullSecretsData(containerImages, credentials)

	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name: vulnerabilityreport.RegistryCredentialsSecretName(obj),
		},
		Data: secretData,
	}
}
