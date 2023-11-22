package tunnel_test

import (
	"bytes"

	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/khulnasoft/tunnel-operator/pkg/docker"
	"github.com/khulnasoft/tunnel-operator/pkg/vulnerabilityreport"

	dbtypes "github.com/khulnasoft-lab/tunnel-db/pkg/types"
	"github.com/khulnasoft/tunnel-operator/pkg/apis/khulnasoft/v1alpha1"
	"github.com/khulnasoft/tunnel-operator/pkg/ext"
	"github.com/khulnasoft/tunnel-operator/pkg/kube"
	"github.com/khulnasoft/tunnel-operator/pkg/plugins/tunnel"
	"github.com/khulnasoft/tunnel-operator/pkg/tunneloperator"
	bz "github.com/dsnet/compress/bzip2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	v1 "k8s.io/api/batch/v1"
	"k8s.io/api/batch/v1beta1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

var (
	fixedTime  = time.Now()
	fixedClock = ext.NewFixedClock(fixedTime)
)

func TestPlugin_GetScanJobSpec(t *testing.T) {

	tmpVolume := corev1.Volume{
		Name: "tmp",
		VolumeSource: corev1.VolumeSource{
			EmptyDir: &corev1.EmptyDirVolumeSource{
				Medium: corev1.StorageMediumDefault,
			},
		},
	}

	tmpVolumeMount := corev1.VolumeMount{
		Name:      "tmp",
		MountPath: "/tmp",
		ReadOnly:  false,
	}

	timeoutEnv := corev1.EnvVar{
		Name: "TUNNEL_TIMEOUT",
		ValueFrom: &corev1.EnvVarSource{
			ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
				LocalObjectReference: corev1.LocalObjectReference{
					Name: "tunnel-operator-tunnel-config",
				},
				Key:      "tunnel.timeout",
				Optional: ptr.To[bool](true),
			},
		},
	}

	testCases := []struct {
		name string

		config              map[string]string
		tunnelOperatorConfig map[string]string
		workloadSpec        client.Object
		credentials         map[string]docker.Auth

		expectedSecretsData []map[string][]byte
		expectedJobSpec     corev1.PodSpec
	}{
		{
			name: "Standalone mode without insecure registry",
			tunnelOperatorConfig: map[string]string{
				tunneloperator.KeyVulnerabilityScannerEnabled:  "true",
				tunneloperator.KeyExposedSecretsScannerEnabled: "true",
				tunneloperator.KeyScanJobcompressLogs:          "true",
			},
			config: map[string]string{
				"tunnel.repository":                "docker.io/khulnasoft/tunnel",
				"tunnel.tag":                       "0.35.0",
				"tunnel.mode":                      string(tunnel.Standalone),
				"tunnel.dbRepository":              tunnel.DefaultDBRepository,
				"tunnel.javaDbRepository":          tunnel.DefaultJavaDBRepository,
				"tunnel.resources.requests.cpu":    "100m",
				"tunnel.resources.requests.memory": "100M",
				"tunnel.resources.limits.cpu":      "500m",
				"tunnel.resources.limits.memory":   "500M",
			},
			workloadSpec: &appsv1.ReplicaSet{
				TypeMeta: metav1.TypeMeta{
					Kind:       "ReplicaSet",
					APIVersion: "apps/v1",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "nginx-6799fc88d8",
					Namespace: "prod-ns",
				},
				Spec: appsv1.ReplicaSetSpec{
					Template: corev1.PodTemplateSpec{
						Spec: corev1.PodSpec{
							Containers: []corev1.Container{
								{
									Name:  "nginx",
									Image: "nginx:1.16",
								},
							},
						},
					},
				},
			},
			expectedJobSpec: corev1.PodSpec{
				Affinity:                     tunneloperator.LinuxNodeAffinity(),
				RestartPolicy:                corev1.RestartPolicyNever,
				ServiceAccountName:           "tunneloperator-sa",
				ImagePullSecrets:             []corev1.LocalObjectReference{},
				AutomountServiceAccountToken: ptr.To[bool](false),
				Volumes: []corev1.Volume{
					tmpVolume, getScanResultVolume(),
				},
				InitContainers: []corev1.Container{
					{
						Name:                     "00000000-0000-0000-0000-000000000001",
						Image:                    "docker.io/khulnasoft/tunnel:0.35.0",
						ImagePullPolicy:          corev1.PullIfNotPresent,
						TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
						Env: []corev1.EnvVar{
							{
								Name: "HTTP_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.httpProxy",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name: "HTTPS_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.httpsProxy",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name: "NO_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.noProxy",
										Optional: ptr.To[bool](true),
									},
								},
							},

							{
								Name: "GITHUB_TOKEN",
								ValueFrom: &corev1.EnvVarSource{
									SecretKeyRef: &corev1.SecretKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.githubToken",
										Optional: ptr.To[bool](true),
									},
								},
							},
						},
						Command: []string{
							"tunnel",
						},
						Args: []string{
							"--cache-dir", "/tmp/tunnel/.cache",
							"image",
							"--download-db-only",
							"--db-repository", tunnel.DefaultDBRepository,
						},
						Resources: corev1.ResourceRequirements{
							Requests: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("100m"),
								corev1.ResourceMemory: resource.MustParse("100M"),
							},
							Limits: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("500m"),
								corev1.ResourceMemory: resource.MustParse("500M"),
							},
						},
						VolumeMounts: []corev1.VolumeMount{
							tmpVolumeMount,
						},
						SecurityContext: &corev1.SecurityContext{
							Privileged:               ptr.To[bool](false),
							AllowPrivilegeEscalation: ptr.To[bool](false),
							Capabilities: &corev1.Capabilities{
								Drop: []corev1.Capability{"all"},
							},
							ReadOnlyRootFilesystem: ptr.To[bool](true),
						},
					},
				},
				Containers: []corev1.Container{
					{
						Name:                     "nginx",
						Image:                    "docker.io/khulnasoft/tunnel:0.35.0",
						ImagePullPolicy:          corev1.PullIfNotPresent,
						TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
						Env: []corev1.EnvVar{
							{
								Name: "TUNNEL_SEVERITY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.severity",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name: "TUNNEL_IGNORE_UNFIXED",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.ignoreUnfixed",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name: "TUNNEL_OFFLINE_SCAN",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.offlineScan",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name: "TUNNEL_JAVA_DB_REPOSITORY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.javaDbRepository",
										Optional: ptr.To[bool](true),
									},
								},
							},
							timeoutEnv,
							{
								Name: "TUNNEL_SKIP_FILES",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.skipFiles",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name: "TUNNEL_SKIP_DIRS",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.skipDirs",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name: "HTTP_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.httpProxy",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name: "HTTPS_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.httpsProxy",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name: "NO_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.noProxy",
										Optional: ptr.To[bool](true),
									},
								},
							},
						},
						Command: []string{
							"/bin/sh",
						},
						Args: []string{
							"-c",
							"tunnel image --slow 'nginx:1.16' --security-checks vuln,secret --image-config-scanners secret   --skip-update  --cache-dir /tmp/tunnel/.cache --quiet  --format json > /tmp/scan/result_nginx.json &&  bzip2 -c /tmp/scan/result_nginx.json | base64",
						},
						Resources: corev1.ResourceRequirements{
							Requests: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("100m"),
								corev1.ResourceMemory: resource.MustParse("100M"),
							},
							Limits: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("500m"),
								corev1.ResourceMemory: resource.MustParse("500M"),
							},
						},
						VolumeMounts: []corev1.VolumeMount{
							tmpVolumeMount, getScanResultVolumeMount(),
						},
						SecurityContext: &corev1.SecurityContext{
							Privileged:               ptr.To[bool](false),
							AllowPrivilegeEscalation: ptr.To[bool](false),
							Capabilities: &corev1.Capabilities{
								Drop: []corev1.Capability{"all"},
							},
							ReadOnlyRootFilesystem: ptr.To[bool](true),
						},
					},
				},
				SecurityContext: &corev1.PodSecurityContext{},
			},
		},
		{
			name: "Standalone mode with insecure registry",
			tunnelOperatorConfig: map[string]string{
				tunneloperator.KeyVulnerabilityScannerEnabled:  "false",
				tunneloperator.KeyExposedSecretsScannerEnabled: "true",
				tunneloperator.KeyScanJobcompressLogs:          "true",
			},
			config: map[string]string{
				"tunnel.repository":                   "docker.io/khulnasoft/tunnel",
				"tunnel.tag":                          "0.35.0",
				"tunnel.mode":                         string(tunnel.Standalone),
				"tunnel.insecureRegistry.pocRegistry": "poc.myregistry.harbor.com.pl",
				"tunnel.dbRepository":                 tunnel.DefaultDBRepository,
				"tunnel.javaDbRepository":             tunnel.DefaultJavaDBRepository,

				"tunnel.resources.requests.cpu":    "100m",
				"tunnel.resources.requests.memory": "100M",
				"tunnel.resources.limits.cpu":      "500m",
				"tunnel.resources.limits.memory":   "500M",
			},
			workloadSpec: &corev1.Pod{
				TypeMeta: metav1.TypeMeta{
					Kind:       "Pod",
					APIVersion: "v1",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "nginx",
					Namespace: "prod-ns",
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name:  "nginx",
							Image: "poc.myregistry.harbor.com.pl/nginx:1.16",
						},
					},
				}},
			expectedJobSpec: corev1.PodSpec{
				Affinity:                     tunneloperator.LinuxNodeAffinity(),
				RestartPolicy:                corev1.RestartPolicyNever,
				ServiceAccountName:           "tunneloperator-sa",
				AutomountServiceAccountToken: ptr.To[bool](false),
				ImagePullSecrets:             []corev1.LocalObjectReference{},
				Volumes: []corev1.Volume{
					tmpVolume, getScanResultVolume(),
				},
				InitContainers: []corev1.Container{
					{
						Name:                     "00000000-0000-0000-0000-000000000001",
						Image:                    "docker.io/khulnasoft/tunnel:0.35.0",
						ImagePullPolicy:          corev1.PullIfNotPresent,
						TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
						Env: []corev1.EnvVar{
							{
								Name: "HTTP_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.httpProxy",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name: "HTTPS_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.httpsProxy",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name: "NO_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.noProxy",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name: "GITHUB_TOKEN",
								ValueFrom: &corev1.EnvVarSource{
									SecretKeyRef: &corev1.SecretKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.githubToken",
										Optional: ptr.To[bool](true),
									},
								},
							},
						},
						Command: []string{
							"tunnel",
						},
						Args: []string{
							"--cache-dir", "/tmp/tunnel/.cache",
							"image",
							"--download-db-only",
							"--db-repository", tunnel.DefaultDBRepository,
						},
						Resources: corev1.ResourceRequirements{
							Requests: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("100m"),
								corev1.ResourceMemory: resource.MustParse("100M"),
							},
							Limits: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("500m"),
								corev1.ResourceMemory: resource.MustParse("500M"),
							},
						},
						VolumeMounts: []corev1.VolumeMount{
							tmpVolumeMount,
						},
						SecurityContext: &corev1.SecurityContext{
							Privileged:               ptr.To[bool](false),
							AllowPrivilegeEscalation: ptr.To[bool](false),
							Capabilities: &corev1.Capabilities{
								Drop: []corev1.Capability{"all"},
							},
							ReadOnlyRootFilesystem: ptr.To[bool](true),
						},
					},
				},
				Containers: []corev1.Container{
					{
						Name:                     "nginx",
						Image:                    "docker.io/khulnasoft/tunnel:0.35.0",
						ImagePullPolicy:          corev1.PullIfNotPresent,
						TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
						Env: []corev1.EnvVar{
							{
								Name: "TUNNEL_SEVERITY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.severity",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name: "TUNNEL_IGNORE_UNFIXED",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.ignoreUnfixed",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name: "TUNNEL_OFFLINE_SCAN",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.offlineScan",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name: "TUNNEL_JAVA_DB_REPOSITORY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.javaDbRepository",
										Optional: ptr.To[bool](true),
									},
								},
							},
							timeoutEnv,
							{
								Name: "TUNNEL_SKIP_FILES",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.skipFiles",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name: "TUNNEL_SKIP_DIRS",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.skipDirs",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name: "HTTP_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.httpProxy",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name: "HTTPS_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.httpsProxy",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name: "NO_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.noProxy",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name:  "TUNNEL_INSECURE",
								Value: "true",
							},
						},
						Command: []string{
							"/bin/sh",
						},
						Args: []string{
							"-c",
							"tunnel image --slow 'poc.myregistry.harbor.com.pl/nginx:1.16' --security-checks secret --image-config-scanners secret   --skip-update  --cache-dir /tmp/tunnel/.cache --quiet  --format json > /tmp/scan/result_nginx.json &&  bzip2 -c /tmp/scan/result_nginx.json | base64",
						},
						Resources: corev1.ResourceRequirements{
							Requests: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("100m"),
								corev1.ResourceMemory: resource.MustParse("100M"),
							},
							Limits: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("500m"),
								corev1.ResourceMemory: resource.MustParse("500M"),
							},
						},
						VolumeMounts: []corev1.VolumeMount{
							tmpVolumeMount, getScanResultVolumeMount(),
						},
						SecurityContext: &corev1.SecurityContext{
							Privileged:               ptr.To[bool](false),
							AllowPrivilegeEscalation: ptr.To[bool](false),
							Capabilities: &corev1.Capabilities{
								Drop: []corev1.Capability{"all"},
							},
							ReadOnlyRootFilesystem: ptr.To[bool](true),
						},
					},
				},
				SecurityContext: &corev1.PodSecurityContext{},
			},
		},
		{
			name: "Standalone mode with non-SSL registry",
			tunnelOperatorConfig: map[string]string{
				tunneloperator.KeyVulnerabilityScannerEnabled:  "true",
				tunneloperator.KeyExposedSecretsScannerEnabled: "false",
				tunneloperator.KeyScanJobcompressLogs:          "true",
			},
			config: map[string]string{
				"tunnel.repository":                 "docker.io/khulnasoft/tunnel",
				"tunnel.tag":                        "0.35.0",
				"tunnel.mode":                       string(tunnel.Standalone),
				"tunnel.nonSslRegistry.pocRegistry": "poc.myregistry.harbor.com.pl",
				"tunnel.dbRepository":               tunnel.DefaultDBRepository,
				"tunnel.javaDbRepository":           tunnel.DefaultJavaDBRepository,
				"tunnel.resources.requests.cpu":     "100m",
				"tunnel.resources.requests.memory":  "100M",
				"tunnel.resources.limits.cpu":       "500m",
				"tunnel.resources.limits.memory":    "500M",
			},
			workloadSpec: &corev1.Pod{
				TypeMeta: metav1.TypeMeta{
					Kind:       "Pod",
					APIVersion: "v1",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "nginx",
					Namespace: "prod-ns",
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name:  "nginx",
							Image: "poc.myregistry.harbor.com.pl/nginx:1.16",
						},
					},
				},
			},
			expectedJobSpec: corev1.PodSpec{
				Affinity:                     tunneloperator.LinuxNodeAffinity(),
				RestartPolicy:                corev1.RestartPolicyNever,
				ServiceAccountName:           "tunneloperator-sa",
				ImagePullSecrets:             []corev1.LocalObjectReference{},
				AutomountServiceAccountToken: ptr.To[bool](false),
				Volumes: []corev1.Volume{
					tmpVolume, getScanResultVolume(),
				},
				InitContainers: []corev1.Container{
					{
						Name:                     "00000000-0000-0000-0000-000000000001",
						Image:                    "docker.io/khulnasoft/tunnel:0.35.0",
						ImagePullPolicy:          corev1.PullIfNotPresent,
						TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
						Env: []corev1.EnvVar{
							{
								Name: "HTTP_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.httpProxy",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name: "HTTPS_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.httpsProxy",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name: "NO_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.noProxy",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name: "GITHUB_TOKEN",
								ValueFrom: &corev1.EnvVarSource{
									SecretKeyRef: &corev1.SecretKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.githubToken",
										Optional: ptr.To[bool](true),
									},
								},
							},
						},
						Command: []string{
							"tunnel",
						},
						Args: []string{
							"--cache-dir", "/tmp/tunnel/.cache",
							"image",
							"--download-db-only",
							"--db-repository", tunnel.DefaultDBRepository,
						},
						Resources: corev1.ResourceRequirements{
							Requests: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("100m"),
								corev1.ResourceMemory: resource.MustParse("100M"),
							},
							Limits: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("500m"),
								corev1.ResourceMemory: resource.MustParse("500M"),
							},
						},
						VolumeMounts: []corev1.VolumeMount{
							tmpVolumeMount,
						},
						SecurityContext: &corev1.SecurityContext{
							Privileged:               ptr.To[bool](false),
							AllowPrivilegeEscalation: ptr.To[bool](false),
							Capabilities: &corev1.Capabilities{
								Drop: []corev1.Capability{"all"},
							},
							ReadOnlyRootFilesystem: ptr.To[bool](true),
						},
					},
				},
				Containers: []corev1.Container{
					{
						Name:                     "nginx",
						Image:                    "docker.io/khulnasoft/tunnel:0.35.0",
						ImagePullPolicy:          corev1.PullIfNotPresent,
						TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
						Env: []corev1.EnvVar{
							{
								Name: "TUNNEL_SEVERITY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.severity",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name: "TUNNEL_IGNORE_UNFIXED",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.ignoreUnfixed",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name: "TUNNEL_OFFLINE_SCAN",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.offlineScan",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name: "TUNNEL_JAVA_DB_REPOSITORY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.javaDbRepository",
										Optional: ptr.To[bool](true),
									},
								},
							},
							timeoutEnv,
							{
								Name: "TUNNEL_SKIP_FILES",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.skipFiles",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name: "TUNNEL_SKIP_DIRS",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.skipDirs",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name: "HTTP_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.httpProxy",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name: "HTTPS_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.httpsProxy",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name: "NO_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.noProxy",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name:  "TUNNEL_NON_SSL",
								Value: "true",
							},
						},
						Command: []string{
							"/bin/sh",
						},
						Args: []string{
							"-c",
							"tunnel image --slow 'poc.myregistry.harbor.com.pl/nginx:1.16' --security-checks vuln   --skip-update  --cache-dir /tmp/tunnel/.cache --quiet  --format json > /tmp/scan/result_nginx.json &&  bzip2 -c /tmp/scan/result_nginx.json | base64",
						},
						Resources: corev1.ResourceRequirements{
							Requests: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("100m"),
								corev1.ResourceMemory: resource.MustParse("100M"),
							},
							Limits: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("500m"),
								corev1.ResourceMemory: resource.MustParse("500M"),
							},
						},
						VolumeMounts: []corev1.VolumeMount{
							tmpVolumeMount, getScanResultVolumeMount(),
						},
						SecurityContext: &corev1.SecurityContext{
							Privileged:               ptr.To[bool](false),
							AllowPrivilegeEscalation: ptr.To[bool](false),
							Capabilities: &corev1.Capabilities{
								Drop: []corev1.Capability{"all"},
							},
							ReadOnlyRootFilesystem: ptr.To[bool](true),
						},
					},
				},
				SecurityContext: &corev1.PodSecurityContext{},
			},
		},
		{
			name: "Standalone mode with tunnelignore file",
			tunnelOperatorConfig: map[string]string{
				tunneloperator.KeyVulnerabilityScannerEnabled:  "true",
				tunneloperator.KeyExposedSecretsScannerEnabled: "true",
				tunneloperator.KeyScanJobcompressLogs:          "true",
			},
			config: map[string]string{
				"tunnel.repository": "docker.io/khulnasoft/tunnel",
				"tunnel.tag":        "0.35.0",
				"tunnel.mode":       string(tunnel.Standalone),
				"tunnel.ignoreFile": `# Accept the risk
CVE-2018-14618

# No impact in our settings
CVE-2019-1543`,
				"tunnel.dbRepository":              tunnel.DefaultDBRepository,
				"tunnel.javaDbRepository":          tunnel.DefaultJavaDBRepository,
				"tunnel.resources.requests.cpu":    "100m",
				"tunnel.resources.requests.memory": "100M",
				"tunnel.resources.limits.cpu":      "500m",
				"tunnel.resources.limits.memory":   "500M",
			},
			workloadSpec: &corev1.Pod{
				TypeMeta: metav1.TypeMeta{
					Kind:       "Pod",
					APIVersion: "v1",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "nginx",
					Namespace: "prod-ns",
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name:  "nginx",
							Image: "nginx:1.16",
						},
					},
				},
			},
			expectedJobSpec: corev1.PodSpec{
				Affinity:                     tunneloperator.LinuxNodeAffinity(),
				RestartPolicy:                corev1.RestartPolicyNever,
				ServiceAccountName:           "tunneloperator-sa",
				ImagePullSecrets:             []corev1.LocalObjectReference{},
				AutomountServiceAccountToken: ptr.To[bool](false),
				Volumes: []corev1.Volume{
					tmpVolume, getScanResultVolume(),
					{
						Name: "ignorefile",
						VolumeSource: corev1.VolumeSource{
							ConfigMap: &corev1.ConfigMapVolumeSource{
								LocalObjectReference: corev1.LocalObjectReference{
									Name: "tunnel-operator-tunnel-config",
								},
								Items: []corev1.KeyToPath{
									{
										Key:  "tunnel.ignoreFile",
										Path: ".tunnelignore",
									},
								},
							},
						},
					},
				},
				InitContainers: []corev1.Container{
					{
						Name:                     "00000000-0000-0000-0000-000000000001",
						Image:                    "docker.io/khulnasoft/tunnel:0.35.0",
						ImagePullPolicy:          corev1.PullIfNotPresent,
						TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
						Env: []corev1.EnvVar{
							{
								Name: "HTTP_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.httpProxy",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name: "HTTPS_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.httpsProxy",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name: "NO_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.noProxy",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name: "GITHUB_TOKEN",
								ValueFrom: &corev1.EnvVarSource{
									SecretKeyRef: &corev1.SecretKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.githubToken",
										Optional: ptr.To[bool](true),
									},
								},
							},
						},
						Command: []string{
							"tunnel",
						},
						Args: []string{
							"--cache-dir", "/tmp/tunnel/.cache",
							"image",
							"--download-db-only",
							"--db-repository", tunnel.DefaultDBRepository,
						},
						Resources: corev1.ResourceRequirements{
							Requests: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("100m"),
								corev1.ResourceMemory: resource.MustParse("100M"),
							},
							Limits: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("500m"),
								corev1.ResourceMemory: resource.MustParse("500M"),
							},
						},
						VolumeMounts: []corev1.VolumeMount{
							tmpVolumeMount,
						},
						SecurityContext: &corev1.SecurityContext{
							Privileged:               ptr.To[bool](false),
							AllowPrivilegeEscalation: ptr.To[bool](false),
							Capabilities: &corev1.Capabilities{
								Drop: []corev1.Capability{"all"},
							},
							ReadOnlyRootFilesystem: ptr.To[bool](true),
						},
					},
				},
				Containers: []corev1.Container{
					{
						Name:                     "nginx",
						Image:                    "docker.io/khulnasoft/tunnel:0.35.0",
						ImagePullPolicy:          corev1.PullIfNotPresent,
						TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
						Env: []corev1.EnvVar{
							{
								Name: "TUNNEL_SEVERITY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.severity",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name: "TUNNEL_IGNORE_UNFIXED",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.ignoreUnfixed",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name: "TUNNEL_OFFLINE_SCAN",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.offlineScan",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name: "TUNNEL_JAVA_DB_REPOSITORY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.javaDbRepository",
										Optional: ptr.To[bool](true),
									},
								},
							},
							timeoutEnv,
							{
								Name: "TUNNEL_SKIP_FILES",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.skipFiles",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name: "TUNNEL_SKIP_DIRS",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.skipDirs",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name: "HTTP_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.httpProxy",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name: "HTTPS_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.httpsProxy",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name: "NO_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.noProxy",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name:  "TUNNEL_IGNOREFILE",
								Value: "/etc/tunnel/.tunnelignore",
							},
						},
						Command: []string{
							"/bin/sh",
						},
						Args: []string{
							"-c",
							"tunnel image --slow 'nginx:1.16' --security-checks vuln,secret --image-config-scanners secret   --skip-update  --cache-dir /tmp/tunnel/.cache --quiet  --format json > /tmp/scan/result_nginx.json &&  bzip2 -c /tmp/scan/result_nginx.json | base64",
						},
						Resources: corev1.ResourceRequirements{
							Requests: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("100m"),
								corev1.ResourceMemory: resource.MustParse("100M"),
							},
							Limits: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("500m"),
								corev1.ResourceMemory: resource.MustParse("500M"),
							},
						},
						VolumeMounts: []corev1.VolumeMount{
							tmpVolumeMount, getScanResultVolumeMount(),
							{
								Name:      "ignorefile",
								MountPath: "/etc/tunnel/.tunnelignore",
								SubPath:   ".tunnelignore",
							},
						},
						SecurityContext: &corev1.SecurityContext{
							Privileged:               ptr.To[bool](false),
							AllowPrivilegeEscalation: ptr.To[bool](false),
							Capabilities: &corev1.Capabilities{
								Drop: []corev1.Capability{"all"},
							},
							ReadOnlyRootFilesystem: ptr.To[bool](true),
						},
					},
				},
				SecurityContext: &corev1.PodSecurityContext{},
			},
		},
		{
			name: "Standalone mode with tunnel ignore policy",
			tunnelOperatorConfig: map[string]string{
				tunneloperator.KeyVulnerabilityScannerEnabled:  "true",
				tunneloperator.KeyExposedSecretsScannerEnabled: "true",
				tunneloperator.KeyScanJobcompressLogs:          "true",
			},
			config: map[string]string{
				"tunnel.repository": "docker.io/khulnasoft/tunnel",
				"tunnel.tag":        "0.35.0",
				"tunnel.mode":       string(tunnel.Standalone),
				"tunnel.ignorePolicy": `package tunnel

import data.lib.tunnel

default ignore = false`,
				"tunnel.dbRepository":              tunnel.DefaultDBRepository,
				"tunnel.javaDbRepository":          tunnel.DefaultJavaDBRepository,
				"tunnel.resources.requests.cpu":    "100m",
				"tunnel.resources.requests.memory": "100M",
				"tunnel.resources.limits.cpu":      "500m",
				"tunnel.resources.limits.memory":   "500M",
			},
			workloadSpec: &corev1.Pod{
				TypeMeta: metav1.TypeMeta{
					Kind:       "Pod",
					APIVersion: "v1",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "nginx",
					Namespace: "prod-ns",
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name:  "nginx",
							Image: "nginx:1.16",
						},
					},
				},
			},
			expectedJobSpec: corev1.PodSpec{
				Affinity:                     tunneloperator.LinuxNodeAffinity(),
				RestartPolicy:                corev1.RestartPolicyNever,
				ServiceAccountName:           "tunneloperator-sa",
				ImagePullSecrets:             []corev1.LocalObjectReference{},
				AutomountServiceAccountToken: ptr.To[bool](false),
				Volumes: []corev1.Volume{
					tmpVolume, getScanResultVolume(),
					{
						Name: "ignorepolicy",
						VolumeSource: corev1.VolumeSource{
							ConfigMap: &corev1.ConfigMapVolumeSource{
								LocalObjectReference: corev1.LocalObjectReference{
									Name: "tunnel-operator-tunnel-config",
								},
								Items: []corev1.KeyToPath{
									{
										Key:  "tunnel.ignorePolicy",
										Path: "policy.rego",
									},
								},
							},
						},
					},
				},
				InitContainers: []corev1.Container{
					{
						Name:                     "00000000-0000-0000-0000-000000000001",
						Image:                    "docker.io/khulnasoft/tunnel:0.35.0",
						ImagePullPolicy:          corev1.PullIfNotPresent,
						TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
						Env: []corev1.EnvVar{
							{
								Name: "HTTP_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.httpProxy",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name: "HTTPS_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.httpsProxy",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name: "NO_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.noProxy",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name: "GITHUB_TOKEN",
								ValueFrom: &corev1.EnvVarSource{
									SecretKeyRef: &corev1.SecretKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.githubToken",
										Optional: ptr.To[bool](true),
									},
								},
							},
						},
						Command: []string{
							"tunnel",
						},
						Args: []string{
							"--cache-dir", "/tmp/tunnel/.cache",
							"image",
							"--download-db-only",
							"--db-repository", tunnel.DefaultDBRepository,
						},
						Resources: corev1.ResourceRequirements{
							Requests: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("100m"),
								corev1.ResourceMemory: resource.MustParse("100M"),
							},
							Limits: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("500m"),
								corev1.ResourceMemory: resource.MustParse("500M"),
							},
						},
						VolumeMounts: []corev1.VolumeMount{
							tmpVolumeMount,
						},
						SecurityContext: &corev1.SecurityContext{
							Privileged:               ptr.To[bool](false),
							AllowPrivilegeEscalation: ptr.To[bool](false),
							Capabilities: &corev1.Capabilities{
								Drop: []corev1.Capability{"all"},
							},
							ReadOnlyRootFilesystem: ptr.To[bool](true),
						},
					},
				},
				Containers: []corev1.Container{
					{
						Name:                     "nginx",
						Image:                    "docker.io/khulnasoft/tunnel:0.35.0",
						ImagePullPolicy:          corev1.PullIfNotPresent,
						TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
						Env: []corev1.EnvVar{
							{
								Name: "TUNNEL_SEVERITY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.severity",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name: "TUNNEL_IGNORE_UNFIXED",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.ignoreUnfixed",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name: "TUNNEL_OFFLINE_SCAN",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.offlineScan",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name: "TUNNEL_JAVA_DB_REPOSITORY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.javaDbRepository",
										Optional: ptr.To[bool](true),
									},
								},
							},
							timeoutEnv,
							{
								Name: "TUNNEL_SKIP_FILES",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.skipFiles",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name: "TUNNEL_SKIP_DIRS",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.skipDirs",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name: "HTTP_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.httpProxy",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name: "HTTPS_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.httpsProxy",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name: "NO_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.noProxy",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name:  "TUNNEL_IGNORE_POLICY",
								Value: "/etc/tunnel/policy.rego",
							},
						},
						Command: []string{
							"/bin/sh",
						},
						Args: []string{
							"-c",
							"tunnel image --slow 'nginx:1.16' --security-checks vuln,secret --image-config-scanners secret   --skip-update  --cache-dir /tmp/tunnel/.cache --quiet  --format json > /tmp/scan/result_nginx.json &&  bzip2 -c /tmp/scan/result_nginx.json | base64",
						},
						Resources: corev1.ResourceRequirements{
							Requests: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("100m"),
								corev1.ResourceMemory: resource.MustParse("100M"),
							},
							Limits: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("500m"),
								corev1.ResourceMemory: resource.MustParse("500M"),
							},
						},
						VolumeMounts: []corev1.VolumeMount{
							tmpVolumeMount, getScanResultVolumeMount(),
							{
								Name:      "ignorepolicy",
								MountPath: "/etc/tunnel/policy.rego",
								SubPath:   "policy.rego",
							},
						},
						SecurityContext: &corev1.SecurityContext{
							Privileged:               ptr.To[bool](false),
							AllowPrivilegeEscalation: ptr.To[bool](false),
							Capabilities: &corev1.Capabilities{
								Drop: []corev1.Capability{"all"},
							},
							ReadOnlyRootFilesystem: ptr.To[bool](true),
						},
					},
				},
				SecurityContext: &corev1.PodSecurityContext{},
			},
		},
		{
			name: "Standalone mode with mirror",
			tunnelOperatorConfig: map[string]string{
				tunneloperator.KeyVulnerabilityScannerEnabled:  "true",
				tunneloperator.KeyExposedSecretsScannerEnabled: "true",
				tunneloperator.KeyScanJobcompressLogs:          "true",
			},
			config: map[string]string{
				"tunnel.repository": "docker.io/khulnasoft/tunnel",
				"tunnel.tag":        "0.35.0",
				"tunnel.mode":       string(tunnel.Standalone),

				"tunnel.dbRepository":              tunnel.DefaultDBRepository,
				"tunnel.javaDbRepository":          tunnel.DefaultJavaDBRepository,
				"tunnel.resources.requests.cpu":    "100m",
				"tunnel.resources.requests.memory": "100M",
				"tunnel.resources.limits.cpu":      "500m",
				"tunnel.resources.limits.memory":   "500M",

				"tunnel.registry.mirror.index.docker.io": "mirror.io",
			},
			workloadSpec: &corev1.Pod{
				TypeMeta: metav1.TypeMeta{
					Kind:       "Pod",
					APIVersion: "v1",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "nginx",
					Namespace: "prod-ns",
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name:  "nginx",
							Image: "nginx:1.16",
						},
					},
				},
			},
			expectedJobSpec: corev1.PodSpec{
				Affinity:                     tunneloperator.LinuxNodeAffinity(),
				RestartPolicy:                corev1.RestartPolicyNever,
				ServiceAccountName:           "tunneloperator-sa",
				ImagePullSecrets:             []corev1.LocalObjectReference{},
				AutomountServiceAccountToken: ptr.To[bool](false),
				Volumes: []corev1.Volume{
					tmpVolume, getScanResultVolume(),
				},
				InitContainers: []corev1.Container{
					{
						Name:                     "00000000-0000-0000-0000-000000000001",
						Image:                    "docker.io/khulnasoft/tunnel:0.35.0",
						ImagePullPolicy:          corev1.PullIfNotPresent,
						TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
						Env: []corev1.EnvVar{
							{
								Name: "HTTP_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.httpProxy",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name: "HTTPS_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.httpsProxy",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name: "NO_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.noProxy",
										Optional: ptr.To[bool](true),
									},
								},
							},

							{
								Name: "GITHUB_TOKEN",
								ValueFrom: &corev1.EnvVarSource{
									SecretKeyRef: &corev1.SecretKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.githubToken",
										Optional: ptr.To[bool](true),
									},
								},
							},
						},
						Command: []string{
							"tunnel",
						},
						Args: []string{
							"--cache-dir", "/tmp/tunnel/.cache",
							"image",
							"--download-db-only",
							"--db-repository", tunnel.DefaultDBRepository,
						},
						Resources: corev1.ResourceRequirements{
							Requests: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("100m"),
								corev1.ResourceMemory: resource.MustParse("100M"),
							},
							Limits: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("500m"),
								corev1.ResourceMemory: resource.MustParse("500M"),
							},
						},
						VolumeMounts: []corev1.VolumeMount{
							tmpVolumeMount,
						},
						SecurityContext: &corev1.SecurityContext{
							Privileged:               ptr.To[bool](false),
							AllowPrivilegeEscalation: ptr.To[bool](false),
							Capabilities: &corev1.Capabilities{
								Drop: []corev1.Capability{"all"},
							},
							ReadOnlyRootFilesystem: ptr.To[bool](true),
						},
					},
				},
				Containers: []corev1.Container{
					{
						Name:                     "nginx",
						Image:                    "docker.io/khulnasoft/tunnel:0.35.0",
						ImagePullPolicy:          corev1.PullIfNotPresent,
						TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
						Env: []corev1.EnvVar{
							{
								Name: "TUNNEL_SEVERITY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.severity",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name: "TUNNEL_IGNORE_UNFIXED",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.ignoreUnfixed",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name: "TUNNEL_OFFLINE_SCAN",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.offlineScan",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name: "TUNNEL_JAVA_DB_REPOSITORY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.javaDbRepository",
										Optional: ptr.To[bool](true),
									},
								},
							},
							timeoutEnv,
							{
								Name: "TUNNEL_SKIP_FILES",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.skipFiles",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name: "TUNNEL_SKIP_DIRS",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.skipDirs",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name: "HTTP_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.httpProxy",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name: "HTTPS_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.httpsProxy",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name: "NO_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.noProxy",
										Optional: ptr.To[bool](true),
									},
								},
							},
						},
						Command: []string{
							"/bin/sh",
						},
						Args: []string{
							"-c",
							"tunnel image --slow 'mirror.io/library/nginx:1.16' --security-checks vuln,secret --image-config-scanners secret   --skip-update  --cache-dir /tmp/tunnel/.cache --quiet  --format json > /tmp/scan/result_nginx.json &&  bzip2 -c /tmp/scan/result_nginx.json | base64",
						},
						Resources: corev1.ResourceRequirements{
							Requests: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("100m"),
								corev1.ResourceMemory: resource.MustParse("100M"),
							},
							Limits: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("500m"),
								corev1.ResourceMemory: resource.MustParse("500M"),
							},
						},
						VolumeMounts: []corev1.VolumeMount{
							tmpVolumeMount, getScanResultVolumeMount(),
						},
						SecurityContext: &corev1.SecurityContext{
							Privileged:               ptr.To[bool](false),
							AllowPrivilegeEscalation: ptr.To[bool](false),
							Capabilities: &corev1.Capabilities{
								Drop: []corev1.Capability{"all"},
							},
							ReadOnlyRootFilesystem: ptr.To[bool](true),
						},
					},
				},
				SecurityContext: &corev1.PodSecurityContext{},
			},
		},
		{
			name: "Standalone mode with custom db repositories",
			tunnelOperatorConfig: map[string]string{
				tunneloperator.KeyVulnerabilityScannerEnabled:  "true",
				tunneloperator.KeyExposedSecretsScannerEnabled: "true",
				tunneloperator.KeyScanJobcompressLogs:          "true",
			},
			config: map[string]string{
				"tunnel.repository":                "docker.io/khulnasoft/tunnel",
				"tunnel.tag":                       "0.35.0",
				"tunnel.mode":                      string(tunnel.Standalone),
				"tunnel.dbRepository":              "custom-registry.com/mirror/tunnel-db",
				"tunnel.javaDbRepository":          "custom-registry.com/mirror/tunnel-java-db",
				"tunnel.resources.requests.cpu":    "100m",
				"tunnel.resources.requests.memory": "100M",
				"tunnel.resources.limits.cpu":      "500m",
				"tunnel.resources.limits.memory":   "500M",
			},
			workloadSpec: &appsv1.ReplicaSet{
				TypeMeta: metav1.TypeMeta{
					Kind:       "ReplicaSet",
					APIVersion: "apps/v1",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "nginx-6799fc88d8",
					Namespace: "prod-ns",
				},
				Spec: appsv1.ReplicaSetSpec{
					Template: corev1.PodTemplateSpec{
						Spec: corev1.PodSpec{
							Containers: []corev1.Container{
								{
									Name:  "nginx",
									Image: "nginx:1.16",
								},
							},
						},
					},
				},
			},
			expectedJobSpec: corev1.PodSpec{
				Affinity:                     tunneloperator.LinuxNodeAffinity(),
				RestartPolicy:                corev1.RestartPolicyNever,
				ServiceAccountName:           "tunneloperator-sa",
				ImagePullSecrets:             []corev1.LocalObjectReference{},
				AutomountServiceAccountToken: ptr.To[bool](false),
				Volumes: []corev1.Volume{
					tmpVolume, getScanResultVolume(),
				},
				InitContainers: []corev1.Container{
					{
						Name:                     "00000000-0000-0000-0000-000000000001",
						Image:                    "docker.io/khulnasoft/tunnel:0.35.0",
						ImagePullPolicy:          corev1.PullIfNotPresent,
						TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
						Env: []corev1.EnvVar{
							{
								Name: "HTTP_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.httpProxy",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name: "HTTPS_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.httpsProxy",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name: "NO_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.noProxy",
										Optional: ptr.To[bool](true),
									},
								},
							},

							{
								Name: "GITHUB_TOKEN",
								ValueFrom: &corev1.EnvVarSource{
									SecretKeyRef: &corev1.SecretKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.githubToken",
										Optional: ptr.To[bool](true),
									},
								},
							},
						},
						Command: []string{
							"tunnel",
						},
						Args: []string{
							"--cache-dir", "/tmp/tunnel/.cache",
							"image",
							"--download-db-only",
							"--db-repository", "custom-registry.com/mirror/tunnel-db",
						},
						Resources: corev1.ResourceRequirements{
							Requests: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("100m"),
								corev1.ResourceMemory: resource.MustParse("100M"),
							},
							Limits: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("500m"),
								corev1.ResourceMemory: resource.MustParse("500M"),
							},
						},
						VolumeMounts: []corev1.VolumeMount{
							tmpVolumeMount,
						},
						SecurityContext: &corev1.SecurityContext{
							Privileged:               ptr.To[bool](false),
							AllowPrivilegeEscalation: ptr.To[bool](false),
							Capabilities: &corev1.Capabilities{
								Drop: []corev1.Capability{"all"},
							},
							ReadOnlyRootFilesystem: ptr.To[bool](true),
						},
					},
				},
				Containers: []corev1.Container{
					{
						Name:                     "nginx",
						Image:                    "docker.io/khulnasoft/tunnel:0.35.0",
						ImagePullPolicy:          corev1.PullIfNotPresent,
						TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
						Env: []corev1.EnvVar{
							{
								Name: "TUNNEL_SEVERITY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.severity",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name: "TUNNEL_IGNORE_UNFIXED",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.ignoreUnfixed",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name: "TUNNEL_OFFLINE_SCAN",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.offlineScan",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name: "TUNNEL_JAVA_DB_REPOSITORY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.javaDbRepository",
										Optional: ptr.To[bool](true),
									},
								},
							},
							timeoutEnv,
							{
								Name: "TUNNEL_SKIP_FILES",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.skipFiles",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name: "TUNNEL_SKIP_DIRS",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.skipDirs",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name: "HTTP_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.httpProxy",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name: "HTTPS_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.httpsProxy",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name: "NO_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.noProxy",
										Optional: ptr.To[bool](true),
									},
								},
							},
						},
						Command: []string{
							"/bin/sh",
						},
						Args: []string{
							"-c",
							"tunnel image --slow 'nginx:1.16' --security-checks vuln,secret --image-config-scanners secret   --skip-update  --cache-dir /tmp/tunnel/.cache --quiet  --format json > /tmp/scan/result_nginx.json &&  bzip2 -c /tmp/scan/result_nginx.json | base64",
						},
						Resources: corev1.ResourceRequirements{
							Requests: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("100m"),
								corev1.ResourceMemory: resource.MustParse("100M"),
							},
							Limits: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("500m"),
								corev1.ResourceMemory: resource.MustParse("500M"),
							},
						},
						VolumeMounts: []corev1.VolumeMount{
							tmpVolumeMount, getScanResultVolumeMount(),
						},
						SecurityContext: &corev1.SecurityContext{
							Privileged:               ptr.To[bool](false),
							AllowPrivilegeEscalation: ptr.To[bool](false),
							Capabilities: &corev1.Capabilities{
								Drop: []corev1.Capability{"all"},
							},
							ReadOnlyRootFilesystem: ptr.To[bool](true),
						},
					},
				},
				SecurityContext: &corev1.PodSecurityContext{},
			},
		},
		{
			name: "ClientServer mode without insecure registry",
			tunnelOperatorConfig: map[string]string{
				tunneloperator.KeyVulnerabilityScannerEnabled:  "true",
				tunneloperator.KeyExposedSecretsScannerEnabled: "true",
				tunneloperator.KeyScanJobcompressLogs:          "true",
			},
			config: map[string]string{
				"tunnel.repository":                "docker.io/khulnasoft/tunnel",
				"tunnel.tag":                       "0.35.0",
				"tunnel.mode":                      string(tunnel.ClientServer),
				"tunnel.serverURL":                 "http://tunnel.tunnel:4954",
				"tunnel.dbRepository":              tunnel.DefaultDBRepository,
				"tunnel.javaDbRepository":          tunnel.DefaultJavaDBRepository,
				"tunnel.resources.requests.cpu":    "100m",
				"tunnel.resources.requests.memory": "100M",
				"tunnel.resources.limits.cpu":      "500m",
				"tunnel.resources.limits.memory":   "500M",
			},
			workloadSpec: &corev1.Pod{
				TypeMeta: metav1.TypeMeta{
					Kind:       "Pod",
					APIVersion: "v1",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "nginx",
					Namespace: "prod-ns",
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name:  "nginx",
							Image: "nginx:1.16",
						},
					},
				},
			},
			expectedJobSpec: corev1.PodSpec{
				Affinity:                     tunneloperator.LinuxNodeAffinity(),
				RestartPolicy:                corev1.RestartPolicyNever,
				ServiceAccountName:           "tunneloperator-sa",
				ImagePullSecrets:             []corev1.LocalObjectReference{},
				AutomountServiceAccountToken: ptr.To[bool](false),
				Volumes: []corev1.Volume{getTmpVolume(),
					getScanResultVolume(),
				},
				Containers: []corev1.Container{
					{
						Name:                     "nginx",
						Image:                    "docker.io/khulnasoft/tunnel:0.35.0",
						ImagePullPolicy:          corev1.PullIfNotPresent,
						TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
						Env: []corev1.EnvVar{
							{
								Name: "HTTP_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.httpProxy",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name: "HTTPS_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.httpsProxy",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name: "NO_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.noProxy",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name: "TUNNEL_SEVERITY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.severity",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name: "TUNNEL_IGNORE_UNFIXED",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.ignoreUnfixed",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name: "TUNNEL_OFFLINE_SCAN",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.offlineScan",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name: "TUNNEL_JAVA_DB_REPOSITORY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.javaDbRepository",
										Optional: ptr.To[bool](true),
									},
								},
							},
							timeoutEnv,
							{
								Name: "TUNNEL_SKIP_FILES",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.skipFiles",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name: "TUNNEL_SKIP_DIRS",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.skipDirs",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name: "TUNNEL_TOKEN_HEADER",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.serverTokenHeader",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name: "TUNNEL_TOKEN",
								ValueFrom: &corev1.EnvVarSource{
									SecretKeyRef: &corev1.SecretKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.serverToken",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name: "TUNNEL_CUSTOM_HEADERS",
								ValueFrom: &corev1.EnvVarSource{
									SecretKeyRef: &corev1.SecretKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.serverCustomHeaders",
										Optional: ptr.To[bool](true),
									},
								},
							},
						},
						Command: []string{
							"/bin/sh",
						},
						Args: []string{
							"-c",
							"tunnel image --slow 'nginx:1.16' --security-checks vuln,secret --image-config-scanners secret     --cache-dir /tmp/tunnel/.cache --quiet  --format json --server 'http://tunnel.tunnel:4954' > /tmp/scan/result_nginx.json &&  bzip2 -c /tmp/scan/result_nginx.json | base64",
						},
						Resources: corev1.ResourceRequirements{
							Requests: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("100m"),
								corev1.ResourceMemory: resource.MustParse("100M"),
							},
							Limits: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("500m"),
								corev1.ResourceMemory: resource.MustParse("500M"),
							},
						},
						VolumeMounts: []corev1.VolumeMount{getTmpVolumeMount(), getScanResultVolumeMount()},
						SecurityContext: &corev1.SecurityContext{
							Privileged:               ptr.To[bool](false),
							AllowPrivilegeEscalation: ptr.To[bool](false),
							Capabilities: &corev1.Capabilities{
								Drop: []corev1.Capability{"all"},
							},
							ReadOnlyRootFilesystem: ptr.To[bool](true),
						},
					},
				},
			},
		},
		{
			name: "ClientServer mode without insecure registry",
			tunnelOperatorConfig: map[string]string{
				tunneloperator.KeyVulnerabilityScannerEnabled:  "true",
				tunneloperator.KeyExposedSecretsScannerEnabled: "true",
				tunneloperator.KeyScanJobcompressLogs:          "true",
			},
			config: map[string]string{
				"tunnel.repository":                "docker.io/khulnasoft/tunnel",
				"tunnel.tag":                       "0.35.0",
				"tunnel.mode":                      string(tunnel.ClientServer),
				"tunnel.serverURL":                 "http://tunnel.tunnel:4954",
				"tunnel.dbRepository":              tunnel.DefaultDBRepository,
				"tunnel.javaDbRepository":          tunnel.DefaultJavaDBRepository,
				"tunnel.resources.requests.cpu":    "100m",
				"tunnel.resources.requests.memory": "100M",
				"tunnel.resources.limits.cpu":      "500m",
				"tunnel.resources.limits.memory":   "500M",
			},
			workloadSpec: &corev1.Pod{
				TypeMeta: metav1.TypeMeta{
					Kind:       "Pod",
					APIVersion: "v1",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "nginx",
					Namespace: "prod-ns",
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name:  "nginx",
							Image: "nginx:1.16",
						},
					},
				},
			},
			expectedJobSpec: corev1.PodSpec{
				Affinity:                     tunneloperator.LinuxNodeAffinity(),
				RestartPolicy:                corev1.RestartPolicyNever,
				ImagePullSecrets:             []corev1.LocalObjectReference{},
				ServiceAccountName:           "tunneloperator-sa",
				AutomountServiceAccountToken: ptr.To[bool](false),
				Volumes: []corev1.Volume{getTmpVolume(),
					getScanResultVolume(),
				},
				Containers: []corev1.Container{
					{
						Name:                     "nginx",
						Image:                    "docker.io/khulnasoft/tunnel:0.35.0",
						ImagePullPolicy:          corev1.PullIfNotPresent,
						TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
						Env: []corev1.EnvVar{
							{
								Name: "HTTP_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.httpProxy",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name: "HTTPS_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.httpsProxy",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name: "NO_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.noProxy",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name: "TUNNEL_SEVERITY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.severity",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name: "TUNNEL_IGNORE_UNFIXED",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.ignoreUnfixed",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name: "TUNNEL_OFFLINE_SCAN",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.offlineScan",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name: "TUNNEL_JAVA_DB_REPOSITORY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.javaDbRepository",
										Optional: ptr.To[bool](true),
									},
								},
							},
							timeoutEnv,
							{
								Name: "TUNNEL_SKIP_FILES",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.skipFiles",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name: "TUNNEL_SKIP_DIRS",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.skipDirs",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name: "TUNNEL_TOKEN_HEADER",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.serverTokenHeader",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name: "TUNNEL_TOKEN",
								ValueFrom: &corev1.EnvVarSource{
									SecretKeyRef: &corev1.SecretKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.serverToken",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name: "TUNNEL_CUSTOM_HEADERS",
								ValueFrom: &corev1.EnvVarSource{
									SecretKeyRef: &corev1.SecretKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.serverCustomHeaders",
										Optional: ptr.To[bool](true),
									},
								},
							},
						},
						Command: []string{
							"/bin/sh",
						},
						Args: []string{
							"-c",
							"tunnel image --slow 'nginx:1.16' --security-checks vuln,secret --image-config-scanners secret     --cache-dir /tmp/tunnel/.cache --quiet  --format json --server 'http://tunnel.tunnel:4954' > /tmp/scan/result_nginx.json &&  bzip2 -c /tmp/scan/result_nginx.json | base64",
						},
						Resources: corev1.ResourceRequirements{
							Requests: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("100m"),
								corev1.ResourceMemory: resource.MustParse("100M"),
							},
							Limits: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("500m"),
								corev1.ResourceMemory: resource.MustParse("500M"),
							},
						},
						VolumeMounts: []corev1.VolumeMount{getTmpVolumeMount(), getScanResultVolumeMount()},
						SecurityContext: &corev1.SecurityContext{
							Privileged:               ptr.To[bool](false),
							AllowPrivilegeEscalation: ptr.To[bool](false),
							Capabilities: &corev1.Capabilities{
								Drop: []corev1.Capability{"all"},
							},
							ReadOnlyRootFilesystem: ptr.To[bool](true),
						},
					},
				},
			},
		},
		{
			name: "ClientServer mode with insecure server",
			tunnelOperatorConfig: map[string]string{
				tunneloperator.KeyVulnerabilityScannerEnabled:  "true",
				tunneloperator.KeyExposedSecretsScannerEnabled: "true",
				tunneloperator.KeyScanJobcompressLogs:          "true",
			},
			config: map[string]string{
				"tunnel.repository":                "docker.io/khulnasoft/tunnel",
				"tunnel.tag":                       "0.35.0",
				"tunnel.mode":                      string(tunnel.ClientServer),
				"tunnel.serverURL":                 "https://tunnel.tunnel:4954",
				"tunnel.serverInsecure":            "true",
				"tunnel.dbRepository":              tunnel.DefaultDBRepository,
				"tunnel.javaDbRepository":          tunnel.DefaultJavaDBRepository,
				"tunnel.resources.requests.cpu":    "100m",
				"tunnel.resources.requests.memory": "100M",
				"tunnel.resources.limits.cpu":      "500m",
				"tunnel.resources.limits.memory":   "500M",
			},
			workloadSpec: &corev1.Pod{
				TypeMeta: metav1.TypeMeta{
					Kind:       "Pod",
					APIVersion: "v1",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "nginx",
					Namespace: "prod-ns",
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name:  "nginx",
							Image: "poc.myregistry.harbor.com.pl/nginx:1.16",
						},
					},
				},
			},
			expectedJobSpec: corev1.PodSpec{
				Affinity:                     tunneloperator.LinuxNodeAffinity(),
				RestartPolicy:                corev1.RestartPolicyNever,
				ServiceAccountName:           "tunneloperator-sa",
				ImagePullSecrets:             []corev1.LocalObjectReference{},
				AutomountServiceAccountToken: ptr.To[bool](false),
				Volumes: []corev1.Volume{getTmpVolume(),
					getScanResultVolume(),
				},
				Containers: []corev1.Container{
					{
						Name:                     "nginx",
						Image:                    "docker.io/khulnasoft/tunnel:0.35.0",
						ImagePullPolicy:          corev1.PullIfNotPresent,
						TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
						Env: []corev1.EnvVar{
							{
								Name: "HTTP_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.httpProxy",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name: "HTTPS_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.httpsProxy",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name: "NO_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.noProxy",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name: "TUNNEL_SEVERITY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.severity",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name: "TUNNEL_IGNORE_UNFIXED",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.ignoreUnfixed",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name: "TUNNEL_OFFLINE_SCAN",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.offlineScan",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name: "TUNNEL_JAVA_DB_REPOSITORY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.javaDbRepository",
										Optional: ptr.To[bool](true),
									},
								},
							},
							timeoutEnv,
							{
								Name: "TUNNEL_SKIP_FILES",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.skipFiles",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name: "TUNNEL_SKIP_DIRS",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.skipDirs",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name: "TUNNEL_TOKEN_HEADER",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.serverTokenHeader",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name: "TUNNEL_TOKEN",
								ValueFrom: &corev1.EnvVarSource{
									SecretKeyRef: &corev1.SecretKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.serverToken",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name: "TUNNEL_CUSTOM_HEADERS",
								ValueFrom: &corev1.EnvVarSource{
									SecretKeyRef: &corev1.SecretKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.serverCustomHeaders",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name:  "TUNNEL_INSECURE",
								Value: "true",
							},
						},
						Command: []string{
							"/bin/sh",
						},
						Args: []string{
							"-c",
							"tunnel image --slow 'poc.myregistry.harbor.com.pl/nginx:1.16' --security-checks vuln,secret --image-config-scanners secret     --cache-dir /tmp/tunnel/.cache --quiet  --format json --server 'https://tunnel.tunnel:4954' > /tmp/scan/result_nginx.json &&  bzip2 -c /tmp/scan/result_nginx.json | base64",
						},
						Resources: corev1.ResourceRequirements{
							Requests: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("100m"),
								corev1.ResourceMemory: resource.MustParse("100M"),
							},
							Limits: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("500m"),
								corev1.ResourceMemory: resource.MustParse("500M"),
							},
						},
						VolumeMounts: []corev1.VolumeMount{getTmpVolumeMount(), getScanResultVolumeMount()},
						SecurityContext: &corev1.SecurityContext{
							Privileged:               ptr.To[bool](false),
							AllowPrivilegeEscalation: ptr.To[bool](false),
							Capabilities: &corev1.Capabilities{
								Drop: []corev1.Capability{"all"},
							},
							ReadOnlyRootFilesystem: ptr.To[bool](true),
						},
					},
				},
			},
		},
		{
			name: "ClientServer mode with non-SSL registry",
			tunnelOperatorConfig: map[string]string{
				tunneloperator.KeyVulnerabilityScannerEnabled:  "true",
				tunneloperator.KeyExposedSecretsScannerEnabled: "false",
				tunneloperator.KeyScanJobcompressLogs:          "true",
			},
			config: map[string]string{
				"tunnel.repository":                 "docker.io/khulnasoft/tunnel",
				"tunnel.tag":                        "0.35.0",
				"tunnel.mode":                       string(tunnel.ClientServer),
				"tunnel.serverURL":                  "http://tunnel.tunnel:4954",
				"tunnel.nonSslRegistry.pocRegistry": "poc.myregistry.harbor.com.pl",
				"tunnel.dbRepository":               tunnel.DefaultDBRepository,
				"tunnel.javaDbRepository":           tunnel.DefaultJavaDBRepository,
				"tunnel.resources.requests.cpu":     "100m",
				"tunnel.resources.requests.memory":  "100M",
				"tunnel.resources.limits.cpu":       "500m",
				"tunnel.resources.limits.memory":    "500M",
			},
			workloadSpec: &corev1.Pod{
				TypeMeta: metav1.TypeMeta{
					Kind:       "Pod",
					APIVersion: "v1",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "nginx",
					Namespace: "prod-ns",
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name:  "nginx",
							Image: "poc.myregistry.harbor.com.pl/nginx:1.16",
						},
					},
				},
			},
			expectedJobSpec: corev1.PodSpec{
				Affinity:                     tunneloperator.LinuxNodeAffinity(),
				RestartPolicy:                corev1.RestartPolicyNever,
				ServiceAccountName:           "tunneloperator-sa",
				ImagePullSecrets:             []corev1.LocalObjectReference{},
				AutomountServiceAccountToken: ptr.To[bool](false),
				Volumes: []corev1.Volume{getTmpVolume(),
					getScanResultVolume(),
				},
				Containers: []corev1.Container{
					{
						Name:                     "nginx",
						Image:                    "docker.io/khulnasoft/tunnel:0.35.0",
						ImagePullPolicy:          corev1.PullIfNotPresent,
						TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
						Env: []corev1.EnvVar{
							{
								Name: "HTTP_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.httpProxy",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name: "HTTPS_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.httpsProxy",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name: "NO_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.noProxy",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name: "TUNNEL_SEVERITY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.severity",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name: "TUNNEL_IGNORE_UNFIXED",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.ignoreUnfixed",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name: "TUNNEL_OFFLINE_SCAN",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.offlineScan",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name: "TUNNEL_JAVA_DB_REPOSITORY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.javaDbRepository",
										Optional: ptr.To[bool](true),
									},
								},
							},
							timeoutEnv,
							{
								Name: "TUNNEL_SKIP_FILES",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.skipFiles",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name: "TUNNEL_SKIP_DIRS",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.skipDirs",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name: "TUNNEL_TOKEN_HEADER",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.serverTokenHeader",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name: "TUNNEL_TOKEN",
								ValueFrom: &corev1.EnvVarSource{
									SecretKeyRef: &corev1.SecretKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.serverToken",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name: "TUNNEL_CUSTOM_HEADERS",
								ValueFrom: &corev1.EnvVarSource{
									SecretKeyRef: &corev1.SecretKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.serverCustomHeaders",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name:  "TUNNEL_NON_SSL",
								Value: "true",
							},
						},
						Command: []string{
							"/bin/sh",
						},
						Args: []string{
							"-c",
							"tunnel image --slow 'poc.myregistry.harbor.com.pl/nginx:1.16' --security-checks vuln     --cache-dir /tmp/tunnel/.cache --quiet  --format json --server 'http://tunnel.tunnel:4954' > /tmp/scan/result_nginx.json &&  bzip2 -c /tmp/scan/result_nginx.json | base64",
						},
						Resources: corev1.ResourceRequirements{
							Requests: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("100m"),
								corev1.ResourceMemory: resource.MustParse("100M"),
							},
							Limits: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("500m"),
								corev1.ResourceMemory: resource.MustParse("500M"),
							},
						},
						VolumeMounts: []corev1.VolumeMount{getTmpVolumeMount(), getScanResultVolumeMount()},
						SecurityContext: &corev1.SecurityContext{
							Privileged:               ptr.To[bool](false),
							AllowPrivilegeEscalation: ptr.To[bool](false),
							Capabilities: &corev1.Capabilities{
								Drop: []corev1.Capability{"all"},
							},
							ReadOnlyRootFilesystem: ptr.To[bool](true),
						},
					},
				},
			},
		},
		{
			name: "ClientServer mode with tunnelignore file",
			tunnelOperatorConfig: map[string]string{
				tunneloperator.KeyVulnerabilityScannerEnabled:  "false",
				tunneloperator.KeyExposedSecretsScannerEnabled: "true",
				tunneloperator.KeyScanJobcompressLogs:          "true",
			},
			config: map[string]string{
				"tunnel.repository": "docker.io/khulnasoft/tunnel",
				"tunnel.tag":        "0.35.0",
				"tunnel.mode":       string(tunnel.ClientServer),
				"tunnel.serverURL":  "http://tunnel.tunnel:4954",
				"tunnel.ignoreFile": `# Accept the risk
CVE-2018-14618

# No impact in our settings
CVE-2019-1543`,
				"tunnel.dbRepository":              tunnel.DefaultDBRepository,
				"tunnel.javaDbRepository":          tunnel.DefaultJavaDBRepository,
				"tunnel.resources.requests.cpu":    "100m",
				"tunnel.resources.requests.memory": "100M",
				"tunnel.resources.limits.cpu":      "500m",
				"tunnel.resources.limits.memory":   "500M",
			},
			workloadSpec: &corev1.Pod{
				TypeMeta: metav1.TypeMeta{
					Kind:       "Pod",
					APIVersion: "v1",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "nginx",
					Namespace: "prod-ns",
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name:  "nginx",
							Image: "nginx:1.16",
						},
					},
				},
			},
			expectedJobSpec: corev1.PodSpec{
				Affinity:                     tunneloperator.LinuxNodeAffinity(),
				RestartPolicy:                corev1.RestartPolicyNever,
				ServiceAccountName:           "tunneloperator-sa",
				ImagePullSecrets:             []corev1.LocalObjectReference{},
				AutomountServiceAccountToken: ptr.To[bool](false),

				Volumes: []corev1.Volume{getTmpVolume(), getScanResultVolume(),
					{
						Name: "ignorefile",
						VolumeSource: corev1.VolumeSource{
							ConfigMap: &corev1.ConfigMapVolumeSource{
								LocalObjectReference: corev1.LocalObjectReference{
									Name: "tunnel-operator-tunnel-config",
								},
								Items: []corev1.KeyToPath{
									{
										Key:  "tunnel.ignoreFile",
										Path: ".tunnelignore",
									},
								},
							},
						},
					},
				},
				Containers: []corev1.Container{
					{
						Name:                     "nginx",
						Image:                    "docker.io/khulnasoft/tunnel:0.35.0",
						ImagePullPolicy:          corev1.PullIfNotPresent,
						TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
						Env: []corev1.EnvVar{
							{
								Name: "HTTP_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.httpProxy",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name: "HTTPS_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.httpsProxy",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name: "NO_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.noProxy",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name: "TUNNEL_SEVERITY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.severity",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name: "TUNNEL_IGNORE_UNFIXED",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.ignoreUnfixed",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name: "TUNNEL_OFFLINE_SCAN",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.offlineScan",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name: "TUNNEL_JAVA_DB_REPOSITORY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.javaDbRepository",
										Optional: ptr.To[bool](true),
									},
								},
							},
							timeoutEnv,
							{
								Name: "TUNNEL_SKIP_FILES",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.skipFiles",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name: "TUNNEL_SKIP_DIRS",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.skipDirs",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name: "TUNNEL_TOKEN_HEADER",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.serverTokenHeader",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name: "TUNNEL_TOKEN",
								ValueFrom: &corev1.EnvVarSource{
									SecretKeyRef: &corev1.SecretKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.serverToken",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name: "TUNNEL_CUSTOM_HEADERS",
								ValueFrom: &corev1.EnvVarSource{
									SecretKeyRef: &corev1.SecretKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.serverCustomHeaders",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name:  "TUNNEL_IGNOREFILE",
								Value: "/etc/tunnel/.tunnelignore",
							},
						},
						Command: []string{
							"/bin/sh",
						},
						Args: []string{
							"-c",
							"tunnel image --slow 'nginx:1.16' --security-checks secret --image-config-scanners secret     --cache-dir /tmp/tunnel/.cache --quiet  --format json --server 'http://tunnel.tunnel:4954' > /tmp/scan/result_nginx.json &&  bzip2 -c /tmp/scan/result_nginx.json | base64",
						},
						Resources: corev1.ResourceRequirements{
							Requests: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("100m"),
								corev1.ResourceMemory: resource.MustParse("100M"),
							},
							Limits: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("500m"),
								corev1.ResourceMemory: resource.MustParse("500M"),
							},
						},
						VolumeMounts: []corev1.VolumeMount{getTmpVolumeMount(), getScanResultVolumeMount(),
							{
								Name:      "ignorefile",
								MountPath: "/etc/tunnel/.tunnelignore",
								SubPath:   ".tunnelignore",
							},
						},
						SecurityContext: &corev1.SecurityContext{
							Privileged:               ptr.To[bool](false),
							AllowPrivilegeEscalation: ptr.To[bool](false),
							Capabilities: &corev1.Capabilities{
								Drop: []corev1.Capability{"all"},
							},
							ReadOnlyRootFilesystem: ptr.To[bool](true),
						},
					},
				},
			},
		},
		{
			name: "ClientServer mode with tunnel ignore policy",
			tunnelOperatorConfig: map[string]string{
				tunneloperator.KeyVulnerabilityScannerEnabled:  "false",
				tunneloperator.KeyExposedSecretsScannerEnabled: "true",
				tunneloperator.KeyScanJobcompressLogs:          "true",
			},
			config: map[string]string{
				"tunnel.repository": "docker.io/khulnasoft/tunnel",
				"tunnel.tag":        "0.35.0",
				"tunnel.mode":       string(tunnel.ClientServer),
				"tunnel.serverURL":  "http://tunnel.tunnel:4954",
				"tunnel.ignorePolicy": `package tunnel

import data.lib.tunnel

default ignore = false`,
				"tunnel.dbRepository":              tunnel.DefaultDBRepository,
				"tunnel.javaDbRepository":          tunnel.DefaultJavaDBRepository,
				"tunnel.resources.requests.cpu":    "100m",
				"tunnel.resources.requests.memory": "100M",
				"tunnel.resources.limits.cpu":      "500m",
				"tunnel.resources.limits.memory":   "500M",
			},
			workloadSpec: &corev1.Pod{
				TypeMeta: metav1.TypeMeta{
					Kind:       "Pod",
					APIVersion: "v1",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "nginx",
					Namespace: "prod-ns",
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name:  "nginx",
							Image: "nginx:1.16",
						},
					},
				},
			},
			expectedJobSpec: corev1.PodSpec{
				Affinity:                     tunneloperator.LinuxNodeAffinity(),
				RestartPolicy:                corev1.RestartPolicyNever,
				ServiceAccountName:           "tunneloperator-sa",
				ImagePullSecrets:             []corev1.LocalObjectReference{},
				AutomountServiceAccountToken: ptr.To[bool](false),

				Volumes: []corev1.Volume{getTmpVolume(), getScanResultVolume(),
					{
						Name: "ignorepolicy",
						VolumeSource: corev1.VolumeSource{
							ConfigMap: &corev1.ConfigMapVolumeSource{
								LocalObjectReference: corev1.LocalObjectReference{
									Name: "tunnel-operator-tunnel-config",
								},
								Items: []corev1.KeyToPath{
									{
										Key:  "tunnel.ignorePolicy",
										Path: "policy.rego",
									},
								},
							},
						},
					},
				},
				Containers: []corev1.Container{
					{
						Name:                     "nginx",
						Image:                    "docker.io/khulnasoft/tunnel:0.35.0",
						ImagePullPolicy:          corev1.PullIfNotPresent,
						TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
						Env: []corev1.EnvVar{
							{
								Name: "HTTP_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.httpProxy",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name: "HTTPS_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.httpsProxy",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name: "NO_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.noProxy",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name: "TUNNEL_SEVERITY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.severity",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name: "TUNNEL_IGNORE_UNFIXED",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.ignoreUnfixed",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name: "TUNNEL_OFFLINE_SCAN",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.offlineScan",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name: "TUNNEL_JAVA_DB_REPOSITORY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.javaDbRepository",
										Optional: ptr.To[bool](true),
									},
								},
							},
							timeoutEnv,
							{
								Name: "TUNNEL_SKIP_FILES",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.skipFiles",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name: "TUNNEL_SKIP_DIRS",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.skipDirs",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name: "TUNNEL_TOKEN_HEADER",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.serverTokenHeader",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name: "TUNNEL_TOKEN",
								ValueFrom: &corev1.EnvVarSource{
									SecretKeyRef: &corev1.SecretKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.serverToken",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name: "TUNNEL_CUSTOM_HEADERS",
								ValueFrom: &corev1.EnvVarSource{
									SecretKeyRef: &corev1.SecretKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.serverCustomHeaders",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name:  "TUNNEL_IGNORE_POLICY",
								Value: "/etc/tunnel/policy.rego",
							},
						},
						Command: []string{
							"/bin/sh",
						},
						Args: []string{
							"-c",
							"tunnel image --slow 'nginx:1.16' --security-checks secret --image-config-scanners secret     --cache-dir /tmp/tunnel/.cache --quiet  --format json --server 'http://tunnel.tunnel:4954' > /tmp/scan/result_nginx.json &&  bzip2 -c /tmp/scan/result_nginx.json | base64",
						},
						Resources: corev1.ResourceRequirements{
							Requests: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("100m"),
								corev1.ResourceMemory: resource.MustParse("100M"),
							},
							Limits: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("500m"),
								corev1.ResourceMemory: resource.MustParse("500M"),
							},
						},
						VolumeMounts: []corev1.VolumeMount{getTmpVolumeMount(), getScanResultVolumeMount(),
							{
								Name:      "ignorepolicy",
								MountPath: "/etc/tunnel/policy.rego",
								SubPath:   "policy.rego",
							},
						},
						SecurityContext: &corev1.SecurityContext{
							Privileged:               ptr.To[bool](false),
							AllowPrivilegeEscalation: ptr.To[bool](false),
							Capabilities: &corev1.Capabilities{
								Drop: []corev1.Capability{"all"},
							},
							ReadOnlyRootFilesystem: ptr.To[bool](true),
						},
					},
				},
			},
		},
		{
			name: "ClientServer mode with custom db repositories",
			tunnelOperatorConfig: map[string]string{
				tunneloperator.KeyVulnerabilityScannerEnabled:  "true",
				tunneloperator.KeyExposedSecretsScannerEnabled: "true",
				tunneloperator.KeyScanJobcompressLogs:          "true",
			},
			config: map[string]string{
				"tunnel.repository":                "docker.io/khulnasoft/tunnel",
				"tunnel.tag":                       "0.35.0",
				"tunnel.mode":                      string(tunnel.ClientServer),
				"tunnel.serverURL":                 "http://tunnel.tunnel:4954",
				"tunnel.dbRepository":              "custom-registry.com/mirror/tunnel-db",
				"tunnel.javaDbRepository":          "custom-registry.com/mirror/tunnel-java-db",
				"tunnel.resources.requests.cpu":    "100m",
				"tunnel.resources.requests.memory": "100M",
				"tunnel.resources.limits.cpu":      "500m",
				"tunnel.resources.limits.memory":   "500M",
			},
			workloadSpec: &corev1.Pod{
				TypeMeta: metav1.TypeMeta{
					Kind:       "Pod",
					APIVersion: "v1",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "nginx",
					Namespace: "prod-ns",
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name:  "nginx",
							Image: "nginx:1.16",
						},
					},
				},
			},
			expectedJobSpec: corev1.PodSpec{
				Affinity:                     tunneloperator.LinuxNodeAffinity(),
				RestartPolicy:                corev1.RestartPolicyNever,
				ServiceAccountName:           "tunneloperator-sa",
				ImagePullSecrets:             []corev1.LocalObjectReference{},
				AutomountServiceAccountToken: ptr.To[bool](false),
				Volumes: []corev1.Volume{getTmpVolume(),
					getScanResultVolume(),
				},
				Containers: []corev1.Container{
					{
						Name:                     "nginx",
						Image:                    "docker.io/khulnasoft/tunnel:0.35.0",
						ImagePullPolicy:          corev1.PullIfNotPresent,
						TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
						Env: []corev1.EnvVar{
							{
								Name: "HTTP_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.httpProxy",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name: "HTTPS_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.httpsProxy",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name: "NO_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.noProxy",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name: "TUNNEL_SEVERITY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.severity",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name: "TUNNEL_IGNORE_UNFIXED",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.ignoreUnfixed",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name: "TUNNEL_OFFLINE_SCAN",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.offlineScan",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name: "TUNNEL_JAVA_DB_REPOSITORY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.javaDbRepository",
										Optional: ptr.To[bool](true),
									},
								},
							},
							timeoutEnv,
							{
								Name: "TUNNEL_SKIP_FILES",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.skipFiles",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name: "TUNNEL_SKIP_DIRS",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.skipDirs",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name: "TUNNEL_TOKEN_HEADER",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.serverTokenHeader",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name: "TUNNEL_TOKEN",
								ValueFrom: &corev1.EnvVarSource{
									SecretKeyRef: &corev1.SecretKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.serverToken",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name: "TUNNEL_CUSTOM_HEADERS",
								ValueFrom: &corev1.EnvVarSource{
									SecretKeyRef: &corev1.SecretKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.serverCustomHeaders",
										Optional: ptr.To[bool](true),
									},
								},
							},
						},
						Command: []string{
							"/bin/sh",
						},
						Args: []string{
							"-c",
							"tunnel image --slow 'nginx:1.16' --security-checks vuln,secret --image-config-scanners secret     --cache-dir /tmp/tunnel/.cache --quiet  --format json --server 'http://tunnel.tunnel:4954' > /tmp/scan/result_nginx.json &&  bzip2 -c /tmp/scan/result_nginx.json | base64",
						},
						Resources: corev1.ResourceRequirements{
							Requests: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("100m"),
								corev1.ResourceMemory: resource.MustParse("100M"),
							},
							Limits: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("500m"),
								corev1.ResourceMemory: resource.MustParse("500M"),
							},
						},
						VolumeMounts: []corev1.VolumeMount{getTmpVolumeMount(), getScanResultVolumeMount()},
						SecurityContext: &corev1.SecurityContext{
							Privileged:               ptr.To[bool](false),
							AllowPrivilegeEscalation: ptr.To[bool](false),
							Capabilities: &corev1.Capabilities{
								Drop: []corev1.Capability{"all"},
							},
							ReadOnlyRootFilesystem: ptr.To[bool](true),
						},
					},
				},
			},
		},
		{
			name: "Tunnel fs scan command in Standalone mode",
			tunnelOperatorConfig: map[string]string{
				tunneloperator.KeyVulnerabilityScannerEnabled:  "true",
				tunneloperator.KeyExposedSecretsScannerEnabled: "true",
				tunneloperator.KeyScanJobcompressLogs:          "true",
			},
			config: map[string]string{
				"tunnel.repository":                "docker.io/khulnasoft/tunnel",
				"tunnel.tag":                       "0.35.0",
				"tunnel.mode":                      string(tunnel.Standalone),
				"tunnel.command":                   string(tunnel.Filesystem),
				"tunnel.dbRepository":              tunnel.DefaultDBRepository,
				"tunnel.javaDbRepository":          tunnel.DefaultJavaDBRepository,
				"tunnel.resources.requests.cpu":    "100m",
				"tunnel.resources.requests.memory": "100M",
				"tunnel.resources.limits.cpu":      "500m",
				"tunnel.resources.limits.memory":   "500M",
				"tunnel.timeout":                   "5m0s",
			},
			workloadSpec: &corev1.Pod{
				TypeMeta: metav1.TypeMeta{
					Kind:       "Pod",
					APIVersion: "v1",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "nginx",
					Namespace: "prod-ns",
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name:  "nginx",
							Image: "nginx:1.9.1",
						},
					},
					NodeName: "kind-control-pane",
				}},
			expectedJobSpec: corev1.PodSpec{
				Affinity:                     tunneloperator.LinuxNodeAffinity(),
				RestartPolicy:                corev1.RestartPolicyNever,
				ServiceAccountName:           "tunneloperator-sa",
				ImagePullSecrets:             []corev1.LocalObjectReference{},
				AutomountServiceAccountToken: ptr.To[bool](false),
				Volumes: []corev1.Volume{
					{
						Name: tunnel.FsSharedVolumeName,
						VolumeSource: corev1.VolumeSource{
							EmptyDir: &corev1.EmptyDirVolumeSource{
								Medium: corev1.StorageMediumDefault,
							},
						},
					},
					{
						Name: "tmp",
						VolumeSource: corev1.VolumeSource{
							EmptyDir: &corev1.EmptyDirVolumeSource{
								Medium: corev1.StorageMediumDefault,
							},
						},
					},
					getScanResultVolume(),
				},
				InitContainers: []corev1.Container{
					{
						Name:                     "00000000-0000-0000-0000-000000000001",
						Image:                    "docker.io/khulnasoft/tunnel:0.35.0",
						ImagePullPolicy:          corev1.PullIfNotPresent,
						TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
						Command: []string{
							"cp",
							"-v",
							"/usr/local/bin/tunnel",
							tunnel.SharedVolumeLocationOfTunnel,
						},
						Resources: corev1.ResourceRequirements{
							Requests: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("100m"),
								corev1.ResourceMemory: resource.MustParse("100M"),
							},
							Limits: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("500m"),
								corev1.ResourceMemory: resource.MustParse("500M"),
							},
						},
						VolumeMounts: []corev1.VolumeMount{
							{
								Name:      tunnel.FsSharedVolumeName,
								ReadOnly:  false,
								MountPath: "/var/tunneloperator",
							},
							{
								Name:      "tmp",
								MountPath: "/tmp",
								ReadOnly:  false,
							},
						},
						SecurityContext: &corev1.SecurityContext{
							Privileged:               ptr.To[bool](false),
							AllowPrivilegeEscalation: ptr.To[bool](false),
							Capabilities: &corev1.Capabilities{
								Drop: []corev1.Capability{"all"},
							},
							ReadOnlyRootFilesystem: ptr.To[bool](true),
						},
					},
					{
						Name:                     "00000000-0000-0000-0000-000000000002",
						Image:                    "docker.io/khulnasoft/tunnel:0.35.0",
						ImagePullPolicy:          corev1.PullIfNotPresent,
						TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
						Env: []corev1.EnvVar{
							{
								Name: "HTTP_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.httpProxy",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name: "HTTPS_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.httpsProxy",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name: "NO_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.noProxy",
										Optional: ptr.To[bool](true),
									},
								},
							},

							{
								Name: "GITHUB_TOKEN",
								ValueFrom: &corev1.EnvVarSource{
									SecretKeyRef: &corev1.SecretKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.githubToken",
										Optional: ptr.To[bool](true),
									},
								},
							},
						},
						Command: []string{
							"tunnel",
						},
						Args: []string{
							"--cache-dir",
							"/var/tunneloperator/tunnel-db",
							"image",
							"--download-db-only",
							"--db-repository", tunnel.DefaultDBRepository,
						},
						Resources: corev1.ResourceRequirements{
							Requests: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("100m"),
								corev1.ResourceMemory: resource.MustParse("100M"),
							},
							Limits: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("500m"),
								corev1.ResourceMemory: resource.MustParse("500M"),
							},
						},
						VolumeMounts: []corev1.VolumeMount{
							{
								Name:      tunnel.FsSharedVolumeName,
								ReadOnly:  false,
								MountPath: "/var/tunneloperator",
							},
							{
								Name:      "tmp",
								MountPath: "/tmp",
								ReadOnly:  false,
							},
						},
						SecurityContext: &corev1.SecurityContext{
							Privileged:               ptr.To[bool](false),
							AllowPrivilegeEscalation: ptr.To[bool](false),
							Capabilities: &corev1.Capabilities{
								Drop: []corev1.Capability{"all"},
							},
							ReadOnlyRootFilesystem: ptr.To[bool](true),
						},
					},
				},
				Containers: []corev1.Container{
					{
						Name:                     "nginx",
						Image:                    "nginx:1.9.1",
						ImagePullPolicy:          corev1.PullNever,
						TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
						Env: []corev1.EnvVar{
							{
								Name: "TUNNEL_SEVERITY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.severity",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name: "TUNNEL_SKIP_FILES",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.skipFiles",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name: "TUNNEL_SKIP_DIRS",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.skipDirs",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name: "HTTP_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.httpProxy",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name: "TUNNEL_TIMEOUT",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.timeout",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name: "HTTPS_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.httpsProxy",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name: "NO_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.noProxy",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name: "TUNNEL_JAVA_DB_REPOSITORY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.javaDbRepository",
										Optional: ptr.To[bool](true),
									},
								},
							},
						},
						Command: []string{
							tunnel.SharedVolumeLocationOfTunnel,
						},
						Args: []string{
							"--cache-dir",
							"/var/tunneloperator/tunnel-db",
							"--quiet",
							"filesystem",
							"--security-checks",
							"vuln,secret",
							"--skip-update",
							"--format",
							"json",
							"/",
							"--slow",
						},
						Resources: corev1.ResourceRequirements{
							Requests: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("100m"),
								corev1.ResourceMemory: resource.MustParse("100M"),
							},
							Limits: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("500m"),
								corev1.ResourceMemory: resource.MustParse("500M"),
							},
						},
						VolumeMounts: []corev1.VolumeMount{
							{
								Name:      tunnel.FsSharedVolumeName,
								ReadOnly:  false,
								MountPath: "/var/tunneloperator",
							},
							{
								Name:      "tmp",
								MountPath: "/tmp",
								ReadOnly:  false,
							},
							getScanResultVolumeMount(),
						},
						SecurityContext: &corev1.SecurityContext{
							Privileged:               ptr.To[bool](false),
							AllowPrivilegeEscalation: ptr.To[bool](false),
							Capabilities: &corev1.Capabilities{
								Drop: []corev1.Capability{"all"},
							},
							ReadOnlyRootFilesystem: ptr.To[bool](true),
						},
					},
				},
				SecurityContext: &corev1.PodSecurityContext{},
				NodeName:        "kind-control-pane",
			},
		},
		{
			name: "Tunnel fs scan command in ClientServer mode",
			tunnelOperatorConfig: map[string]string{
				tunneloperator.KeyVulnerabilityScannerEnabled:  "true",
				tunneloperator.KeyExposedSecretsScannerEnabled: "true",
				tunneloperator.KeyScanJobcompressLogs:          "true",
			},
			config: map[string]string{
				"tunnel.repository":                "docker.io/khulnasoft/tunnel",
				"tunnel.tag":                       "0.35.0",
				"tunnel.mode":                      string(tunnel.ClientServer),
				"tunnel.serverURL":                 "http://tunnel.tunnel:4954",
				"tunnel.command":                   string(tunnel.Filesystem),
				"tunnel.dbRepository":              tunnel.DefaultDBRepository,
				"tunnel.javaDbRepository":          tunnel.DefaultJavaDBRepository,
				"tunnel.resources.requests.cpu":    "100m",
				"tunnel.resources.requests.memory": "100M",
				"tunnel.resources.limits.cpu":      "500m",
				"tunnel.resources.limits.memory":   "500M",
				"tunnel.timeout":                   "5m0s",
			},
			workloadSpec: &corev1.Pod{
				TypeMeta: metav1.TypeMeta{
					Kind:       "Pod",
					APIVersion: "v1",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "nginx",
					Namespace: "prod-ns",
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name:  "nginx",
							Image: "nginx:1.9.1",
						},
					},
					NodeName: "kind-control-pane",
				}},
			expectedJobSpec: corev1.PodSpec{
				Affinity:                     tunneloperator.LinuxNodeAffinity(),
				RestartPolicy:                corev1.RestartPolicyNever,
				ServiceAccountName:           "tunneloperator-sa",
				ImagePullSecrets:             []corev1.LocalObjectReference{},
				AutomountServiceAccountToken: ptr.To[bool](false),
				Volumes: []corev1.Volume{
					{
						Name: tunnel.FsSharedVolumeName,
						VolumeSource: corev1.VolumeSource{
							EmptyDir: &corev1.EmptyDirVolumeSource{
								Medium: corev1.StorageMediumDefault,
							},
						},
					},
					{
						Name: "tmp",
						VolumeSource: corev1.VolumeSource{
							EmptyDir: &corev1.EmptyDirVolumeSource{
								Medium: corev1.StorageMediumDefault,
							},
						},
					},
					getScanResultVolume(),
				},
				InitContainers: []corev1.Container{
					{
						Name:                     "00000000-0000-0000-0000-000000000001",
						Image:                    "docker.io/khulnasoft/tunnel:0.35.0",
						ImagePullPolicy:          corev1.PullIfNotPresent,
						TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
						Command: []string{
							"cp",
							"-v",
							"/usr/local/bin/tunnel",
							tunnel.SharedVolumeLocationOfTunnel,
						},
						Resources: corev1.ResourceRequirements{
							Requests: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("100m"),
								corev1.ResourceMemory: resource.MustParse("100M"),
							},
							Limits: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("500m"),
								corev1.ResourceMemory: resource.MustParse("500M"),
							},
						},
						VolumeMounts: []corev1.VolumeMount{
							{
								Name:      tunnel.FsSharedVolumeName,
								ReadOnly:  false,
								MountPath: "/var/tunneloperator",
							},
							{
								Name:      "tmp",
								MountPath: "/tmp",
								ReadOnly:  false,
							},
						},
						SecurityContext: &corev1.SecurityContext{
							Privileged:               ptr.To[bool](false),
							AllowPrivilegeEscalation: ptr.To[bool](false),
							Capabilities: &corev1.Capabilities{
								Drop: []corev1.Capability{"all"},
							},
							ReadOnlyRootFilesystem: ptr.To[bool](true),
						},
					},
				},
				Containers: []corev1.Container{
					{
						Name:                     "nginx",
						Image:                    "nginx:1.9.1",
						ImagePullPolicy:          corev1.PullNever,
						TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
						Env: []corev1.EnvVar{
							{
								Name: "TUNNEL_SEVERITY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.severity",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name: "TUNNEL_SKIP_FILES",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.skipFiles",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name: "TUNNEL_SKIP_DIRS",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.skipDirs",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name: "HTTP_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.httpProxy",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name: "TUNNEL_TIMEOUT",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.timeout",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name: "HTTPS_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.httpsProxy",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name: "NO_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.noProxy",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name: "TUNNEL_TOKEN_HEADER",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.serverTokenHeader",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name: "TUNNEL_TOKEN",
								ValueFrom: &corev1.EnvVarSource{
									SecretKeyRef: &corev1.SecretKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.serverToken",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name: "TUNNEL_CUSTOM_HEADERS",
								ValueFrom: &corev1.EnvVarSource{
									SecretKeyRef: &corev1.SecretKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.serverCustomHeaders",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name: "TUNNEL_JAVA_DB_REPOSITORY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.javaDbRepository",
										Optional: ptr.To[bool](true),
									},
								},
							},
						},
						Command: []string{
							tunnel.SharedVolumeLocationOfTunnel,
						},
						Args: []string{
							"--cache-dir",
							"/var/tunneloperator/tunnel-db",
							"--quiet",
							"filesystem",
							"--security-checks",
							"vuln,secret",
							"--skip-update",
							"--format",
							"json",
							"/",
							"--server",
							"http://tunnel.tunnel:4954",
							"--slow",
						},
						Resources: corev1.ResourceRequirements{
							Requests: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("100m"),
								corev1.ResourceMemory: resource.MustParse("100M"),
							},
							Limits: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("500m"),
								corev1.ResourceMemory: resource.MustParse("500M"),
							},
						},
						VolumeMounts: []corev1.VolumeMount{
							{
								Name:      tunnel.FsSharedVolumeName,
								ReadOnly:  false,
								MountPath: "/var/tunneloperator",
							},
							{
								Name:      "tmp",
								MountPath: "/tmp",
								ReadOnly:  false,
							},
							getScanResultVolumeMount(),
						},
						SecurityContext: &corev1.SecurityContext{
							Privileged:               ptr.To[bool](false),
							AllowPrivilegeEscalation: ptr.To[bool](false),
							Capabilities: &corev1.Capabilities{
								Drop: []corev1.Capability{"all"},
							},
							ReadOnlyRootFilesystem: ptr.To[bool](true),
						},
					},
				},
				SecurityContext: &corev1.PodSecurityContext{},
				NodeName:        "kind-control-pane",
			},
		},
		{
			name: "Tunnel rootfs scan command in Standalone mode",
			tunnelOperatorConfig: map[string]string{
				tunneloperator.KeyVulnerabilityScannerEnabled:  "true",
				tunneloperator.KeyExposedSecretsScannerEnabled: "true",
				tunneloperator.KeyScanJobcompressLogs:          "true",
			},
			config: map[string]string{
				"tunnel.repository":                "docker.io/khulnasoft/tunnel",
				"tunnel.tag":                       "0.35.0",
				"tunnel.mode":                      string(tunnel.Standalone),
				"tunnel.command":                   string(tunnel.Rootfs),
				"tunnel.dbRepository":              tunnel.DefaultDBRepository,
				"tunnel.javaDbRepository":          tunnel.DefaultJavaDBRepository,
				"tunnel.resources.requests.cpu":    "100m",
				"tunnel.resources.requests.memory": "100M",
				"tunnel.resources.limits.cpu":      "500m",
				"tunnel.resources.limits.memory":   "500M",
				"tunnel.timeout":                   "5m0s",
			},
			workloadSpec: &corev1.Pod{
				TypeMeta: metav1.TypeMeta{
					Kind:       "Pod",
					APIVersion: "v1",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "nginx",
					Namespace: "prod-ns",
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name:  "nginx",
							Image: "nginx:1.9.1",
						},
					},
					NodeName: "kind-control-pane",
				}},
			expectedJobSpec: corev1.PodSpec{
				Affinity:                     tunneloperator.LinuxNodeAffinity(),
				RestartPolicy:                corev1.RestartPolicyNever,
				ServiceAccountName:           "tunneloperator-sa",
				ImagePullSecrets:             []corev1.LocalObjectReference{},
				AutomountServiceAccountToken: ptr.To[bool](false),
				Volumes: []corev1.Volume{
					{
						Name: tunnel.FsSharedVolumeName,
						VolumeSource: corev1.VolumeSource{
							EmptyDir: &corev1.EmptyDirVolumeSource{
								Medium: corev1.StorageMediumDefault,
							},
						},
					},
					{
						Name: "tmp",
						VolumeSource: corev1.VolumeSource{
							EmptyDir: &corev1.EmptyDirVolumeSource{
								Medium: corev1.StorageMediumDefault,
							},
						},
					},
					getScanResultVolume(),
				},
				InitContainers: []corev1.Container{
					{
						Name:                     "00000000-0000-0000-0000-000000000001",
						Image:                    "docker.io/khulnasoft/tunnel:0.35.0",
						ImagePullPolicy:          corev1.PullIfNotPresent,
						TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
						Command: []string{
							"cp",
							"-v",
							"/usr/local/bin/tunnel",
							tunnel.SharedVolumeLocationOfTunnel,
						},
						Resources: corev1.ResourceRequirements{
							Requests: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("100m"),
								corev1.ResourceMemory: resource.MustParse("100M"),
							},
							Limits: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("500m"),
								corev1.ResourceMemory: resource.MustParse("500M"),
							},
						},
						VolumeMounts: []corev1.VolumeMount{
							{
								Name:      tunnel.FsSharedVolumeName,
								ReadOnly:  false,
								MountPath: "/var/tunneloperator",
							},
							{
								Name:      "tmp",
								MountPath: "/tmp",
								ReadOnly:  false,
							},
						},
						SecurityContext: &corev1.SecurityContext{
							Privileged:               ptr.To[bool](false),
							AllowPrivilegeEscalation: ptr.To[bool](false),
							Capabilities: &corev1.Capabilities{
								Drop: []corev1.Capability{"all"},
							},
							ReadOnlyRootFilesystem: ptr.To[bool](true),
						},
					},
					{
						Name:                     "00000000-0000-0000-0000-000000000002",
						Image:                    "docker.io/khulnasoft/tunnel:0.35.0",
						ImagePullPolicy:          corev1.PullIfNotPresent,
						TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
						Env: []corev1.EnvVar{
							{
								Name: "HTTP_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.httpProxy",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name: "HTTPS_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.httpsProxy",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name: "NO_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.noProxy",
										Optional: ptr.To[bool](true),
									},
								},
							},

							{
								Name: "GITHUB_TOKEN",
								ValueFrom: &corev1.EnvVarSource{
									SecretKeyRef: &corev1.SecretKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.githubToken",
										Optional: ptr.To[bool](true),
									},
								},
							},
						},
						Command: []string{
							"tunnel",
						},
						Args: []string{
							"--cache-dir",
							"/var/tunneloperator/tunnel-db",
							"image",
							"--download-db-only",
							"--db-repository", tunnel.DefaultDBRepository,
						},
						Resources: corev1.ResourceRequirements{
							Requests: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("100m"),
								corev1.ResourceMemory: resource.MustParse("100M"),
							},
							Limits: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("500m"),
								corev1.ResourceMemory: resource.MustParse("500M"),
							},
						},
						VolumeMounts: []corev1.VolumeMount{
							{
								Name:      tunnel.FsSharedVolumeName,
								ReadOnly:  false,
								MountPath: "/var/tunneloperator",
							},
							{
								Name:      "tmp",
								MountPath: "/tmp",
								ReadOnly:  false,
							},
						},
						SecurityContext: &corev1.SecurityContext{
							Privileged:               ptr.To[bool](false),
							AllowPrivilegeEscalation: ptr.To[bool](false),
							Capabilities: &corev1.Capabilities{
								Drop: []corev1.Capability{"all"},
							},
							ReadOnlyRootFilesystem: ptr.To[bool](true),
						},
					},
				},
				Containers: []corev1.Container{
					{
						Name:                     "nginx",
						Image:                    "nginx:1.9.1",
						ImagePullPolicy:          corev1.PullNever,
						TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
						Env: []corev1.EnvVar{
							{
								Name: "TUNNEL_SEVERITY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.severity",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name: "TUNNEL_SKIP_FILES",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.skipFiles",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name: "TUNNEL_SKIP_DIRS",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.skipDirs",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name: "HTTP_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.httpProxy",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name: "TUNNEL_TIMEOUT",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.timeout",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name: "HTTPS_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.httpsProxy",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name: "NO_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.noProxy",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name: "TUNNEL_JAVA_DB_REPOSITORY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.javaDbRepository",
										Optional: ptr.To[bool](true),
									},
								},
							},
						},
						Command: []string{
							tunnel.SharedVolumeLocationOfTunnel,
						},
						Args: []string{
							"--cache-dir",
							"/var/tunneloperator/tunnel-db",
							"--quiet",
							"rootfs",
							"--security-checks",
							"vuln,secret",
							"--skip-update",
							"--format",
							"json",
							"/",
							"--slow",
						},
						Resources: corev1.ResourceRequirements{
							Requests: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("100m"),
								corev1.ResourceMemory: resource.MustParse("100M"),
							},
							Limits: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("500m"),
								corev1.ResourceMemory: resource.MustParse("500M"),
							},
						},
						VolumeMounts: []corev1.VolumeMount{
							{
								Name:      tunnel.FsSharedVolumeName,
								ReadOnly:  false,
								MountPath: "/var/tunneloperator",
							},
							{
								Name:      "tmp",
								MountPath: "/tmp",
								ReadOnly:  false,
							},
							getScanResultVolumeMount(),
						},
						SecurityContext: &corev1.SecurityContext{
							Privileged:               ptr.To[bool](false),
							AllowPrivilegeEscalation: ptr.To[bool](false),
							Capabilities: &corev1.Capabilities{
								Drop: []corev1.Capability{"all"},
							},
							ReadOnlyRootFilesystem: ptr.To[bool](true),
						},
					},
				},
				SecurityContext: &corev1.PodSecurityContext{},
				NodeName:        "kind-control-pane",
			},
		},
		{
			name: "Tunnel rootfs scan command in ClientServer mode",
			tunnelOperatorConfig: map[string]string{
				tunneloperator.KeyVulnerabilityScannerEnabled:  "true",
				tunneloperator.KeyExposedSecretsScannerEnabled: "true",
				tunneloperator.KeyScanJobcompressLogs:          "true",
			},
			config: map[string]string{
				"tunnel.repository":                "docker.io/khulnasoft/tunnel",
				"tunnel.tag":                       "0.35.0",
				"tunnel.mode":                      string(tunnel.ClientServer),
				"tunnel.serverURL":                 "http://tunnel.tunnel:4954",
				"tunnel.command":                   string(tunnel.Rootfs),
				"tunnel.dbRepository":              tunnel.DefaultDBRepository,
				"tunnel.javaDbRepository":          tunnel.DefaultJavaDBRepository,
				"tunnel.resources.requests.cpu":    "100m",
				"tunnel.resources.requests.memory": "100M",
				"tunnel.resources.limits.cpu":      "500m",
				"tunnel.resources.limits.memory":   "500M",
				"tunnel.timeout":                   "5m0s",
			},
			workloadSpec: &corev1.Pod{
				TypeMeta: metav1.TypeMeta{
					Kind:       "Pod",
					APIVersion: "v1",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "nginx",
					Namespace: "prod-ns",
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name:  "nginx",
							Image: "nginx:1.9.1",
						},
					},
					NodeName: "kind-control-pane",
				}},
			expectedJobSpec: corev1.PodSpec{
				Affinity:                     tunneloperator.LinuxNodeAffinity(),
				RestartPolicy:                corev1.RestartPolicyNever,
				ServiceAccountName:           "tunneloperator-sa",
				ImagePullSecrets:             []corev1.LocalObjectReference{},
				AutomountServiceAccountToken: ptr.To[bool](false),
				Volumes: []corev1.Volume{
					{
						Name: tunnel.FsSharedVolumeName,
						VolumeSource: corev1.VolumeSource{
							EmptyDir: &corev1.EmptyDirVolumeSource{
								Medium: corev1.StorageMediumDefault,
							},
						},
					},
					{
						Name: "tmp",
						VolumeSource: corev1.VolumeSource{
							EmptyDir: &corev1.EmptyDirVolumeSource{
								Medium: corev1.StorageMediumDefault,
							},
						},
					},
					getScanResultVolume(),
				},
				InitContainers: []corev1.Container{
					{
						Name:                     "00000000-0000-0000-0000-000000000001",
						Image:                    "docker.io/khulnasoft/tunnel:0.35.0",
						ImagePullPolicy:          corev1.PullIfNotPresent,
						TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
						Command: []string{
							"cp",
							"-v",
							"/usr/local/bin/tunnel",
							tunnel.SharedVolumeLocationOfTunnel,
						},
						Resources: corev1.ResourceRequirements{
							Requests: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("100m"),
								corev1.ResourceMemory: resource.MustParse("100M"),
							},
							Limits: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("500m"),
								corev1.ResourceMemory: resource.MustParse("500M"),
							},
						},
						VolumeMounts: []corev1.VolumeMount{
							{
								Name:      tunnel.FsSharedVolumeName,
								ReadOnly:  false,
								MountPath: "/var/tunneloperator",
							},
							{
								Name:      "tmp",
								MountPath: "/tmp",
								ReadOnly:  false,
							},
						},
						SecurityContext: &corev1.SecurityContext{
							Privileged:               ptr.To[bool](false),
							AllowPrivilegeEscalation: ptr.To[bool](false),
							Capabilities: &corev1.Capabilities{
								Drop: []corev1.Capability{"all"},
							},
							ReadOnlyRootFilesystem: ptr.To[bool](true),
						},
					},
				},
				Containers: []corev1.Container{
					{
						Name:                     "nginx",
						Image:                    "nginx:1.9.1",
						ImagePullPolicy:          corev1.PullNever,
						TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
						Env: []corev1.EnvVar{
							{
								Name: "TUNNEL_SEVERITY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.severity",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name: "TUNNEL_SKIP_FILES",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.skipFiles",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name: "TUNNEL_SKIP_DIRS",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.skipDirs",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name: "HTTP_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.httpProxy",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name: "TUNNEL_TIMEOUT",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.timeout",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name: "HTTPS_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.httpsProxy",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name: "NO_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.noProxy",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name: "TUNNEL_TOKEN_HEADER",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.serverTokenHeader",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name: "TUNNEL_TOKEN",
								ValueFrom: &corev1.EnvVarSource{
									SecretKeyRef: &corev1.SecretKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.serverToken",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name: "TUNNEL_CUSTOM_HEADERS",
								ValueFrom: &corev1.EnvVarSource{
									SecretKeyRef: &corev1.SecretKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.serverCustomHeaders",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name: "TUNNEL_JAVA_DB_REPOSITORY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.javaDbRepository",
										Optional: ptr.To[bool](true),
									},
								},
							},
						},
						Command: []string{
							tunnel.SharedVolumeLocationOfTunnel,
						},
						Args: []string{
							"--cache-dir",
							"/var/tunneloperator/tunnel-db",
							"--quiet",
							"rootfs",
							"--security-checks",
							"vuln,secret",
							"--skip-update",
							"--format",
							"json",
							"/",
							"--server",
							"http://tunnel.tunnel:4954",
							"--slow",
						},
						Resources: corev1.ResourceRequirements{
							Requests: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("100m"),
								corev1.ResourceMemory: resource.MustParse("100M"),
							},
							Limits: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("500m"),
								corev1.ResourceMemory: resource.MustParse("500M"),
							},
						},
						VolumeMounts: []corev1.VolumeMount{
							{
								Name:      tunnel.FsSharedVolumeName,
								ReadOnly:  false,
								MountPath: "/var/tunneloperator",
							},
							{
								Name:      "tmp",
								MountPath: "/tmp",
								ReadOnly:  false,
							},
							getScanResultVolumeMount(),
						},
						SecurityContext: &corev1.SecurityContext{
							Privileged:               ptr.To[bool](false),
							AllowPrivilegeEscalation: ptr.To[bool](false),
							Capabilities: &corev1.Capabilities{
								Drop: []corev1.Capability{"all"},
							},
							ReadOnlyRootFilesystem: ptr.To[bool](true),
						},
					},
				},
				SecurityContext: &corev1.PodSecurityContext{},
				NodeName:        "kind-control-pane",
			},
		},
		{
			name: "Standalone mode with ECR image and mirror",
			tunnelOperatorConfig: map[string]string{
				tunneloperator.KeyVulnerabilityScannerEnabled:  "true",
				tunneloperator.KeyExposedSecretsScannerEnabled: "true",
				tunneloperator.KeyScanJobcompressLogs:          "true",
			},
			config: map[string]string{
				"tunnel.repository": "docker.io/khulnasoft/tunnel",
				"tunnel.tag":        "0.35.0",
				"tunnel.mode":       string(tunnel.Standalone),

				"tunnel.dbRepository":              tunnel.DefaultDBRepository,
				"tunnel.javaDbRepository":          tunnel.DefaultJavaDBRepository,
				"tunnel.resources.requests.cpu":    "100m",
				"tunnel.resources.requests.memory": "100M",
				"tunnel.resources.limits.cpu":      "500m",
				"tunnel.resources.limits.memory":   "500M",

				"tunnel.registry.mirror.000000000000.dkr.ecr.us-east-1.amazonaws.com": "000000000000.dkr.ecr.eu-west-1.amazonaws.com",
			},
			workloadSpec: &corev1.Pod{
				TypeMeta: metav1.TypeMeta{
					Kind:       "Pod",
					APIVersion: "v1",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "nginx",
					Namespace: "prod-ns",
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name:  "nginx",
							Image: "000000000000.dkr.ecr.us-east-1.amazonaws.com/nginx:1.16",
						},
					},
				},
			},
			expectedJobSpec: corev1.PodSpec{
				Affinity:                     tunneloperator.LinuxNodeAffinity(),
				RestartPolicy:                corev1.RestartPolicyNever,
				ServiceAccountName:           "tunneloperator-sa",
				ImagePullSecrets:             []corev1.LocalObjectReference{},
				AutomountServiceAccountToken: ptr.To[bool](false),
				Volumes: []corev1.Volume{
					tmpVolume, getScanResultVolume(),
				},
				InitContainers: []corev1.Container{
					{
						Name:                     "00000000-0000-0000-0000-000000000001",
						Image:                    "docker.io/khulnasoft/tunnel:0.35.0",
						ImagePullPolicy:          corev1.PullIfNotPresent,
						TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
						Env: []corev1.EnvVar{
							{
								Name: "HTTP_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.httpProxy",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name: "HTTPS_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.httpsProxy",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name: "NO_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.noProxy",
										Optional: ptr.To[bool](true),
									},
								},
							},

							{
								Name: "GITHUB_TOKEN",
								ValueFrom: &corev1.EnvVarSource{
									SecretKeyRef: &corev1.SecretKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.githubToken",
										Optional: ptr.To[bool](true),
									},
								},
							},
						},
						Command: []string{
							"tunnel",
						},
						Args: []string{
							"--cache-dir", "/tmp/tunnel/.cache",
							"image",
							"--download-db-only",
							"--db-repository", tunnel.DefaultDBRepository,
						},
						Resources: corev1.ResourceRequirements{
							Requests: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("100m"),
								corev1.ResourceMemory: resource.MustParse("100M"),
							},
							Limits: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("500m"),
								corev1.ResourceMemory: resource.MustParse("500M"),
							},
						},
						VolumeMounts: []corev1.VolumeMount{
							tmpVolumeMount,
						},
						SecurityContext: &corev1.SecurityContext{
							Privileged:               ptr.To[bool](false),
							AllowPrivilegeEscalation: ptr.To[bool](false),
							Capabilities: &corev1.Capabilities{
								Drop: []corev1.Capability{"all"},
							},
							ReadOnlyRootFilesystem: ptr.To[bool](true),
						},
					},
				},
				Containers: []corev1.Container{
					{
						Name:                     "nginx",
						Image:                    "docker.io/khulnasoft/tunnel:0.35.0",
						ImagePullPolicy:          corev1.PullIfNotPresent,
						TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
						Env: []corev1.EnvVar{
							{
								Name: "TUNNEL_SEVERITY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.severity",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name: "TUNNEL_IGNORE_UNFIXED",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.ignoreUnfixed",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name: "TUNNEL_OFFLINE_SCAN",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.offlineScan",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name: "TUNNEL_JAVA_DB_REPOSITORY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.javaDbRepository",
										Optional: ptr.To[bool](true),
									},
								},
							},
							timeoutEnv,
							{
								Name: "TUNNEL_SKIP_FILES",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.skipFiles",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name: "TUNNEL_SKIP_DIRS",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.skipDirs",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name: "HTTP_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.httpProxy",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name: "HTTPS_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.httpsProxy",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name: "NO_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.noProxy",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name:  "AWS_REGION",
								Value: "eu-west-1",
							},
						},
						Command: []string{
							"/bin/sh",
						},
						Args: []string{
							"-c",
							"tunnel image --slow '000000000000.dkr.ecr.eu-west-1.amazonaws.com/nginx:1.16' --security-checks vuln,secret --image-config-scanners secret   --skip-update  --cache-dir /tmp/tunnel/.cache --quiet  --format json > /tmp/scan/result_nginx.json &&  bzip2 -c /tmp/scan/result_nginx.json | base64",
						},
						Resources: corev1.ResourceRequirements{
							Requests: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("100m"),
								corev1.ResourceMemory: resource.MustParse("100M"),
							},
							Limits: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("500m"),
								corev1.ResourceMemory: resource.MustParse("500M"),
							},
						},
						VolumeMounts: []corev1.VolumeMount{
							tmpVolumeMount, getScanResultVolumeMount(),
						},
						SecurityContext: &corev1.SecurityContext{
							Privileged:               ptr.To[bool](false),
							AllowPrivilegeEscalation: ptr.To[bool](false),
							Capabilities: &corev1.Capabilities{
								Drop: []corev1.Capability{"all"},
							},
							ReadOnlyRootFilesystem: ptr.To[bool](true),
						},
					},
				},
				SecurityContext: &corev1.PodSecurityContext{},
			},
		},
		{
			name: "Standalone mode with credentials",
			tunnelOperatorConfig: map[string]string{
				tunneloperator.KeyVulnerabilityScannerEnabled:  "true",
				tunneloperator.KeyExposedSecretsScannerEnabled: "true",
				tunneloperator.KeyScanJobcompressLogs:          "true",
			},
			config: map[string]string{
				"tunnel.repository": "docker.io/khulnasoft/tunnel",
				"tunnel.tag":        "0.35.0",
				"tunnel.mode":       string(tunnel.Standalone),

				"tunnel.dbRepository":              tunnel.DefaultDBRepository,
				"tunnel.javaDbRepository":          tunnel.DefaultJavaDBRepository,
				"tunnel.resources.requests.cpu":    "100m",
				"tunnel.resources.requests.memory": "100M",
				"tunnel.resources.limits.cpu":      "500m",
				"tunnel.resources.limits.memory":   "500M",
			},
			workloadSpec: &corev1.Pod{
				TypeMeta: metav1.TypeMeta{
					Kind:       "Pod",
					APIVersion: "v1",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "nginx",
					Namespace: "prod-ns",
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name:  "nginx",
							Image: "nginx:1.16",
						},
					},
				},
			},
			credentials: map[string]docker.Auth{
				"index.docker.io": {Username: "user1", Password: "pass123"},
			},
			expectedSecretsData: []map[string][]byte{
				{
					"nginx.username": []byte("user1"),
					"nginx.password": []byte("pass123"),
				},
			},
			expectedJobSpec: corev1.PodSpec{
				Affinity:                     tunneloperator.LinuxNodeAffinity(),
				RestartPolicy:                corev1.RestartPolicyNever,
				ServiceAccountName:           "tunneloperator-sa",
				ImagePullSecrets:             []corev1.LocalObjectReference{},
				AutomountServiceAccountToken: ptr.To[bool](false),
				Volumes: []corev1.Volume{
					tmpVolume, getScanResultVolume(),
				},
				InitContainers: []corev1.Container{
					{
						Name:                     "00000000-0000-0000-0000-000000000001",
						Image:                    "docker.io/khulnasoft/tunnel:0.35.0",
						ImagePullPolicy:          corev1.PullIfNotPresent,
						TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
						Env: []corev1.EnvVar{
							{
								Name: "HTTP_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.httpProxy",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name: "HTTPS_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.httpsProxy",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name: "NO_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.noProxy",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name: "GITHUB_TOKEN",
								ValueFrom: &corev1.EnvVarSource{
									SecretKeyRef: &corev1.SecretKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.githubToken",
										Optional: ptr.To[bool](true),
									},
								},
							},
						},
						Command: []string{
							"tunnel",
						},
						Args: []string{
							"--cache-dir", "/tmp/tunnel/.cache",
							"image",
							"--download-db-only",
							"--db-repository", tunnel.DefaultDBRepository,
						},
						Resources: corev1.ResourceRequirements{
							Requests: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("100m"),
								corev1.ResourceMemory: resource.MustParse("100M"),
							},
							Limits: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("500m"),
								corev1.ResourceMemory: resource.MustParse("500M"),
							},
						},
						VolumeMounts: []corev1.VolumeMount{
							tmpVolumeMount,
						},
						SecurityContext: &corev1.SecurityContext{
							Privileged:               ptr.To[bool](false),
							AllowPrivilegeEscalation: ptr.To[bool](false),
							Capabilities: &corev1.Capabilities{
								Drop: []corev1.Capability{"all"},
							},
							ReadOnlyRootFilesystem: ptr.To[bool](true),
						},
					},
				},
				Containers: []corev1.Container{
					{
						Name:                     "nginx",
						Image:                    "docker.io/khulnasoft/tunnel:0.35.0",
						ImagePullPolicy:          corev1.PullIfNotPresent,
						TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
						Env: []corev1.EnvVar{
							{
								Name: "TUNNEL_SEVERITY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.severity",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name: "TUNNEL_IGNORE_UNFIXED",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.ignoreUnfixed",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name: "TUNNEL_OFFLINE_SCAN",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.offlineScan",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name: "TUNNEL_JAVA_DB_REPOSITORY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.javaDbRepository",
										Optional: ptr.To[bool](true),
									},
								},
							},
							timeoutEnv,
							{
								Name: "TUNNEL_SKIP_FILES",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.skipFiles",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name: "TUNNEL_SKIP_DIRS",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.skipDirs",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name: "HTTP_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.httpProxy",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name: "HTTPS_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.httpsProxy",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name: "NO_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.noProxy",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name: "TUNNEL_USERNAME",
								ValueFrom: &corev1.EnvVarSource{
									SecretKeyRef: &corev1.SecretKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "scan-vulnerabilityreport-5cbcd9b4dc-regcred",
										},
										Key: "nginx.username",
									},
								},
							},
							{
								Name: "TUNNEL_PASSWORD",
								ValueFrom: &corev1.EnvVarSource{
									SecretKeyRef: &corev1.SecretKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "scan-vulnerabilityreport-5cbcd9b4dc-regcred",
										},
										Key: "nginx.password",
									},
								},
							},
						},
						Command: []string{
							"/bin/sh",
						},
						Args: []string{
							"-c",
							"tunnel image --slow 'nginx:1.16' --security-checks vuln,secret --image-config-scanners secret   --skip-update  --cache-dir /tmp/tunnel/.cache --quiet  --format json > /tmp/scan/result_nginx.json &&  bzip2 -c /tmp/scan/result_nginx.json | base64",
						},
						Resources: corev1.ResourceRequirements{
							Requests: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("100m"),
								corev1.ResourceMemory: resource.MustParse("100M"),
							},
							Limits: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("500m"),
								corev1.ResourceMemory: resource.MustParse("500M"),
							},
						},
						VolumeMounts: []corev1.VolumeMount{
							tmpVolumeMount, getScanResultVolumeMount(),
						},
						SecurityContext: &corev1.SecurityContext{
							Privileged:               ptr.To[bool](false),
							AllowPrivilegeEscalation: ptr.To[bool](false),
							Capabilities: &corev1.Capabilities{
								Drop: []corev1.Capability{"all"},
							},
							ReadOnlyRootFilesystem: ptr.To[bool](true),
						},
					},
				},
				SecurityContext: &corev1.PodSecurityContext{},
			},
		},
		{
			name: "Standalone mode with credentials and mirror",
			tunnelOperatorConfig: map[string]string{
				tunneloperator.KeyVulnerabilityScannerEnabled:  "true",
				tunneloperator.KeyExposedSecretsScannerEnabled: "true",
				tunneloperator.KeyScanJobcompressLogs:          "true",
			},
			config: map[string]string{
				"tunnel.repository": "docker.io/khulnasoft/tunnel",
				"tunnel.tag":        "0.35.0",
				"tunnel.mode":       string(tunnel.Standalone),

				"tunnel.dbRepository":              tunnel.DefaultDBRepository,
				"tunnel.javaDbRepository":          tunnel.DefaultJavaDBRepository,
				"tunnel.resources.requests.cpu":    "100m",
				"tunnel.resources.requests.memory": "100M",
				"tunnel.resources.limits.cpu":      "500m",
				"tunnel.resources.limits.memory":   "500M",

				"tunnel.registry.mirror.index.docker.io": "mirror.io",
			},
			workloadSpec: &corev1.Pod{
				TypeMeta: metav1.TypeMeta{
					Kind:       "Pod",
					APIVersion: "v1",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "nginx",
					Namespace: "prod-ns",
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name:  "nginx",
							Image: "nginx:1.16",
						},
					},
				},
			},
			credentials: map[string]docker.Auth{
				"mirror.io": {Username: "user1", Password: "pass123"},
			},
			expectedSecretsData: []map[string][]byte{
				{
					"nginx.username": []byte("user1"),
					"nginx.password": []byte("pass123"),
				},
			},
			expectedJobSpec: corev1.PodSpec{
				Affinity:                     tunneloperator.LinuxNodeAffinity(),
				RestartPolicy:                corev1.RestartPolicyNever,
				ServiceAccountName:           "tunneloperator-sa",
				ImagePullSecrets:             []corev1.LocalObjectReference{},
				AutomountServiceAccountToken: ptr.To[bool](false),
				Volumes: []corev1.Volume{
					tmpVolume, getScanResultVolume(),
				},
				InitContainers: []corev1.Container{
					{
						Name:                     "00000000-0000-0000-0000-000000000001",
						Image:                    "docker.io/khulnasoft/tunnel:0.35.0",
						ImagePullPolicy:          corev1.PullIfNotPresent,
						TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
						Env: []corev1.EnvVar{
							{
								Name: "HTTP_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.httpProxy",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name: "HTTPS_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.httpsProxy",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name: "NO_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.noProxy",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name: "GITHUB_TOKEN",
								ValueFrom: &corev1.EnvVarSource{
									SecretKeyRef: &corev1.SecretKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.githubToken",
										Optional: ptr.To[bool](true),
									},
								},
							},
						},
						Command: []string{
							"tunnel",
						},
						Args: []string{
							"--cache-dir", "/tmp/tunnel/.cache",
							"image",
							"--download-db-only",
							"--db-repository", tunnel.DefaultDBRepository,
						},
						Resources: corev1.ResourceRequirements{
							Requests: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("100m"),
								corev1.ResourceMemory: resource.MustParse("100M"),
							},
							Limits: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("500m"),
								corev1.ResourceMemory: resource.MustParse("500M"),
							},
						},
						VolumeMounts: []corev1.VolumeMount{
							tmpVolumeMount,
						},
						SecurityContext: &corev1.SecurityContext{
							Privileged:               ptr.To[bool](false),
							AllowPrivilegeEscalation: ptr.To[bool](false),
							Capabilities: &corev1.Capabilities{
								Drop: []corev1.Capability{"all"},
							},
							ReadOnlyRootFilesystem: ptr.To[bool](true),
						},
					},
				},
				Containers: []corev1.Container{
					{
						Name:                     "nginx",
						Image:                    "docker.io/khulnasoft/tunnel:0.35.0",
						ImagePullPolicy:          corev1.PullIfNotPresent,
						TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
						Env: []corev1.EnvVar{
							{
								Name: "TUNNEL_SEVERITY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.severity",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name: "TUNNEL_IGNORE_UNFIXED",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.ignoreUnfixed",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name: "TUNNEL_OFFLINE_SCAN",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.offlineScan",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name: "TUNNEL_JAVA_DB_REPOSITORY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.javaDbRepository",
										Optional: ptr.To[bool](true),
									},
								},
							},
							timeoutEnv,
							{
								Name: "TUNNEL_SKIP_FILES",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.skipFiles",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name: "TUNNEL_SKIP_DIRS",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.skipDirs",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name: "HTTP_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.httpProxy",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name: "HTTPS_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.httpsProxy",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name: "NO_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "tunnel-operator-tunnel-config",
										},
										Key:      "tunnel.noProxy",
										Optional: ptr.To[bool](true),
									},
								},
							},
							{
								Name: "TUNNEL_USERNAME",
								ValueFrom: &corev1.EnvVarSource{
									SecretKeyRef: &corev1.SecretKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "scan-vulnerabilityreport-5cbcd9b4dc-regcred",
										},
										Key: "nginx.username",
									},
								},
							},
							{
								Name: "TUNNEL_PASSWORD",
								ValueFrom: &corev1.EnvVarSource{
									SecretKeyRef: &corev1.SecretKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "scan-vulnerabilityreport-5cbcd9b4dc-regcred",
										},
										Key: "nginx.password",
									},
								},
							},
						},
						Command: []string{
							"/bin/sh",
						},
						Args: []string{
							"-c",
							"tunnel image --slow 'mirror.io/library/nginx:1.16' --security-checks vuln,secret --image-config-scanners secret   --skip-update  --cache-dir /tmp/tunnel/.cache --quiet  --format json > /tmp/scan/result_nginx.json &&  bzip2 -c /tmp/scan/result_nginx.json | base64",
						},
						Resources: corev1.ResourceRequirements{
							Requests: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("100m"),
								corev1.ResourceMemory: resource.MustParse("100M"),
							},
							Limits: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("500m"),
								corev1.ResourceMemory: resource.MustParse("500M"),
							},
						},
						VolumeMounts: []corev1.VolumeMount{
							tmpVolumeMount, getScanResultVolumeMount(),
						},
						SecurityContext: &corev1.SecurityContext{
							Privileged:               ptr.To[bool](false),
							AllowPrivilegeEscalation: ptr.To[bool](false),
							Capabilities: &corev1.Capabilities{
								Drop: []corev1.Capability{"all"},
							},
							ReadOnlyRootFilesystem: ptr.To[bool](true),
						},
					},
				},
				SecurityContext: &corev1.PodSecurityContext{},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			fakeclient := fake.NewClientBuilder().WithObjects(
				&corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "tunnel-operator-tunnel-config",
						Namespace: "tunneloperator-ns",
					},
					Data: tc.config,
				}, &v1.CronJob{}).Build()
			pluginContext := tunneloperator.NewPluginContext().
				WithName(tunnel.Plugin).
				WithNamespace("tunneloperator-ns").
				WithServiceAccountName("tunneloperator-sa").
				WithTunnelOperatorConfig(tc.tunnelOperatorConfig).
				WithClient(fakeclient).
				Get()
			resolver := kube.NewObjectResolver(fakeclient, &kube.CompatibleObjectMapper{})
			instance := tunnel.NewPlugin(fixedClock, ext.NewSimpleIDGenerator(), &resolver)
			securityContext := &corev1.SecurityContext{
				Privileged:               ptr.To[bool](false),
				AllowPrivilegeEscalation: ptr.To[bool](false),
				Capabilities: &corev1.Capabilities{
					Drop: []corev1.Capability{"all"},
				},
				ReadOnlyRootFilesystem: ptr.To[bool](true),
			}
			jobSpec, secrets, err := instance.GetScanJobSpec(pluginContext, tc.workloadSpec, tc.credentials, securityContext, map[string]v1alpha1.SbomReportData{})
			require.NoError(t, err)
			assert.Equal(t, tc.expectedJobSpec, jobSpec)
			assert.Equal(t, len(tc.expectedSecretsData), len(secrets))
			for i := 0; i < len(secrets); i++ {
				assert.Equal(t, tc.expectedSecretsData[i], secrets[i].Data)
			}

		})
	}

	testCases = []struct {
		name                string
		config              map[string]string
		tunnelOperatorConfig map[string]string
		workloadSpec        client.Object
		credentials         map[string]docker.Auth
		expectedSecretsData []map[string][]byte
		expectedJobSpec     corev1.PodSpec
	}{{
		name: "Tunnel fs scan command in Standalone mode",
		tunnelOperatorConfig: map[string]string{
			tunneloperator.KeyVulnerabilityScannerEnabled:       "true",
			tunneloperator.KeyExposedSecretsScannerEnabled:      "true",
			tunneloperator.KeyVulnerabilityScansInSameNamespace: "true",
		},
		config: map[string]string{
			"tunnel.repository":                "docker.io/khulnasoft/tunnel",
			"tunnel.tag":                       "0.35.0",
			"tunnel.mode":                      string(tunnel.Standalone),
			"tunnel.command":                   string(tunnel.Filesystem),
			"tunnel.dbRepository":              tunnel.DefaultDBRepository,
			"tunnel.javaDbRepository":          tunnel.DefaultJavaDBRepository,
			"tunnel.resources.requests.cpu":    "100m",
			"tunnel.resources.requests.memory": "100M",
			"tunnel.resources.limits.cpu":      "500m",
			"tunnel.resources.limits.memory":   "500M",
			"tunnel.timeout":                   "5m0s",
		},
		workloadSpec: &corev1.Pod{
			TypeMeta: metav1.TypeMeta{
				Kind:       "Pod",
				APIVersion: "v1",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name:      "nginx",
				Namespace: "prod-ns",
			},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{
					{
						Name:  "nginx",
						Image: "nginx:1.9.1",
					},
				},
				NodeName:           "kind-control-pane",
				ServiceAccountName: "nginx-sa",
			}},
		expectedJobSpec: corev1.PodSpec{
			Affinity:                     tunneloperator.LinuxNodeAffinity(),
			RestartPolicy:                corev1.RestartPolicyNever,
			ServiceAccountName:           "tunneloperator-sa",
			ImagePullSecrets:             []corev1.LocalObjectReference{},
			AutomountServiceAccountToken: ptr.To[bool](false),
			Volumes: []corev1.Volume{
				{
					Name: tunnel.FsSharedVolumeName,
					VolumeSource: corev1.VolumeSource{
						EmptyDir: &corev1.EmptyDirVolumeSource{
							Medium: corev1.StorageMediumDefault,
						},
					},
				},
				{
					Name: "tmp",
					VolumeSource: corev1.VolumeSource{
						EmptyDir: &corev1.EmptyDirVolumeSource{
							Medium: corev1.StorageMediumDefault,
						},
					},
				},
				getScanResultVolume(),
			},
			InitContainers: []corev1.Container{
				{
					Name:                     "00000000-0000-0000-0000-000000000001",
					Image:                    "docker.io/khulnasoft/tunnel:0.35.0",
					ImagePullPolicy:          corev1.PullIfNotPresent,
					TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
					Command: []string{
						"cp",
						"-v",
						"/usr/local/bin/tunnel",
						tunnel.SharedVolumeLocationOfTunnel,
					},
					Resources: corev1.ResourceRequirements{
						Requests: corev1.ResourceList{
							corev1.ResourceCPU:    resource.MustParse("100m"),
							corev1.ResourceMemory: resource.MustParse("100M"),
						},
						Limits: corev1.ResourceList{
							corev1.ResourceCPU:    resource.MustParse("500m"),
							corev1.ResourceMemory: resource.MustParse("500M"),
						},
					},
					VolumeMounts: []corev1.VolumeMount{
						{
							Name:      tunnel.FsSharedVolumeName,
							ReadOnly:  false,
							MountPath: "/var/tunneloperator",
						},
						{
							Name:      "tmp",
							MountPath: "/tmp",
							ReadOnly:  false,
						},
					},
					SecurityContext: &corev1.SecurityContext{
						Privileged:               ptr.To[bool](false),
						AllowPrivilegeEscalation: ptr.To[bool](false),
						Capabilities: &corev1.Capabilities{
							Drop: []corev1.Capability{"all"},
						},
						ReadOnlyRootFilesystem: ptr.To[bool](true),
						RunAsUser:              ptr.To[int64](0),
					},
				},
				{
					Name:                     "00000000-0000-0000-0000-000000000002",
					Image:                    "docker.io/khulnasoft/tunnel:0.35.0",
					ImagePullPolicy:          corev1.PullIfNotPresent,
					TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
					Env: []corev1.EnvVar{
						{
							Name: "HTTP_PROXY",
							ValueFrom: &corev1.EnvVarSource{
								ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
									LocalObjectReference: corev1.LocalObjectReference{
										Name: "tunnel-operator-tunnel-config",
									},
									Key:      "tunnel.httpProxy",
									Optional: ptr.To[bool](true),
								},
							},
						},
						{
							Name: "HTTPS_PROXY",
							ValueFrom: &corev1.EnvVarSource{
								ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
									LocalObjectReference: corev1.LocalObjectReference{
										Name: "tunnel-operator-tunnel-config",
									},
									Key:      "tunnel.httpsProxy",
									Optional: ptr.To[bool](true),
								},
							},
						},
						{
							Name: "NO_PROXY",
							ValueFrom: &corev1.EnvVarSource{
								ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
									LocalObjectReference: corev1.LocalObjectReference{
										Name: "tunnel-operator-tunnel-config",
									},
									Key:      "tunnel.noProxy",
									Optional: ptr.To[bool](true),
								},
							},
						},
						{
							Name: "GITHUB_TOKEN",
							ValueFrom: &corev1.EnvVarSource{
								SecretKeyRef: &corev1.SecretKeySelector{
									LocalObjectReference: corev1.LocalObjectReference{
										Name: "tunnel-operator-tunnel-config",
									},
									Key:      "tunnel.githubToken",
									Optional: ptr.To[bool](true),
								},
							},
						},
					},
					Command: []string{
						"tunnel",
					},
					Args: []string{
						"--cache-dir",
						"/var/tunneloperator/tunnel-db",
						"image",
						"--download-db-only",
						"--db-repository", tunnel.DefaultDBRepository,
					},
					Resources: corev1.ResourceRequirements{
						Requests: corev1.ResourceList{
							corev1.ResourceCPU:    resource.MustParse("100m"),
							corev1.ResourceMemory: resource.MustParse("100M"),
						},
						Limits: corev1.ResourceList{
							corev1.ResourceCPU:    resource.MustParse("500m"),
							corev1.ResourceMemory: resource.MustParse("500M"),
						},
					},
					VolumeMounts: []corev1.VolumeMount{
						{
							Name:      tunnel.FsSharedVolumeName,
							ReadOnly:  false,
							MountPath: "/var/tunneloperator",
						},
						{
							Name:      "tmp",
							MountPath: "/tmp",
							ReadOnly:  false,
						},
					},
					SecurityContext: &corev1.SecurityContext{
						Privileged:               ptr.To[bool](false),
						AllowPrivilegeEscalation: ptr.To[bool](false),
						Capabilities: &corev1.Capabilities{
							Drop: []corev1.Capability{"all"},
						},
						ReadOnlyRootFilesystem: ptr.To[bool](true),
						RunAsUser:              ptr.To[int64](0),
					},
				},
			},
			Containers: []corev1.Container{
				{
					Name:                     "nginx",
					Image:                    "nginx:1.9.1",
					ImagePullPolicy:          corev1.PullIfNotPresent,
					TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
					Env: []corev1.EnvVar{
						{
							Name: "TUNNEL_SEVERITY",
							ValueFrom: &corev1.EnvVarSource{
								ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
									LocalObjectReference: corev1.LocalObjectReference{
										Name: "tunnel-operator-tunnel-config",
									},
									Key:      "tunnel.severity",
									Optional: ptr.To[bool](true),
								},
							},
						},
						{
							Name: "TUNNEL_SKIP_FILES",
							ValueFrom: &corev1.EnvVarSource{
								ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
									LocalObjectReference: corev1.LocalObjectReference{
										Name: "tunnel-operator-tunnel-config",
									},
									Key:      "tunnel.skipFiles",
									Optional: ptr.To[bool](true),
								},
							},
						},
						{
							Name: "TUNNEL_SKIP_DIRS",
							ValueFrom: &corev1.EnvVarSource{
								ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
									LocalObjectReference: corev1.LocalObjectReference{
										Name: "tunnel-operator-tunnel-config",
									},
									Key:      "tunnel.skipDirs",
									Optional: ptr.To[bool](true),
								},
							},
						},
						{
							Name: "HTTP_PROXY",
							ValueFrom: &corev1.EnvVarSource{
								ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
									LocalObjectReference: corev1.LocalObjectReference{
										Name: "tunnel-operator-tunnel-config",
									},
									Key:      "tunnel.httpProxy",
									Optional: ptr.To[bool](true),
								},
							},
						},
						{
							Name: "TUNNEL_TIMEOUT",
							ValueFrom: &corev1.EnvVarSource{
								ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
									LocalObjectReference: corev1.LocalObjectReference{
										Name: "tunnel-operator-tunnel-config",
									},
									Key:      "tunnel.timeout",
									Optional: ptr.To[bool](true),
								},
							},
						},
						{
							Name: "HTTPS_PROXY",
							ValueFrom: &corev1.EnvVarSource{
								ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
									LocalObjectReference: corev1.LocalObjectReference{
										Name: "tunnel-operator-tunnel-config",
									},
									Key:      "tunnel.httpsProxy",
									Optional: ptr.To[bool](true),
								},
							},
						},
						{
							Name: "NO_PROXY",
							ValueFrom: &corev1.EnvVarSource{
								ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
									LocalObjectReference: corev1.LocalObjectReference{
										Name: "tunnel-operator-tunnel-config",
									},
									Key:      "tunnel.noProxy",
									Optional: ptr.To[bool](true),
								},
							},
						},
						{
							Name: "TUNNEL_JAVA_DB_REPOSITORY",
							ValueFrom: &corev1.EnvVarSource{
								ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
									LocalObjectReference: corev1.LocalObjectReference{
										Name: "tunnel-operator-tunnel-config",
									},
									Key:      "tunnel.javaDbRepository",
									Optional: ptr.To[bool](true),
								},
							},
						},
					},
					Command: []string{
						tunnel.SharedVolumeLocationOfTunnel,
					},
					Args: []string{
						"--cache-dir",
						"/var/tunneloperator/tunnel-db",
						"--quiet",
						"filesystem",
						"--security-checks",
						"vuln,secret",
						"--skip-update",
						"--format",
						"json",
						"/",
						"--slow",
					},
					Resources: corev1.ResourceRequirements{
						Requests: corev1.ResourceList{
							corev1.ResourceCPU:    resource.MustParse("100m"),
							corev1.ResourceMemory: resource.MustParse("100M"),
						},
						Limits: corev1.ResourceList{
							corev1.ResourceCPU:    resource.MustParse("500m"),
							corev1.ResourceMemory: resource.MustParse("500M"),
						},
					},
					VolumeMounts: []corev1.VolumeMount{
						{
							Name:      tunnel.FsSharedVolumeName,
							ReadOnly:  false,
							MountPath: "/var/tunneloperator",
						},
						{
							Name:      "tmp",
							MountPath: "/tmp",
							ReadOnly:  false,
						},
						getScanResultVolumeMount(),
					},
					SecurityContext: &corev1.SecurityContext{
						Privileged:               ptr.To[bool](false),
						AllowPrivilegeEscalation: ptr.To[bool](false),
						Capabilities: &corev1.Capabilities{
							Drop: []corev1.Capability{"all"},
						},
						ReadOnlyRootFilesystem: ptr.To[bool](true),
						RunAsUser:              ptr.To[int64](0),
					},
				},
			},
			SecurityContext: &corev1.PodSecurityContext{},
		},
	}}
	// Test cases when tunneloperator is enabled with option to run job in the namespace of workload
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			fakeclient := fake.NewClientBuilder().WithObjects(
				&corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "tunnel-operator-tunnel-config",
						Namespace: "tunneloperator-ns",
					},
					Data: tc.config,
				}, &v1beta1.CronJob{}).Build()
			pluginContext := tunneloperator.NewPluginContext().
				WithName(tunnel.Plugin).
				WithNamespace("tunneloperator-ns").
				WithServiceAccountName("tunneloperator-sa").
				WithClient(fakeclient).
				WithTunnelOperatorConfig(tc.tunnelOperatorConfig).
				Get()
			resolver := kube.NewObjectResolver(fakeclient, &kube.CompatibleObjectMapper{})
			instance := tunnel.NewPlugin(fixedClock, ext.NewSimpleIDGenerator(), &resolver)
			securityContext := &corev1.SecurityContext{
				Privileged:               ptr.To[bool](false),
				AllowPrivilegeEscalation: ptr.To[bool](false),
				Capabilities: &corev1.Capabilities{
					Drop: []corev1.Capability{"all"},
				},
				ReadOnlyRootFilesystem: ptr.To[bool](true),
				// Root expected for standalone mode - the user would need to know this
				RunAsUser: ptr.To[int64](0),
			}
			jobSpec, secrets, err := instance.GetScanJobSpec(pluginContext, tc.workloadSpec, tc.credentials, securityContext, map[string]v1alpha1.SbomReportData{})
			require.NoError(t, err)
			assert.Equal(t, tc.expectedJobSpec, jobSpec)
			assert.Equal(t, len(tc.expectedSecretsData), len(secrets))
			for i := 0; i < len(secrets); i++ {
				assert.Equal(t, tc.expectedSecretsData[i], secrets[i].Data)
			}
		})
	}
}

var (
	sampleVulnerabilityReport = v1alpha1.VulnerabilityReportData{
		UpdateTimestamp: metav1.NewTime(fixedTime),
		Scanner: v1alpha1.Scanner{
			Name:    v1alpha1.ScannerNameTunnel,
			Vendor:  "Khulnasoft Security",
			Version: "0.9.1",
		},
		Registry: v1alpha1.Registry{
			Server: "index.docker.io",
		},
		Artifact: v1alpha1.Artifact{
			Repository: "library/alpine",
			Tag:        "3.10.2",
		},
		Summary: v1alpha1.VulnerabilitySummary{
			CriticalCount: 0,
			MediumCount:   1,
			LowCount:      1,
			NoneCount:     0,
			UnknownCount:  0,
		},
		Vulnerabilities: []v1alpha1.Vulnerability{
			{
				VulnerabilityID:  "CVE-2019-1549",
				Resource:         "openssl",
				InstalledVersion: "1.1.1c-r0",
				FixedVersion:     "1.1.1d-r0",
				Severity:         v1alpha1.SeverityMedium,
				Title:            "openssl: information disclosure in fork()",
				PrimaryLink:      "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-1549",
				Links:            []string{},
			},
			{
				VulnerabilityID:  "CVE-2019-1547",
				Resource:         "openssl",
				InstalledVersion: "1.1.1c-r0",
				FixedVersion:     "1.1.1d-r0",
				Severity:         v1alpha1.SeverityLow,
				Title:            "openssl: side-channel weak encryption vulnerability",
				PrimaryLink:      "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-1547",
				Links:            []string{},
			},
		},
	}

	sampleExposedSecretReport = v1alpha1.ExposedSecretReportData{
		UpdateTimestamp: metav1.NewTime(fixedTime),
		Scanner: v1alpha1.Scanner{
			Name:    v1alpha1.ScannerNameTunnel,
			Vendor:  "Khulnasoft Security",
			Version: "0.9.1",
		},
		Registry: v1alpha1.Registry{
			Server: "index.docker.io",
		},
		Artifact: v1alpha1.Artifact{
			Repository: "library/alpine",
			Tag:        "3.10.2",
		},
		Summary: v1alpha1.ExposedSecretSummary{
			CriticalCount: 3,
			HighCount:     1,
			MediumCount:   0,
			LowCount:      0,
		},
		Secrets: []v1alpha1.ExposedSecret{
			{
				Target:   "/app/config/secret.yaml",
				RuleID:   "stripe-publishable-token",
				Category: "Stripe",
				Severity: "HIGH",
				Title:    "Stripe",
				Match:    "publishable_key: *****",
			},
			{
				Target:   "/app/config/secret.yaml",
				RuleID:   "stripe-access-token",
				Category: "Stripe",
				Severity: "CRITICAL",
				Title:    "Stripe",
				Match:    "secret_key: *****",
			},
			{
				Target:   "/etc/apt/s3auth.conf",
				RuleID:   "aws-access-key-id",
				Category: "AWS",
				Severity: "CRITICAL",
				Title:    "AWS Access Key ID",
				Match:    "AccessKeyId = ********************",
			},
			{
				Target:   "/etc/apt/s3auth.conf",
				RuleID:   "aws-secret-access-key",
				Category: "AWS",
				Severity: "CRITICAL",
				Title:    "AWS Secret Access Key",
				Match:    "SecretAccessKey = ****************************************",
			},
		},
	}

	emptyVulnerabilityReport = v1alpha1.VulnerabilityReportData{
		UpdateTimestamp: metav1.NewTime(fixedTime),
		Scanner: v1alpha1.Scanner{
			Name:    v1alpha1.ScannerNameTunnel,
			Vendor:  "Khulnasoft Security",
			Version: "0.9.1",
		},
		Registry: v1alpha1.Registry{
			Server: "index.docker.io",
		},
		Artifact: v1alpha1.Artifact{
			Repository: "library/alpine",
			Tag:        "3.10.2",
		},
		Summary: v1alpha1.VulnerabilitySummary{
			CriticalCount: 0,
			HighCount:     0,
			MediumCount:   0,
			LowCount:      0,
			NoneCount:     0,
			UnknownCount:  0,
		},
		Vulnerabilities: []v1alpha1.Vulnerability{},
	}

	emptyExposedSecretReport = v1alpha1.ExposedSecretReportData{
		UpdateTimestamp: metav1.NewTime(fixedTime),
		Scanner: v1alpha1.Scanner{
			Name:    v1alpha1.ScannerNameTunnel,
			Vendor:  "Khulnasoft Security",
			Version: "0.9.1",
		},
		Registry: v1alpha1.Registry{
			Server: "index.docker.io",
		},
		Artifact: v1alpha1.Artifact{
			Repository: "library/alpine",
			Tag:        "3.10.2",
		},
		Summary: v1alpha1.ExposedSecretSummary{
			CriticalCount: 0,
			HighCount:     0,
			MediumCount:   0,
			LowCount:      0,
		},
		Secrets: []v1alpha1.ExposedSecret{},
	}
)

func TestPlugin_ParseReportData(t *testing.T) {
	config := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "tunnel-operator-tunnel-config",
			Namespace: "tunneloperator-ns",
		},
		Data: map[string]string{
			"tunnel.repository": "khulnasoft/tunnel",
			"tunnel.tag":        "0.9.1",
			"tunnel.mode":       string(tunnel.Standalone),
			"tunnel.command":    string(tunnel.Image),
		},
	}

	testCases := []struct {
		name                        string
		imageRef                    string
		input                       string
		expectedError               error
		expectedVulnerabilityReport v1alpha1.VulnerabilityReportData
		expectedExposedSecretReport v1alpha1.ExposedSecretReportData
		compressed                  string
	}{
		{
			name:                        "Should convert both vulnerability and exposedsecret report in JSON format when input is quiet",
			imageRef:                    "alpine:3.10.2",
			input:                       getReportAsString("full_report.json"),
			expectedError:               nil,
			expectedVulnerabilityReport: sampleVulnerabilityReport,
			expectedExposedSecretReport: sampleExposedSecretReport,
			compressed:                  "true",
		},
		{
			name:                        "Should convert both vulnerability and exposedsecret report in JSON format when input is quiet",
			imageRef:                    "alpine:3.10.2",
			input:                       getReportAsStringnonCompressed("full_report.json"),
			expectedError:               nil,
			expectedVulnerabilityReport: sampleVulnerabilityReport,
			expectedExposedSecretReport: sampleExposedSecretReport,
			compressed:                  "false",
		},
		{
			name:                        "Should convert vulnerability report in JSON format when OS is not detected",
			imageRef:                    "alpine:3.10.2",
			input:                       `null`,
			expectedError:               fmt.Errorf("bzip2 data invalid: bad magic value"),
			expectedVulnerabilityReport: emptyVulnerabilityReport,
			expectedExposedSecretReport: emptyExposedSecretReport,
			compressed:                  "true",
		},
		{
			name:                        "Should only parse vulnerability report",
			imageRef:                    "alpine:3.10.2",
			input:                       getReportAsString("vulnerability_report.json"),
			expectedError:               nil,
			expectedVulnerabilityReport: sampleVulnerabilityReport,
			expectedExposedSecretReport: emptyExposedSecretReport,
			compressed:                  "true",
		},
		{
			name:                        "Should only parse exposedsecret report",
			imageRef:                    "alpine:3.10.2",
			input:                       getReportAsString("exposedsecret_report.json"),
			expectedError:               nil,
			expectedVulnerabilityReport: emptyVulnerabilityReport,
			expectedExposedSecretReport: sampleExposedSecretReport,
			compressed:                  "true",
		},
		{
			name:          "Should return error when image reference cannot be parsed",
			imageRef:      ":",
			input:         "null",
			expectedError: errors.New("could not parse reference: :"),
			compressed:    "false",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			fakeClient := fake.NewClientBuilder().WithObjects(config).Build()
			ctx := tunneloperator.NewPluginContext().
				WithName("Tunnel").
				WithNamespace("tunneloperator-ns").
				WithServiceAccountName("tunneloperator-sa").
				WithClient(fakeClient).
				WithTunnelOperatorConfig(map[string]string{
					"scanJob.compressLogs": tc.compressed,
					"generateSbomEnabled":  "false",
				}).
				Get()
			resolver := kube.NewObjectResolver(fakeClient, &kube.CompatibleObjectMapper{})
			instance := tunnel.NewPlugin(fixedClock, ext.NewSimpleIDGenerator(), &resolver)
			vulnReport, secretReport, _, err := instance.ParseReportData(ctx, tc.imageRef, io.NopCloser(strings.NewReader(tc.input)))
			switch {
			case tc.expectedError == nil:
				require.NoError(t, err)
				assert.Equal(t, tc.expectedVulnerabilityReport, vulnReport)
				assert.Equal(t, tc.expectedExposedSecretReport, secretReport)
			default:
				assert.EqualError(t, err, tc.expectedError.Error())
			}
		})
	}

}

func TestGetScoreFromCVSS(t *testing.T) {
	testCases := []struct {
		name          string
		cvss          dbtypes.VendorCVSS
		expectedScore *float64
	}{
		{
			name: "Should return nvd score when nvd and vendor v3 score exist",
			cvss: dbtypes.VendorCVSS{
				"nvd": {
					V3Score: 8.1,
				},
				"redhat": {
					V3Score: 8.3,
				},
			},
			expectedScore: ptr.To[float64](8.1),
		},
		{
			name: "Should return nvd score when vendor v3 score is nil",
			cvss: dbtypes.VendorCVSS{
				"nvd": {
					V3Score: 8.1,
				},
				"redhat": {
					V3Score: 0.0,
				},
			},
			expectedScore: ptr.To[float64](8.1),
		},
		{
			name: "Should return nvd score when vendor doesn't exist",
			cvss: dbtypes.VendorCVSS{
				"nvd": {
					V3Score: 8.1,
				},
			},
			expectedScore: ptr.To[float64](8.1),
		},
		{
			name: "Should return vendor score when nvd doesn't exist",
			cvss: dbtypes.VendorCVSS{
				"redhat": {
					V3Score: 8.1,
				},
			},
			expectedScore: ptr.To[float64](8.1),
		},
		{
			name: "Should return nil when vendor and nvd both v3 scores are nil",
			cvss: dbtypes.VendorCVSS{
				"nvd": {
					V3Score: 0.0,
				},
				"redhat": {
					V3Score: 0.0,
				},
			},
			expectedScore: nil,
		},
		{
			name:          "Should return nil when cvss doesn't exist",
			cvss:          dbtypes.VendorCVSS{},
			expectedScore: nil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			score := vulnerabilityreport.GetScoreFromCVSS(vulnerabilityreport.GetCvssV3(tc.cvss))
			assert.Equal(t, tc.expectedScore, score)
		})
	}
}

func TestGetCVSSV3(t *testing.T) {
	testCases := []struct {
		name     string
		cvss     dbtypes.VendorCVSS
		expected map[string]*vulnerabilityreport.CVSS
	}{
		{
			name: "Should return vendor score when vendor v3 score exist",
			cvss: dbtypes.VendorCVSS{
				"nvd": {
					V3Score: 8.1,
				},
				"redhat": {
					V3Score: 8.3,
				},
			},
			expected: map[string]*vulnerabilityreport.CVSS{
				"nvd":    {V3Score: ptr.To[float64](8.1)},
				"redhat": {V3Score: ptr.To[float64](8.3)},
			},
		},
		{
			name: "Should return nil when vendor and nvd both v3 scores are nil",
			cvss: dbtypes.VendorCVSS{
				"nvd": {
					V3Score: 0.0,
				},
				"redhat": {
					V3Score: 0.0,
				},
			},
			expected: map[string]*vulnerabilityreport.CVSS{
				"nvd":    {V3Score: nil},
				"redhat": {V3Score: nil},
			},
		},
		{
			name:     "Should return nil when cvss doesn't exist",
			cvss:     dbtypes.VendorCVSS{},
			expected: map[string]*vulnerabilityreport.CVSS{},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			score := vulnerabilityreport.GetCvssV3(tc.cvss)
			assert.True(t, reflect.DeepEqual(tc.expected, score))
		})
	}
}

func TestGetContainers(t *testing.T) {
	workloadSpec := &appsv1.ReplicaSet{
		Spec: appsv1.ReplicaSetSpec{
			Template: corev1.PodTemplateSpec{

				Spec: corev1.PodSpec{
					InitContainers: []corev1.Container{
						{Name: "init1", Image: "busybox:1.34.1"},
						{Name: "init2", Image: "busybox:1.34.1"},
					},
					Containers: []corev1.Container{
						{Name: "container1", Image: "busybox:1.34.1"},
						{Name: "container2", Image: "busybox:1.34.1"},
					},
					EphemeralContainers: []corev1.EphemeralContainer{
						{
							EphemeralContainerCommon: corev1.EphemeralContainerCommon{
								Name: "ephemeral1", Image: "busybox:1.34.1",
							},
						},
						{
							EphemeralContainerCommon: corev1.EphemeralContainerCommon{
								Name: "ephemeral2", Image: "busybox:1.34.1",
							},
						},
					},
				},
			},
		},
	}

	testCases := []struct {
		name       string
		configData map[string]string
	}{
		{
			name: "Standalone mode with image command",
			configData: map[string]string{
				"tunnel.dbRepository":     tunnel.DefaultDBRepository,
				"tunnel.javaDbRepository": tunnel.DefaultJavaDBRepository,
				"tunnel.repository":       "gcr.io/khulnasoft/tunnel",
				"tunnel.tag":              "0.35.0",
				"tunnel.mode":             string(tunnel.Standalone),
				"tunnel.command":          string(tunnel.Image),
			},
		},
		{
			name: "ClientServer mode with image command",
			configData: map[string]string{
				"tunnel.serverURL":        "http://tunnel.tunnel:4954",
				"tunnel.dbRepository":     tunnel.DefaultDBRepository,
				"tunnel.javaDbRepository": tunnel.DefaultJavaDBRepository,
				"tunnel.repository":       "gcr.io/khulnasoft/tunnel",
				"tunnel.tag":              "0.35.0",
				"tunnel.mode":             string(tunnel.ClientServer),
				"tunnel.command":          string(tunnel.Image),
			},
		},
		{
			name: "Standalone mode with filesystem command",
			configData: map[string]string{
				"tunnel.serverURL":        "http://tunnel.tunnel:4954",
				"tunnel.dbRepository":     tunnel.DefaultDBRepository,
				"tunnel.javaDbRepository": tunnel.DefaultJavaDBRepository,
				"tunnel.repository":       "docker.io/khulnasoft/tunnel",
				"tunnel.tag":              "0.35.0",
				"tunnel.mode":             string(tunnel.Standalone),
				"tunnel.command":          string(tunnel.Filesystem),
			},
		},
	}

	expectedContainers := []string{
		"container1",
		"container2",
		"ephemeral1",
		"ephemeral2",
		"init1",
		"init2",
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			fakeclient := fake.NewClientBuilder().WithObjects(
				&corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "tunnel-operator-tunnel-config",
						Namespace: "tunneloperator-ns",
					},
					Data: tc.configData,
				},
			).Build()

			pluginContext := tunneloperator.NewPluginContext().
				WithName(tunnel.Plugin).
				WithNamespace("tunneloperator-ns").
				WithServiceAccountName("tunneloperator-sa").
				WithClient(fakeclient).
				WithTunnelOperatorConfig(map[string]string{tunneloperator.KeyVulnerabilityScansInSameNamespace: "true"}).
				Get()
			resolver := kube.NewObjectResolver(fakeclient, &kube.CompatibleObjectMapper{})
			instance := tunnel.NewPlugin(fixedClock, ext.NewSimpleIDGenerator(), &resolver)
			jobSpec, _, err := instance.GetScanJobSpec(pluginContext, workloadSpec, nil, nil, map[string]v1alpha1.SbomReportData{})
			assert.NoError(t, err)

			containers := make([]string, 0)

			for _, c := range jobSpec.Containers {
				containers = append(containers, c.Name)
			}

			sort.Strings(containers)

			assert.Equal(t, expectedContainers, containers)
		})
	}
}

func getReportAsString(fixture string) string {
	f, err := os.Open("./testdata/fixture/" + fixture)
	if err != nil {
		log.Fatal(err)
	}

	b, err := io.ReadAll(f)
	if err != nil {
		log.Fatal(err)
	}
	value, err := writeBzip2AndEncode(b)
	if err != nil {
		log.Fatal(err)
	}
	return value
}
func getReportAsStringnonCompressed(fixture string) string {
	f, err := os.Open("./testdata/fixture/" + fixture)
	if err != nil {
		log.Fatal(err)
	}

	b, err := io.ReadAll(f)
	if err != nil {
		log.Fatal(err)
	}
	return string(b)
}

func getScanResultVolume() corev1.Volume {
	return corev1.Volume{
		Name: "scanresult",
		VolumeSource: corev1.VolumeSource{
			EmptyDir: &corev1.EmptyDirVolumeSource{
				Medium: corev1.StorageMediumDefault,
			},
		},
	}
}
func getTmpVolume() corev1.Volume {
	return corev1.Volume{
		Name: "tmp",
		VolumeSource: corev1.VolumeSource{
			EmptyDir: &corev1.EmptyDirVolumeSource{
				Medium: corev1.StorageMediumDefault,
			},
		},
	}
}

func getScanResultVolumeMount() corev1.VolumeMount {
	return corev1.VolumeMount{
		Name:      "scanresult",
		ReadOnly:  false,
		MountPath: "/tmp/scan",
	}
}

func getTmpVolumeMount() corev1.VolumeMount {
	return corev1.VolumeMount{
		Name:      "tmp",
		ReadOnly:  false,
		MountPath: "/tmp",
	}
}

func writeBzip2AndEncode(data []byte) (string, error) {
	var in bytes.Buffer
	w, err := bz.NewWriter(&in, &bz.WriterConfig{})
	if err != nil {
		return "", err
	}
	_, err = w.Write(data)
	if err != nil {
		return "", err
	}
	err = w.Close()
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(in.Bytes()), nil
}

func TestSkipDirFileEnvVars(t *testing.T) {
	testCases := []struct {
		name       string
		configName string
		skipType   string
		envKey     string
		workload   *corev1.Pod
		configKey  string
		want       corev1.EnvVar
	}{
		{
			name:       "read skip file from annotation",
			configName: "tunnel-operator-tunnel-config",
			skipType:   tunnel.SkipFilesAnnotation,
			envKey:     "TUNNEL_SKIP_FILES",
			configKey:  "tunnel.skipFiles",
			workload: &corev1.Pod{
				TypeMeta: metav1.TypeMeta{
					Kind:       "Pod",
					APIVersion: "v1",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "nginx",
					Namespace: "prod-ns",
					Annotations: map[string]string{
						tunnel.SkipFilesAnnotation: "/src/Gemfile.lock,/examplebinary",
					},
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name:  "nginx",
							Image: "nginx:1.16",
						},
					},
				},
			},
			want: corev1.EnvVar{
				Name:  "TUNNEL_SKIP_FILES",
				Value: "/src/Gemfile.lock,/examplebinary",
			},
		},
		{
			name:       "read skip file from config",
			configName: "tunnel-operator-tunnel-config",
			skipType:   tunnel.SkipFilesAnnotation,
			envKey:     "TUNNEL_SKIP_FILES",
			configKey:  "tunnel.skipFiles",
			workload: &corev1.Pod{
				TypeMeta: metav1.TypeMeta{
					Kind:       "Pod",
					APIVersion: "v1",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "nginx",
					Namespace: "prod-ns",
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name:  "nginx",
							Image: "nginx:1.16",
						},
					},
				},
			},
			want: corev1.EnvVar{
				Name: "TUNNEL_SKIP_FILES",
				ValueFrom: &corev1.EnvVarSource{
					ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
						LocalObjectReference: corev1.LocalObjectReference{
							Name: "tunnel-operator-tunnel-config",
						},
						Key:      "tunnel.skipFiles",
						Optional: ptr.To[bool](true),
					},
				},
			},
		},
		{
			name:       "read skip dir from annotation",
			configName: "tunnel-operator-tunnel-config",
			skipType:   tunnel.SkipDirsAnnotation,
			envKey:     "TUNNEL_SKIP_DIRS",
			configKey:  "tunnel.skipDirs",
			workload: &corev1.Pod{
				TypeMeta: metav1.TypeMeta{
					Kind:       "Pod",
					APIVersion: "v1",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "nginx",
					Namespace: "prod-ns",
					Annotations: map[string]string{
						tunnel.SkipDirsAnnotation: "/src/",
					},
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name:  "nginx",
							Image: "nginx:1.16",
						},
					},
				},
			},
			want: corev1.EnvVar{
				Name:  "TUNNEL_SKIP_DIRS",
				Value: "/src/",
			},
		},
		{
			name:       "read skip dir from config",
			configName: "tunnel-operator-tunnel-config",
			skipType:   tunnel.SkipDirsAnnotation,
			envKey:     "TUNNEL_SKIP_DIRS",
			configKey:  "tunnel.skipDirs",
			workload: &corev1.Pod{
				TypeMeta: metav1.TypeMeta{
					Kind:       "Pod",
					APIVersion: "v1",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "nginx",
					Namespace: "prod-ns",
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name:  "nginx",
							Image: "nginx:1.16",
						},
					},
				},
			},
			want: corev1.EnvVar{
				Name: "TUNNEL_SKIP_DIRS",
				ValueFrom: &corev1.EnvVarSource{
					ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
						LocalObjectReference: corev1.LocalObjectReference{
							Name: "tunnel-operator-tunnel-config",
						},
						Key:      "tunnel.skipDirs",
						Optional: ptr.To[bool](true),
					},
				},
			},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := tunnel.ConfigWorkloadAnnotationEnvVars(tc.workload, tc.skipType, tc.envKey, tc.configName, tc.configKey)
			assert.Equal(t, got, tc.want)
		})
	}
}

func TestGetClientServerSkipUpdate(t *testing.T) {
	testCases := []struct {
		name       string
		configData tunnel.Config
		want       bool
	}{
		{
			name: "clientServerSkipUpdate param set to true",
			configData: tunnel.Config{PluginConfig: tunneloperator.PluginConfig{
				Data: map[string]string{
					"tunnel.clientServerSkipUpdate": "true",
				},
			}},
			want: true,
		},
		{
			name: "clientServerSkipUpdate param set to false",
			configData: tunnel.Config{PluginConfig: tunneloperator.PluginConfig{
				Data: map[string]string{
					"tunnel.clientServerSkipUpdate": "false",
				},
			}},
			want: false,
		},
		{
			name: "clientServerSkipUpdate param set to no valid value",
			configData: tunnel.Config{PluginConfig: tunneloperator.PluginConfig{
				Data: map[string]string{
					"tunnel.clientServerSkipUpdate": "false2",
				},
			}},
			want: false,
		},
		{
			name: "clientServerSkipUpdate param set to no value",
			configData: tunnel.Config{PluginConfig: tunneloperator.PluginConfig{
				Data: map[string]string{},
			}},
			want: false,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.configData.GetClientServerSkipUpdate()
			assert.Equal(t, got, tc.want)

		})
	}
}

func TestGetSkipJavaDBUpdate(t *testing.T) {
	testCases := []struct {
		name       string
		configData tunnel.Config
		want       bool
	}{
		{
			name: "skipJavaDBUpdate param set to true",
			configData: tunnel.Config{PluginConfig: tunneloperator.PluginConfig{
				Data: map[string]string{
					"tunnel.skipJavaDBUpdate": "true",
				},
			}},
			want: true,
		},
		{
			name: "skipJavaDBUpdate param set to false",
			configData: tunnel.Config{PluginConfig: tunneloperator.PluginConfig{
				Data: map[string]string{
					"tunnel.skipJavaDBUpdate": "false",
				},
			}},
			want: false,
		},
		{
			name: "skipJavaDBUpdate param set to no valid value",
			configData: tunnel.Config{PluginConfig: tunneloperator.PluginConfig{
				Data: map[string]string{
					"tunnel.skipJavaDBUpdate": "false2",
				},
			}},
			want: false,
		},
		{
			name: "skipJavaDBUpdate param set to no  value",
			configData: tunnel.Config{PluginConfig: tunneloperator.PluginConfig{
				Data: map[string]string{},
			}},
			want: false,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.configData.GetSkipJavaDBUpdate()
			assert.Equal(t, got, tc.want)

		})
	}
}

func TestGetImageScanCacheDir(t *testing.T) {
	testCases := []struct {
		name       string
		configData tunnel.Config
		want       string
	}{
		{
			name: "imageScanCacheDir param set non-default path",
			configData: tunnel.Config{PluginConfig: tunneloperator.PluginConfig{
				Data: map[string]string{
					"tunnel.imageScanCacheDir": "/home/tunnel/.cache",
				},
			}},
			want: "/home/tunnel/.cache",
		},
		{
			name: "imageScanCacheDir param set as empty string",
			configData: tunnel.Config{PluginConfig: tunneloperator.PluginConfig{
				Data: map[string]string{
					"tunnel.imageScanCacheDir": "",
				},
			}},
			want: "/tmp/tunnel/.cache",
		},
		{
			name: "imageScanCacheDir param unset",
			configData: tunnel.Config{PluginConfig: tunneloperator.PluginConfig{
				Data: map[string]string{},
			}},
			want: "/tmp/tunnel/.cache",
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.configData.GetImageScanCacheDir()
			assert.Equal(t, got, tc.want)
		})
	}
}

func TestGetFilesystemScanCacheDir(t *testing.T) {
	testCases := []struct {
		name       string
		configData tunnel.Config
		want       string
	}{
		{
			name: "filesystemScanCacheDir param set non-default path",
			configData: tunnel.Config{PluginConfig: tunneloperator.PluginConfig{
				Data: map[string]string{
					"tunnel.filesystemScanCacheDir": "/home/tunneloperator/tunnel-db",
				},
			}},
			want: "/home/tunneloperator/tunnel-db",
		},
		{
			name: "filesystemScanCacheDir param set as empty string",
			configData: tunnel.Config{PluginConfig: tunneloperator.PluginConfig{
				Data: map[string]string{
					"tunnel.filesystemScanCacheDir": "",
				},
			}},
			want: "/var/tunneloperator/tunnel-db",
		},
		{
			name: "filesystemScanCacheDir param unset",
			configData: tunnel.Config{PluginConfig: tunneloperator.PluginConfig{
				Data: map[string]string{},
			}},
			want: "/var/tunneloperator/tunnel-db",
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.configData.GetFilesystemScanCacheDir()
			assert.Equal(t, got, tc.want)
		})
	}
}
