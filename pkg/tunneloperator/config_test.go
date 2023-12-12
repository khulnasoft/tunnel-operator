package tunneloperator_test

import (
	"context"
	"testing"

	"github.com/khulnasoft/tunnel-operator/pkg/apis/khulnasoft/v1alpha1"
	"github.com/khulnasoft/tunnel-operator/pkg/tunneloperator"
	"github.com/onsi/gomega"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/kubernetes/fake"
)

func TestConfigData_GetVulnerabilityReportsScanner(t *testing.T) {
	testCases := []struct {
		name            string
		configData      tunneloperator.ConfigData
		expectedError   string
		expectedScanner tunneloperator.Scanner
	}{
		{
			name: "Should return Trivy",
			configData: tunneloperator.ConfigData{
				"vulnerabilityReports.scanner": "Trivy",
			},
			expectedScanner: v1alpha1.ScannerNameTrivy,
		},
		{
			name:          "Should return error when value is not set",
			configData:    tunneloperator.ConfigData{},
			expectedError: "property vulnerabilityReports.scanner not set",
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			scanner, err := tc.configData.GetVulnerabilityReportsScanner()
			if tc.expectedError != "" {
				require.EqualError(t, err, tc.expectedError)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tc.expectedScanner, scanner)
			}
		})
	}
}

func TestConfigData_GetConfigAuditReportsScanner(t *testing.T) {
	testCases := []struct {
		name            string
		configData      tunneloperator.ConfigData
		expectedError   string
		expectedScanner tunneloperator.Scanner
	}{
		{
			name: "Should return Trivy",
			configData: tunneloperator.ConfigData{
				"configAuditReports.scanner": "Trivy",
			},
			expectedScanner: v1alpha1.ScannerNameTrivy,
		},
		{
			name:          "Should return error when value is not set",
			configData:    tunneloperator.ConfigData{},
			expectedError: "property configAuditReports.scanner not set",
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			scanner, err := tc.configData.GetConfigAuditReportsScanner()
			if tc.expectedError != "" {
				require.EqualError(t, err, tc.expectedError)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tc.expectedScanner, scanner)
			}
		})
	}
}

func TestConfigData_GetScanJobTolerations(t *testing.T) {
	testCases := []struct {
		name        string
		config      tunneloperator.ConfigData
		expected    []corev1.Toleration
		expectError string
	}{
		{
			name:     "no scanJob.tolerations in ConfigData",
			config:   tunneloperator.ConfigData{},
			expected: []corev1.Toleration(nil),
		},
		{
			name:        "scanJob.tolerations value is not json",
			config:      tunneloperator.ConfigData{"scanJob.tolerations": `lolwut`},
			expected:    []corev1.Toleration(nil),
			expectError: "invalid character 'l' looking for beginning of value",
		},
		{
			name:     "empty JSON array",
			config:   tunneloperator.ConfigData{"scanJob.tolerations": `[]`},
			expected: []corev1.Toleration{},
		},
		{
			name: "one valid toleration",
			config: tunneloperator.ConfigData{
				"scanJob.tolerations": `[{"key":"key1","operator":"Equal","value":"value1","effect":"NoSchedule"}]`},
			expected: []corev1.Toleration{{
				Key:      "key1",
				Operator: "Equal",
				Value:    "value1",
				Effect:   "NoSchedule",
			}},
		},
		{
			name: "multiple valid tolerations",
			config: tunneloperator.ConfigData{
				"scanJob.tolerations": `[{"key":"key1","operator":"Equal","value":"value1","effect":"NoSchedule"},
					  {"key":"key2","operator":"Equal","value":"value2","effect":"NoSchedule"}]`},
			expected: []corev1.Toleration{
				{
					Key:      "key1",
					Operator: "Equal",
					Value:    "value1",
					Effect:   "NoSchedule",
				},
				{
					Key:      "key2",
					Operator: "Equal",
					Value:    "value2",
					Effect:   "NoSchedule",
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.config.GetScanJobTolerations()
			if tc.expectError != "" {
				assert.Error(t, err, "unexpected end of JSON input", tc.name)
			} else {
				assert.NoError(t, err, tc.name)
			}
			assert.Equal(t, tc.expected, got, tc.name)
		})
	}
}

func TestConfigData_GetImagePullSecret(t *testing.T) {
	testCases := []struct {
		name        string
		config      tunneloperator.ConfigData
		expected    []corev1.LocalObjectReference
		expectError string
	}{
		{
			name:     "no image pull secrets in ConfigData",
			config:   tunneloperator.ConfigData{},
			expected: []corev1.LocalObjectReference{},
		},
		{
			name: "one valid imagePullSecret",
			config: tunneloperator.ConfigData{
				"node.collector.imagePullSecret": `mysecret`},
			expected: []corev1.LocalObjectReference{{
				Name: "mysecret",
			}},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.config.GetNodeCollectorImagePullsecret()
			assert.Equal(t, tc.expected, got, tc.name)
		})
	}
}

func TestConfigData_GetScanJobPodPriorityClassName(t *testing.T) {
	testCases := []struct {
		name     string
		config   tunneloperator.ConfigData
		expected string
	}{
		{
			name:     "no scanJob.podPriorityClassName in ConfigData",
			config:   tunneloperator.ConfigData{},
			expected: "",
		},
		{
			name:     "scanJob.podPriorityClassName value is not string",
			config:   tunneloperator.ConfigData{"scanJob.podPriorityClassName": "2"},
			expected: "2",
		},
		{
			name:     "empty string value",
			config:   tunneloperator.ConfigData{"scanJob.podPriorityClassName": ""},
			expected: "",
		},
		{
			name:     "one valid string",
			config:   tunneloperator.ConfigData{"scanJob.podPriorityClassName": "testing"},
			expected: "testing",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got, _ := tc.config.GetScanJobPodPriorityClassName()
			assert.Equal(t, tc.expected, got, tc.name)
		})
	}
}

func TestConfigData_TestConfigData_GetNodeCollectorVolumes(t *testing.T) {
	testCases := []struct {
		name        string
		config      tunneloperator.ConfigData
		expected    []corev1.Volume
		expectError string
	}{
		{
			name:     "no node-collector volumes in ConfigData",
			config:   tunneloperator.ConfigData{},
			expected: []corev1.Volume(nil),
		},
		{
			name:        "no node-collector volumes value is not json",
			config:      tunneloperator.ConfigData{"nodeCollector.volumes": `lolwut`},
			expected:    []corev1.Volume(nil),
			expectError: "invalid character 'l' looking for beginning of value",
		},
		{
			name:     "empty JSON array",
			config:   tunneloperator.ConfigData{"nodeCollector.volumes": `[]`},
			expected: []corev1.Volume{},
		},
		{
			name:   " JSON with valid data",
			config: tunneloperator.ConfigData{"nodeCollector.volumes": `[{"hostPath":{"path":"/var/lib/etcd"},"name":"var-lib-etcd"}]`},
			expected: []corev1.Volume{
				{
					Name: "var-lib-etcd",
					VolumeSource: corev1.VolumeSource{
						HostPath: &corev1.HostPathVolumeSource{
							Path: "/var/lib/etcd",
						},
					},
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.config.GetNodeCollectorVolumes()
			if tc.expectError != "" {
				assert.Error(t, err, "unexpected end of JSON input", tc.name)
			} else {
				assert.NoError(t, err, tc.name)
			}
			assert.Equal(t, tc.expected, got, tc.name)
		})
	}
}

func TestConfigData_TestConfigData_GetNodeCollectorVolumeMounts(t *testing.T) {
	testCases := []struct {
		name        string
		config      tunneloperator.ConfigData
		expected    []corev1.VolumeMount
		expectError string
	}{
		{
			name:     "no node-collector volume mounts in ConfigData",
			config:   tunneloperator.ConfigData{},
			expected: []corev1.VolumeMount(nil),
		},
		{
			name:        "no node-collector volume mounts value is not json",
			config:      tunneloperator.ConfigData{"nodeCollector.volumeMounts": `lolwut`},
			expected:    []corev1.VolumeMount(nil),
			expectError: "invalid character 'l' looking for beginning of value",
		},
		{
			name:     "empty JSON array",
			config:   tunneloperator.ConfigData{"nodeCollector.volumeMounts": `[]`},
			expected: []corev1.VolumeMount{},
		},
		{
			name:   " JSON with valid data",
			config: tunneloperator.ConfigData{"nodeCollector.volumeMounts": `[{"mountPath":"/var/lib/etcd","name":"var-lib-etcd","readOnly":true}]`},
			expected: []corev1.VolumeMount{
				{
					Name:      "var-lib-etcd",
					MountPath: "/var/lib/etcd",
					ReadOnly:  true,
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.config.GetGetNodeCollectorVolumeMounts()
			if tc.expectError != "" {
				assert.Error(t, err, "unexpected end of JSON input", tc.name)
			} else {
				assert.NoError(t, err, tc.name)
			}
			assert.Equal(t, tc.expected, got, tc.name)
		})
	}
}

func TestAutomountServiceAccountToken(t *testing.T) {
	testCases := []struct {
		name     string
		config   tunneloperator.ConfigData
		expected bool
	}{
		{
			name:     "no scanJob.automountServiceAccountToken in ConfigData",
			config:   tunneloperator.ConfigData{},
			expected: false,
		},
		{
			name:     "scanJob.automountServiceAccountToken false",
			config:   tunneloperator.ConfigData{"scanJob.automountServiceAccountToken": `false`},
			expected: false,
		},
		{
			name:     "scanJob.automountServiceAccountToken true",
			config:   tunneloperator.ConfigData{"scanJob.automountServiceAccountToken": `true`},
			expected: true,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.config.GetScanJobAutomountServiceAccountToken()
			assert.Equal(t, tc.expected, got, tc.name)
		})
	}
}

func TestConfigData_GetScanJobAnnotations(t *testing.T) {
	testCases := []struct {
		name        string
		config      tunneloperator.ConfigData
		expected    map[string]string
		expectError string
	}{
		{
			name: "scan job annotations can be fetched successfully",
			config: tunneloperator.ConfigData{
				"scanJob.annotations": "a.b=c.d/e,foo=bar",
			},
			expected: map[string]string{
				"foo": "bar",
				"a.b": "c.d/e",
			},
		},
		{
			name:     "gracefully deal with unprovided annotations",
			config:   tunneloperator.ConfigData{},
			expected: map[string]string{},
		},
		{
			name: "raise an error on being provided with annotations in wrong format",
			config: tunneloperator.ConfigData{
				"scanJob.annotations": "foo",
			},
			expected:    map[string]string{},
			expectError: "failed parsing incorrectly formatted custom scan job annotations: foo",
		},
		{
			name: "raise an error on being provided with annotations in wrong format",
			config: tunneloperator.ConfigData{
				"scanJob.annotations": "foo=bar,a=b=c",
			},
			expected:    map[string]string{},
			expectError: "failed parsing incorrectly formatted custom scan job annotations: foo=bar,a=b=c",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			scanJobAnnotations, err := tc.config.GetScanJobAnnotations()
			if tc.expectError != "" {
				assert.EqualError(t, err, tc.expectError, tc.name)
			} else {
				assert.NoError(t, err, tc.name)
				assert.Equal(t, tc.expected, scanJobAnnotations, tc.name)
			}
		})
	}
}

func TestConfigData_GetScanJobNodeSelector(t *testing.T) {
	testCases := []struct {
		name        string
		config      tunneloperator.ConfigData
		expected    map[string]string
		expectError string
	}{
		{
			name: "scan job template nodeSelector can be fetched successfully",
			config: tunneloperator.ConfigData{
				"scanJob.nodeSelector": "{\"nodeType\":\"worker\", \"testLabel2\":\"testVal1\"}",
			},
			expected: map[string]string{
				"nodeType":   "worker",
				"testLabel2": "testVal1",
			},
		},
		{
			name:     "gracefully deal with unprovided nodeSelector",
			config:   tunneloperator.ConfigData{},
			expected: map[string]string{},
		},
		{
			name: "raise an error on being provided with empty nodeSelector",
			config: tunneloperator.ConfigData{
				"scanJob.nodeSelector": "{}",
			},
			expected: map[string]string{},
		},
		{
			name: "raise an error on being provided with template nodeSelector in wrong format",
			config: tunneloperator.ConfigData{
				"scanJob.nodeSelector": "{dlzm",
			},
			expected:    map[string]string{},
			expectError: "failed to parse incorrect job template nodeSelector {dlzm: invalid character 'd' looking for beginning of object key string",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			scanJobPodTemplateLabels, err := tc.config.GetScanJobNodeSelector()
			if tc.expectError != "" {
				assert.EqualError(t, err, tc.expectError, tc.name)
			} else {
				assert.NoError(t, err, tc.name)
				assert.Equal(t, tc.expected, scanJobPodTemplateLabels, tc.name)
			}
		})
	}
}

func TestConfigData_GetScanJobPodTemplateLabels(t *testing.T) {
	testCases := []struct {
		name        string
		config      tunneloperator.ConfigData
		expected    labels.Set
		expectError string
	}{
		{
			name: "scan job template labels with additional comma at the end can be fetched successfully",
			config: tunneloperator.ConfigData{
				"scanJob.podTemplateLabels": "a.b=c.d/e,foo=bar,",
			},
			expected: labels.Set{
				"foo": "bar",
				"a.b": "c.d/e",
			},
		},
		{
			name: "scan job template labels can be fetched successfully",
			config: tunneloperator.ConfigData{
				"scanJob.podTemplateLabels": "a.b=c.d/e,foo=bar",
			},
			expected: labels.Set{
				"foo": "bar",
				"a.b": "c.d/e",
			},
		},
		{
			name:     "gracefully deal with unprovided labels",
			config:   tunneloperator.ConfigData{},
			expected: labels.Set{},
		},
		{
			name: "raise an error on being provided with labels in wrong format",
			config: tunneloperator.ConfigData{
				"scanJob.podTemplateLabels": "foo",
			},
			expected:    labels.Set{},
			expectError: "failed parsing incorrectly formatted custom scan pod template labels: foo",
		},
		{
			name: "raise an error on being provided with template labels in wrong format",
			config: tunneloperator.ConfigData{
				"scanJob.podTemplateLabels": "foo=bar,a=b=c",
			},
			expected:    labels.Set{},
			expectError: "failed parsing incorrectly formatted custom scan pod template labels: foo=bar,a=b=c",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			scanJobPodTemplateLabels, err := tc.config.GetScanJobPodTemplateLabels()
			if tc.expectError != "" {
				assert.EqualError(t, err, tc.expectError, tc.name)
			} else {
				assert.NoError(t, err, tc.name)
				assert.Equal(t, tc.expected, scanJobPodTemplateLabels, tc.name)
			}
		})
	}
}

func TestConfigData_GetScanContainerSecurityContext(t *testing.T) {
	expectedAllowPrivilegeEscalation := false
	expectedCapabilities := corev1.Capabilities{
		Drop: []corev1.Capability{"all"},
	}
	expectedPrivileged := false
	expectedReadOnlyRootFilesystem := true

	testCases := []struct {
		name        string
		config      tunneloperator.ConfigData
		expected    *corev1.SecurityContext
		expectError string
	}{
		{
			name: "scan job template [container] SecurityContext can be fetched successfully",
			config: tunneloperator.ConfigData{
				"scanJob.podTemplateContainerSecurityContext": "{\"allowPrivilegeEscalation\":false,\"capabilities\":{\"drop\":[\"all\"]},\"privileged\":false,\"readOnlyRootFilesystem\":true}",
			},
			expected: &corev1.SecurityContext{
				AllowPrivilegeEscalation: &expectedAllowPrivilegeEscalation,
				Capabilities:             &expectedCapabilities,
				Privileged:               &expectedPrivileged,
				ReadOnlyRootFilesystem:   &expectedReadOnlyRootFilesystem,
			},
		},
		{
			name:     "gracefully deal with unprovided securityContext",
			config:   tunneloperator.ConfigData{},
			expected: nil,
		},
		{
			name: "raise an error on being provided with securityContext in wrong format",
			config: tunneloperator.ConfigData{
				"scanJob.podTemplateContainerSecurityContext": "foo",
			},
			expected:    nil,
			expectError: "failed parsing incorrectly formatted custom scan container template securityContext: foo",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			scanJobSecurityContext, err := tc.config.GetScanJobContainerSecurityContext()
			if tc.expectError != "" {
				assert.EqualError(t, err, tc.expectError, tc.name)
			} else {
				assert.NoError(t, err, tc.name)
				assert.Equal(t, tc.expected, scanJobSecurityContext, tc.name)
			}
		})
	}
}

func TestConfigData_GetScanJobPodSecurityContext(t *testing.T) {
	expectedUid := int64(1258)
	expectedGid := int64(55589)
	expectedNonRoot := true

	testCases := []struct {
		name        string
		config      tunneloperator.ConfigData
		expected    *corev1.PodSecurityContext
		expectError string
	}{
		{
			name: "scan job template podSecurityContext can be fetched successfully",
			config: tunneloperator.ConfigData{
				"scanJob.podTemplatePodSecurityContext": "{\"RunAsUser\": 1258, \"RunAsGroup\": 55589, \"RunAsNonRoot\": true}",
			},
			expected: &corev1.PodSecurityContext{
				RunAsUser:    &expectedUid,
				RunAsGroup:   &expectedGid,
				RunAsNonRoot: &expectedNonRoot,
			},
		},
		{
			name:     "gracefully deal with unprovided securityContext",
			config:   tunneloperator.ConfigData{},
			expected: nil,
		},
		{
			name: "raise an error on being provided with securityContext in wrong format",
			config: tunneloperator.ConfigData{
				"scanJob.podTemplatePodSecurityContext": "foo",
			},
			expected:    nil,
			expectError: "failed parsing incorrectly formatted custom scan pod template securityContext: foo",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			scanJobPodSecurityContext, err := tc.config.GetScanJobPodSecurityContext()
			if tc.expectError != "" {
				assert.EqualError(t, err, tc.expectError, tc.name)
			} else {
				assert.NoError(t, err, tc.name)
				assert.Equal(t, tc.expected, scanJobPodSecurityContext, tc.name)
			}
		})
	}
}

func TestConfigData_GetComplianceFailEntriesLimit(t *testing.T) {
	testCases := []struct {
		name       string
		configData tunneloperator.ConfigData
		want       int
	}{
		{
			name:       "Should return compliance fail entries limit default value",
			configData: tunneloperator.ConfigData{},
			want:       10,
		},
		{
			name: "Should return compliance fail entries limit from config data",
			configData: tunneloperator.ConfigData{
				"compliance.failEntriesLimit": "15",
			},
			want: 15,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			gotLimit := tc.configData.ComplianceFailEntriesLimit()
			assert.Equal(t, tc.want, gotLimit)
		})
	}
}

func TestGetScanJobCompressLogs(t *testing.T) {
	testCases := []struct {
		name       string
		configData tunneloperator.ConfigData
		want       bool
	}{
		{
			name:       "should return Scan Job compress logs  default value",
			configData: tunneloperator.ConfigData{},
			want:       false,
		},
		{
			name: "Should return scan job compress logs true",
			configData: tunneloperator.ConfigData{
				"scanJob.compressLogs": "true",
			},
			want: true,
		},
		{
			name: "Should return scan job compress logs false",
			configData: tunneloperator.ConfigData{
				"scanJob.compressLogs": "false",
			},
			want: false,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			compressLogs := tc.configData.CompressLogs()
			assert.Equal(t, tc.want, compressLogs)
		})
	}
}

func TestGetVersionFromImageRef(t *testing.T) {
	testCases := []struct {
		imageRef        string
		expectedVersion string
	}{
		{
			imageRef:        "docker.io/aquasec/trivy:0.9.1",
			expectedVersion: "0.9.1",
		},
		{
			imageRef:        "docker.io/aquasec/trivy@sha256:5020dac24a63ef4f24452a0c63ebbfe93a5309e40f6353d1ee8221d2184ee954",
			expectedVersion: "sha256:5020dac24a63ef4f24452a0c63ebbfe93a5309e40f6353d1ee8221d2184ee954",
		},
		{
			imageRef:        "aquasec/trivy:0.9.1",
			expectedVersion: "0.9.1",
		},
		{
			imageRef:        "aquasec/trivy:latest",
			expectedVersion: "latest",
		},
		{
			imageRef:        "aquasec/trivy",
			expectedVersion: "latest",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.imageRef, func(t *testing.T) {
			version, _ := tunneloperator.GetVersionFromImageRef(tc.imageRef)
			assert.Equal(t, tc.expectedVersion, version)
		})
	}
}

func TestConfigManager_Read(t *testing.T) {
	clientset := fake.NewSimpleClientset(
		&corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: tunneloperator.NamespaceName,
				Name:      tunneloperator.ConfigMapName,
			},
			Data: map[string]string{
				"foo": "bar",
			},
		},
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: tunneloperator.NamespaceName,
				Name:      tunneloperator.SecretName,
			},
			Data: map[string][]byte{
				"baz": []byte("s3cret"),
			},
		},
	)

	data, err := tunneloperator.NewConfigManager(clientset, tunneloperator.NamespaceName).
		Read(context.TODO())

	require.NoError(t, err)
	assert.Equal(t, tunneloperator.ConfigData{
		"foo": "bar",
		"baz": "s3cret",
	}, data)
}

func TestConfigManager_EnsureDefault(t *testing.T) {

	t.Run("Should create ConfigMaps and Secret", func(t *testing.T) {
		g := gomega.NewGomegaWithT(t)

		namespace := "tunneloperator-ns"
		clientset := fake.NewSimpleClientset()

		err := tunneloperator.NewConfigManager(clientset, namespace).EnsureDefault(context.TODO())
		g.Expect(err).ToNot(gomega.HaveOccurred())

		cm, err := clientset.CoreV1().ConfigMaps(namespace).
			Get(context.TODO(), tunneloperator.ConfigMapName, metav1.GetOptions{})
		g.Expect(err).ToNot(gomega.HaveOccurred())
		g.Expect(cm.Data).To(gomega.BeEquivalentTo(tunneloperator.GetDefaultConfig()))

		secret, err := clientset.CoreV1().Secrets(namespace).
			Get(context.TODO(), tunneloperator.SecretName, metav1.GetOptions{})
		g.Expect(err).ToNot(gomega.HaveOccurred())
		g.Expect(secret.Data).To(gomega.BeEmpty())
	})

	t.Run("Should not modify ConfigMaps nor Secret", func(t *testing.T) {
		g := gomega.NewGomegaWithT(t)
		namespace := "tunneloperator-ns"
		clientset := fake.NewSimpleClientset(
			&corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: namespace,
					Name:      tunneloperator.ConfigMapName,
				},
				Data: map[string]string{
					"foo":                        "bar",
					"configAuditReports.scanner": "Trivy",
				},
			},
			&corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: namespace,
					Name:      tunneloperator.SecretName,
				},
				Data: map[string][]byte{
					"baz": []byte("s3cret"),
				},
			},
			&corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: namespace,
					Name:      tunneloperator.GetPluginConfigMapName("Trivy"),
				},
				Data: map[string]string{
					"trivy.policy.my-check.rego": "<REGO>",
				},
			},
		)

		err := tunneloperator.NewConfigManager(clientset, namespace).EnsureDefault(context.TODO())
		g.Expect(err).ToNot(gomega.HaveOccurred())

		cm, err := clientset.CoreV1().ConfigMaps(namespace).
			Get(context.TODO(), tunneloperator.ConfigMapName, metav1.GetOptions{})
		g.Expect(err).ToNot(gomega.HaveOccurred())
		g.Expect(cm.Data).To(gomega.Equal(map[string]string{
			"foo":                        "bar",
			"configAuditReports.scanner": "Trivy",
		}))

		secret, err := clientset.CoreV1().Secrets(namespace).
			Get(context.TODO(), tunneloperator.SecretName, metav1.GetOptions{})
		g.Expect(err).ToNot(gomega.HaveOccurred())
		g.Expect(secret.Data).To(gomega.Equal(map[string][]byte{
			"baz": []byte("s3cret"),
		}))

		pluginConfig, err := clientset.CoreV1().ConfigMaps(namespace).
			Get(context.TODO(), tunneloperator.GetPluginConfigMapName("Trivy"), metav1.GetOptions{})
		g.Expect(err).ToNot(gomega.HaveOccurred())
		g.Expect(pluginConfig.Data).To(gomega.Equal(map[string]string{
			"trivy.policy.my-check.rego": "<REGO>",
		}))
	})

}

func TestConfigManager_Delete(t *testing.T) {
	t.Run("Should not return error when ConfigMap and secret do not exist", func(t *testing.T) {
		clientset := fake.NewSimpleClientset()
		err := tunneloperator.NewConfigManager(clientset, tunneloperator.NamespaceName).Delete(context.TODO())
		require.NoError(t, err)
	})

	t.Run("Should delete ConfigMap and secret", func(t *testing.T) {
		clientset := fake.NewSimpleClientset(
			&corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: tunneloperator.NamespaceName,
					Name:      tunneloperator.ConfigMapName,
				},
				Data: map[string]string{
					"foo": "bar",
				},
			},
			&corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: tunneloperator.NamespaceName,
					Name:      tunneloperator.SecretName,
				},
				Data: map[string][]byte{
					"baz": []byte("s3cret"),
				},
			},
		)

		err := tunneloperator.NewConfigManager(clientset, tunneloperator.NamespaceName).Delete(context.TODO())
		require.NoError(t, err)

		_, err = clientset.CoreV1().ConfigMaps(tunneloperator.NamespaceName).
			Get(context.TODO(), tunneloperator.ConfigMapName, metav1.GetOptions{})
		assert.True(t, errors.IsNotFound(err))

		_, err = clientset.CoreV1().Secrets(tunneloperator.NamespaceName).
			Get(context.TODO(), tunneloperator.SecretName, metav1.GetOptions{})
		assert.True(t, errors.IsNotFound(err))
	})
}

func TestConfigData_VulnerabilityScannerEnabled(t *testing.T) {
	testCases := []struct {
		name     string
		key      string
		value    string
		expected bool
	}{
		{
			name:     "Should return false when key is not set",
			key:      "lah",
			value:    "true",
			expected: false,
		},
		{
			name:     "Should return false when key is set 'false'",
			key:      tunneloperator.KeyVulnerabilityScannerEnabled,
			value:    "false",
			expected: false,
		},
		{
			name:     "Should return true when key is set 'true'",
			key:      tunneloperator.KeyVulnerabilityScannerEnabled,
			value:    "true",
			expected: true,
		},
	}
	for _, tc := range testCases {
		configData := tunneloperator.ConfigData{}
		t.Run(tc.name, func(t *testing.T) {
			configData.Set(tc.key, tc.value)
			got := configData.VulnerabilityScannerEnabled()
			assert.Equal(t, tc.expected, got)
		})
	}
}

func TestConfigData_ExposedSecretsScannerEnabled(t *testing.T) {
	testCases := []struct {
		name     string
		key      string
		value    string
		expected bool
	}{
		{
			name:     "Should return false when key is not set",
			key:      "lah",
			value:    "true",
			expected: false,
		},
		{
			name:     "Should return false when key is set 'false'",
			key:      tunneloperator.KeyExposedSecretsScannerEnabled,
			value:    "false",
			expected: false,
		},
		{
			name:     "Should return true when key is set 'true'",
			key:      tunneloperator.KeyExposedSecretsScannerEnabled,
			value:    "true",
			expected: true,
		},
	}
	for _, tc := range testCases {
		configData := tunneloperator.ConfigData{}
		t.Run(tc.name, func(t *testing.T) {
			configData.Set(tc.key, tc.value)
			got := configData.ExposedSecretsScannerEnabled()
			assert.Equal(t, tc.expected, got)
		})
	}
}
