package tunnel_test

import (
	"testing"

	"github.com/khulnasoft/tunnel-operator/pkg/plugins/tunnel"
	"github.com/khulnasoft/tunnel-operator/pkg/tunneloperator"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestGetMirroredImage(t *testing.T) {
	testCases := []struct {
		name          string
		image         string
		mirrors       map[string]string
		expected      string
		expectedError string
	}{
		{
			name:     "Mirror not match",
			image:    "alpine",
			mirrors:  map[string]string{"gcr.io": "mirror.io"},
			expected: "alpine",
		},
		{
			name:     "Mirror match",
			image:    "alpine",
			mirrors:  map[string]string{"index.docker.io": "mirror.io"},
			expected: "mirror.io/library/alpine:latest",
		},
		{
			name:          "Broken image",
			image:         "alpine@sha256:broken",
			expectedError: "could not parse reference: alpine@sha256:broken",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			expected, err := tunnel.GetMirroredImage(tc.image, tc.mirrors)
			if tc.expectedError != "" {
				require.EqualError(t, err, tc.expectedError)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tc.expected, expected)
			}
		})
	}
}

func TestGetSbomScanCommandAndArgs(t *testing.T) {
	testCases := []struct {
		name           string
		mode           tunnel.Mode
		sbomFile       string
		serverUrl      string
		resultFileName string
		wantCmd        []string
		wantArgs       []string
		compressedLogs string
	}{
		{
			name:           "command and args for standalone mode compress",
			mode:           tunnel.Standalone,
			sbomFile:       "/tmp/scan/bom.json",
			serverUrl:      "",
			resultFileName: "output.json",
			compressedLogs: "true",
			wantArgs:       []string{"-c", "tunnel sbom --slow /tmp/scan/bom.json  --skip-db-update  --cache-dir /tmp/tunnel/.cache --quiet --format json > /tmp/scan/output.json &&  bzip2 -c /tmp/scan/output.json | base64"},
			wantCmd:        []string{"/bin/sh"},
		},
		{
			name:           "command and args for standalone mode non compress",
			mode:           tunnel.Standalone,
			sbomFile:       "/tmp/scan/bom.json",
			serverUrl:      "",
			resultFileName: "",
			compressedLogs: "false",
			wantArgs:       []string{"--cache-dir", "/tmp/tunnel/.cache", "--quiet", "sbom", "--format", "json", "/tmp/scan/bom.json", "--slow", "--skip-db-update"},
			wantCmd:        []string{"tunnel"},
		},
		{
			name:           "command and args for client/server mode compress",
			mode:           tunnel.ClientServer,
			sbomFile:       "/tmp/scan/bom.json",
			serverUrl:      "http://tunnel-server:8080",
			resultFileName: "output.json",
			compressedLogs: "true",
			wantArgs:       []string{"-c", "tunnel sbom --slow /tmp/scan/bom.json    --cache-dir /tmp/tunnel/.cache --quiet --format json --server 'http://tunnel-server:8080' > /tmp/scan/output.json &&  bzip2 -c /tmp/scan/output.json | base64"},
			wantCmd:        []string{"/bin/sh"},
		},
		{
			name:           "command and args for client/server mode non compress",
			mode:           tunnel.ClientServer,
			sbomFile:       "/tmp/scan/bom.json",
			serverUrl:      "http://tunnel-server:8080",
			resultFileName: "",
			compressedLogs: "false",
			wantArgs:       []string{"--cache-dir", "/tmp/tunnel/.cache", "--quiet", "sbom", "--format", "json", "--server", "http://tunnel-server:8080", "/tmp/scan/bom.json", "--slow"},
			wantCmd:        []string{"tunnel"},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			client := fake.NewClientBuilder().
				WithScheme(tunneloperator.NewScheme()).
				WithObjects(&corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "tunnel-operator-tunnel-config",
						Namespace: "tunneloperator-ns",
					},
					Data: map[string]string{
						"tunnel.tag":                    "0.41.0",
						"scanJob.compressLogs":         tc.compressedLogs,
						"tunnel.clientServerSkipUpdate": "false",
					},
				}).
				Build()

			pluginContext := tunneloperator.NewPluginContext().
				WithName("tunnel").
				WithNamespace("tunneloperator-ns").
				WithClient(client).
				WithTunnelOperatorConfig(map[string]string{
					"tunnel.tag":                    "0.41.0",
					"scanJob.compressLogs":         tc.compressedLogs,
					"tunnel.clientServerSkipUpdate": "false",
				}).
				Get()
			cmd, args := tunnel.GetSbomScanCommandAndArgs(pluginContext, tc.mode, tc.sbomFile, tc.serverUrl, tc.resultFileName)
			assert.Equal(t, tc.wantCmd, cmd)
			assert.Equal(t, tc.wantArgs, args)
		})
	}
}
