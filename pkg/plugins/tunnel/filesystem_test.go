package tunnel_test

import (
	"testing"

	"github.com/khulnasoft/tunnel-operator/pkg/plugins/tunnel"
	"github.com/khulnasoft/tunnel-operator/pkg/tunneloperator"
	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestGetSbomFSScanningArgs(t *testing.T) {
	testCases := []struct {
		name           string
		mode           tunnel.Mode
		sbomFile       string
		serverUrl      string
		resultFileName string
		wantCmd        []string
		wantArgs       []string
	}{
		{
			name:           "command and args for standalone mode",
			mode:           tunnel.Standalone,
			sbomFile:       "/tmp/scan/bom.json",
			serverUrl:      "",
			resultFileName: "",
			wantArgs:       []string{"--cache-dir", "/var/tunneloperator/tunnel-db", "--quiet", "sbom", "--format", "json", "--skip-db-update", "/tmp/scan/bom.json", "--slow"},
			wantCmd:        []string{tunnel.SharedVolumeLocationOfTunnel},
		},
		{
			name:           "command and args for client/server mode",
			mode:           tunnel.ClientServer,
			sbomFile:       "/tmp/scan/bom.json",
			serverUrl:      "http://tunnel-server:8080",
			resultFileName: "",
			wantArgs:       []string{"--cache-dir", "/var/tunneloperator/tunnel-db", "--quiet", "sbom", "--format", "json", "--skip-db-update", "/tmp/scan/bom.json", "--server", "http://tunnel-server:8080", "--slow"},
			wantCmd:        []string{tunnel.SharedVolumeLocationOfTunnel},
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
					"tunnel.clientServerSkipUpdate": "false",
				}).
				Get()
			cmd, args := tunnel.GetSbomFSScanningArgs(pluginContext, tc.mode, tc.serverUrl, tc.sbomFile)
			assert.Equal(t, tc.wantCmd, cmd)
			assert.Equal(t, tc.wantArgs, args)
		})
	}
}
