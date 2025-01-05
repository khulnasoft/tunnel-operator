package tunnel_test

import (
	"testing"

	"github.com/khulnasoft/tunnel-operator/pkg/plugins/tunnel"
	"github.com/khulnasoft/tunnel-operator/pkg/tunneloperator"
	"github.com/stretchr/testify/assert"
)

func TestSlow(t *testing.T) {
	testCases := []struct {
		name       string
		configData tunneloperator.ConfigData
		want       string
	}{{

		name: "slow param set to true",
		configData: map[string]string{
			"tunnel.tag":  "0.35.0",
			"tunnel.slow": "true",
		},
		want: "--slow",
	},
		{
			name: "slow param set to false",
			configData: map[string]string{
				"tunnel.tag":  "0.35.0",
				"tunnel.slow": "false",
			},
			want: "",
		},
		{
			name: "slow param set to no valid value",
			configData: map[string]string{
				"tunnel.tag":  "0.35.0",
				"tunnel.slow": "false2",
			},
			want: "--slow",
		},
		{
			name: "slow param set to true and tunnel tag is less then 0.35.0",
			configData: map[string]string{
				"tunnel.slow": "true",
				"tunnel.tag":  "0.33.0",
			},
			want: "",
		},

		{
			name: "slow param set to true and tunnel tag is bigger then 0.35.0",
			configData: map[string]string{
				"tunnel.slow": "true",
				"tunnel.tag":  "0.36.0",
			},
			want: "--slow",
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := tunnel.Slow(tunnel.Config{tunneloperator.PluginConfig{Data: tc.configData}})
			assert.Equal(t, got, tc.want)
		})
	}
}

func TestScanner(t *testing.T) {
	testCases := []struct {
		name       string
		configData tunneloperator.ConfigData
		want       string
	}{{

		name: "scanner with tunnel tag lower then v0.37.0",
		configData: map[string]string{
			"tunnel.tag": "0.36.0",
		},
		want: "--security-checks",
	},
		{
			name: "scanner with tunnel tag equal then v0.37.0",
			configData: map[string]string{
				"tunnel.tag": "0.37.0",
			},
			want: "--scanners",
		},
		{
			name: "scanner with tunnel tag higher then v0.38.0",
			configData: map[string]string{
				"tunnel.tag": "0.38.0",
			},
			want: "--scanners",
		},
		{
			name:       "scanner with no tunnel tag lower",
			configData: map[string]string{},
			want:       "--scanners",
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := tunnel.Scanners(tunnel.Config{tunneloperator.PluginConfig{Data: tc.configData}})
			assert.Equal(t, got, tc.want)
		})
	}
}

func TestSkipDBUpdate(t *testing.T) {
	testCases := []struct {
		name       string
		configData tunneloperator.ConfigData
		want       string
	}{{

		name: "skip update DB with tunnel tag lower then v0.37.0",
		configData: map[string]string{
			"tunnel.tag": "0.36.0",
		},
		want: "--skip-update",
	},
		{
			name: "skip update DB with tunnel tag equal then v0.37.0",
			configData: map[string]string{
				"tunnel.tag": "0.37.0",
			},
			want: "--skip-db-update",
		},
		{
			name: "skip update DB with tunnel tag higher then v0.37.0",
			configData: map[string]string{
				"tunnel.tag": "0.38.0",
			},
			want: "--skip-db-update",
		},
		{
			name:       "skip update DB with no tunnel tag lower",
			configData: map[string]string{},
			want:       "--skip-db-update",
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := tunnel.SkipDBUpdate(tunnel.Config{tunneloperator.PluginConfig{Data: tc.configData}})
			assert.Equal(t, got, tc.want)
		})
	}
}

func TestSkipJavaDBUpdate(t *testing.T) {
	testCases := []struct {
		name       string
		configData tunneloperator.ConfigData
		want       string
	}{
		{
			name: "skip update Java DB with tunnel tag lower then v0.37.0",
			configData: map[string]string{
				"tunnel.skipJavaDBUpdate": "true",
				"tunnel.tag":              "0.36.0",
			},
			want: "",
		},
		{
			name: "skip update Java DB with tunnel tag equal to v0.37.0",
			configData: map[string]string{
				"tunnel.skipJavaDBUpdate": "true",
				"tunnel.tag":              "0.37.0",
			},
			want: "--skip-java-db-update",
		},
		{
			name: "skip update Java DB with tunnel tag higher then v0.37.0",
			configData: map[string]string{
				"tunnel.skipJavaDBUpdate": "true",
				"tunnel.tag":              "0.38.0",
			},
			want: "--skip-java-db-update",
		},
		{
			name: "skip update Java DB with no tunnel tag",
			configData: map[string]string{
				"tunnel.skipJavaDBUpdate": "true",
			},
			want: "--skip-java-db-update",
		},
		{
			name: "skip update Java DB with skip false",
			configData: map[string]string{
				"tunnel.skipJavaDBUpdate": "false",
			},
			want: "",
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := tunnel.SkipJavaDBUpdate(tunnel.Config{tunneloperator.PluginConfig{Data: tc.configData}})
			assert.Equal(t, got, tc.want)
		})
	}
}
