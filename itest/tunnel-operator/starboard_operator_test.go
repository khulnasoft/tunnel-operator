package tunnel_operator

import (
	. "github.com/khulnasoft/tunnel-operator/itest/tunnel-operator/behavior"
	. "github.com/onsi/ginkgo/v2"
)

var _ = Describe("Tunnel Operator", func() {

	// TODO Refactor to run this container in a separate test suite
	Describe("Vulnerability Scanner", VulnerabilityScannerBehavior(&inputs))

	// TODO Refactor to run this container in a separate test suite
	Describe("Configuration Checker", ConfigurationCheckerBehavior(&inputs))

	// TODO Refactor to run this container in a separate test suite
	// Describe("CIS Kubernetes Benchmark", CISKubernetesBenchmarkBehavior(&inputs))

})
