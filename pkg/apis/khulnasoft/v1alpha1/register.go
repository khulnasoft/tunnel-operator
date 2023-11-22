package v1alpha1

import (
	"github.com/khulnasoft/tunnel-operator/pkg/apis/khulnasoft"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// SchemeGroupVersion is group version used to register these objects
var SchemeGroupVersion = schema.GroupVersion{Group: khulnasoft.GroupName, Version: "v1alpha1"}

var (
	// SchemeBuilder initializes a scheme builder
	SchemeBuilder = runtime.NewSchemeBuilder(addKnownTypes)
	// AddToScheme is a global function that registers this API group & version to a scheme
	AddToScheme = SchemeBuilder.AddToScheme
)

// Adds the list of known types to Scheme.
func addKnownTypes(scheme *runtime.Scheme) error {
	scheme.AddKnownTypes(SchemeGroupVersion,
		&VulnerabilityReport{},
		&VulnerabilityReportList{},
		&ConfigAuditReport{},
		&ConfigAuditReportList{},
		&ClusterConfigAuditReport{},
		&ClusterConfigAuditReportList{},
		&ClusterComplianceReport{},
		&ClusterComplianceReportList{},
		&ExposedSecretReport{},
		&ExposedSecretReportList{},
		&RbacAssessmentReport{},
		&RbacAssessmentReportList{},
		&ClusterRbacAssessmentReport{},
		&ClusterRbacAssessmentReportList{},
		&InfraAssessmentReport{},
		&InfraAssessmentReportList{},
		&ClusterInfraAssessmentReport{},
		&ClusterInfraAssessmentReportList{},
		&SbomReport{},
		&SbomReportList{},
	)
	meta.AddToGroupVersion(scheme, SchemeGroupVersion)
	return nil
}
