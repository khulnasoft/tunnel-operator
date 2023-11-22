package rbacassessment_test

import (
	"testing"

	"github.com/khulnasoft/tunnel-operator/pkg/apis/khulnasoft/v1alpha1"
	"github.com/khulnasoft/tunnel-operator/pkg/configauditreport"
	"github.com/khulnasoft/tunnel-operator/pkg/rbacassessment"
	"github.com/khulnasoft/tunnel-operator/pkg/tunneloperator"
	. "github.com/onsi/gomega"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/utils/ptr"
)

func TestReportBuilder(t *testing.T) {

	t.Run("Should build report for namespaced resource", func(t *testing.T) {
		g := NewGomegaWithT(t)

		report, err := rbacassessment.NewReportBuilder(scheme.Scheme).
			Controller(&rbacv1.Role{
				TypeMeta: metav1.TypeMeta{
					Kind:       "Role",
					APIVersion: "rbac.authorization.k8s.io/v1",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "some-owner",
					Namespace: "qa",
					Labels:    labels.Set{"tier": "tier-1", "owner": "team-a"},
				},
				Rules: []rbacv1.PolicyRule{},
			}).
			ResourceSpecHash("xyz").
			PluginConfigHash("nop").
			Data(v1alpha1.RbacAssessmentReportData{}).
			ResourceLabelsToInclude([]string{"tier"}).
			GetReport()
		g.Expect(err).ToNot(HaveOccurred())
		assessmentReport := rbacReport()
		g.Expect(report).To(Equal(assessmentReport))
	})

	t.Run("Should build report for namespaced resource with capital letter", func(t *testing.T) {
		g := NewGomegaWithT(t)

		report, err := rbacassessment.NewReportBuilder(scheme.Scheme).
			Controller(&rbacv1.Role{
				TypeMeta: metav1.TypeMeta{
					Kind:       "Role",
					APIVersion: "rbac.authorization.k8s.io/v1",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "some-Owner",
					Namespace: "qa",
					Labels:    labels.Set{"tier": "tier-1", "owner": "team-a"},
				},
				Rules: []rbacv1.PolicyRule{},
			}).
			ResourceSpecHash("xyz").
			PluginConfigHash("nop").
			Data(v1alpha1.RbacAssessmentReportData{}).
			ResourceLabelsToInclude([]string{"tier"}).
			GetReport()
		g.Expect(err).ToNot(HaveOccurred())
		assessmentReport := v1alpha1.RbacAssessmentReport{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "role-5ccc5d4cff",
				Namespace: "qa",
				OwnerReferences: []metav1.OwnerReference{
					{
						APIVersion:         "rbac.authorization.k8s.io/v1",
						Kind:               "Role",
						Name:               "some-Owner",
						Controller:         ptr.To[bool](true),
						BlockOwnerDeletion: ptr.To[bool](false),
					},
				},
				Labels: map[string]string{
					tunneloperator.LabelResourceKind:      "Role",
					tunneloperator.LabelResourceName:      "some-Owner",
					tunneloperator.LabelResourceNamespace: "qa",
					tunneloperator.LabelResourceSpecHash:  "xyz",
					tunneloperator.LabelPluginConfigHash:  "nop",
					"tier":                               "tier-1",
				},
			},
			Report: v1alpha1.RbacAssessmentReportData{},
		}
		g.Expect(report).To(Equal(assessmentReport))
	})

	t.Run("Should build report for cluster scoped resource", func(t *testing.T) {
		g := NewGomegaWithT(t)

		report, err := configauditreport.NewReportBuilder(scheme.Scheme).
			Controller(&rbacv1.ClusterRole{
				TypeMeta: metav1.TypeMeta{
					Kind:       "ClusterRole",
					APIVersion: "rbac.authorization.k8s.io/v1",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:   "system:controller:node-controller",
					Labels: labels.Set{"tier": "tier-1", "owner": "team-a"},
				},
			}).
			ResourceSpecHash("xyz").
			PluginConfigHash("nop").
			Data(v1alpha1.ConfigAuditReportData{}).
			ResourceLabelsToInclude([]string{"tier"}).
			GetClusterReport()

		g.Expect(err).ToNot(HaveOccurred())
		g.Expect(report).To(Equal(v1alpha1.ClusterConfigAuditReport{
			ObjectMeta: metav1.ObjectMeta{
				Name: "clusterrole-6f69bb5b79",
				OwnerReferences: []metav1.OwnerReference{
					{
						APIVersion:         "rbac.authorization.k8s.io/v1",
						Kind:               "ClusterRole",
						Name:               "system:controller:node-controller",
						Controller:         ptr.To[bool](true),
						BlockOwnerDeletion: ptr.To[bool](false),
					},
				},
				Labels: map[string]string{
					tunneloperator.LabelResourceKind:      "ClusterRole",
					tunneloperator.LabelResourceNameHash:  "6f69bb5b79",
					tunneloperator.LabelResourceNamespace: "",
					tunneloperator.LabelResourceSpecHash:  "xyz",
					tunneloperator.LabelPluginConfigHash:  "nop",
					"tier":                               "tier-1",
				},
				Annotations: map[string]string{
					tunneloperator.LabelResourceName: "system:controller:node-controller",
				},
			},
			Report: v1alpha1.ConfigAuditReportData{},
		}))
	})
}

func rbacReport() v1alpha1.RbacAssessmentReport {
	return v1alpha1.RbacAssessmentReport{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "role-some-owner",
			Namespace: "qa",
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion:         "rbac.authorization.k8s.io/v1",
					Kind:               "Role",
					Name:               "some-owner",
					Controller:         ptr.To[bool](true),
					BlockOwnerDeletion: ptr.To[bool](false),
				},
			},
			Labels: map[string]string{
				tunneloperator.LabelResourceKind:      "Role",
				tunneloperator.LabelResourceName:      "some-owner",
				tunneloperator.LabelResourceNamespace: "qa",
				tunneloperator.LabelResourceSpecHash:  "xyz",
				tunneloperator.LabelPluginConfigHash:  "nop",
				"tier":                               "tier-1",
			},
		},
		Report: v1alpha1.RbacAssessmentReportData{},
	}
}
