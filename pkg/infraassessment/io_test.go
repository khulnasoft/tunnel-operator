package infraassessment_test

import (
	"context"
	"testing"

	"github.com/khulnasoft/tunnel-operator/pkg/infraassessment"

	"github.com/khulnasoft/tunnel-operator/pkg/apis/khulnasoft/v1alpha1"
	"github.com/khulnasoft/tunnel-operator/pkg/kube"
	"github.com/khulnasoft/tunnel-operator/pkg/tunneloperator"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestReadWriter(t *testing.T) {

	kubernetesScheme := tunneloperator.NewScheme()

	t.Run("Should create InfraAssessmentReport", func(t *testing.T) {
		testClient := fake.NewClientBuilder().WithScheme(kubernetesScheme).Build()
		resolver := kube.NewObjectResolver(testClient, &kube.CompatibleObjectMapper{})
		readWriter := infraassessment.NewReadWriter(&resolver)
		err := readWriter.WriteReport(context.TODO(), v1alpha1.InfraAssessmentReport{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "role-app",
				Namespace: "qa",
				Labels: map[string]string{
					tunneloperator.LabelResourceKind:      "Role",
					tunneloperator.LabelResourceName:      "app",
					tunneloperator.LabelResourceNamespace: "qa",
				},
			},
			Report: v1alpha1.InfraAssessmentReportData{
				Summary: v1alpha1.InfraAssessmentSummary{
					LowCount:      8,
					CriticalCount: 3,
				},
			},
		})
		require.NoError(t, err)

		var found v1alpha1.InfraAssessmentReport
		err = testClient.Get(context.TODO(), types.NamespacedName{Namespace: "qa", Name: "role-app"}, &found)
		require.NoError(t, err)

		assert.Equal(t, v1alpha1.InfraAssessmentReport{
			TypeMeta: metav1.TypeMeta{
				Kind:       "InfraAssessmentReport",
				APIVersion: "khulnasoft.github.io/v1alpha1",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name:      "role-app",
				Namespace: "qa",
				Labels: map[string]string{
					tunneloperator.LabelResourceKind:      "Role",
					tunneloperator.LabelResourceName:      "app",
					tunneloperator.LabelResourceNamespace: "qa",
				},
				ResourceVersion: "1",
			},
			Report: v1alpha1.InfraAssessmentReportData{
				Summary: v1alpha1.InfraAssessmentSummary{
					LowCount:      8,
					CriticalCount: 3,
				},
			},
		}, found)
	})

	t.Run("Should update InfraAssessmentReport", func(t *testing.T) {
		testClient := fake.NewClientBuilder().WithScheme(kubernetesScheme).WithObjects(&v1alpha1.InfraAssessmentReport{
			ObjectMeta: metav1.ObjectMeta{
				Name:            "role-app",
				Namespace:       "qa",
				ResourceVersion: "0",
				Labels: map[string]string{
					tunneloperator.LabelResourceKind:      "Role",
					tunneloperator.LabelResourceName:      "app",
					tunneloperator.LabelResourceNamespace: "qa",
					tunneloperator.LabelResourceSpecHash:  "h1",
				},
			},
			Report: v1alpha1.InfraAssessmentReportData{
				Summary: v1alpha1.InfraAssessmentSummary{
					LowCount:      8,
					CriticalCount: 3,
				},
			},
		}).Build()
		resolver := kube.NewObjectResolver(testClient, &kube.CompatibleObjectMapper{})
		readWriter := infraassessment.NewReadWriter(&resolver)
		err := readWriter.WriteReport(context.TODO(), v1alpha1.InfraAssessmentReport{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "role-app",
				Namespace: "qa",
				Labels: map[string]string{
					tunneloperator.LabelResourceKind:      "Role",
					tunneloperator.LabelResourceName:      "app",
					tunneloperator.LabelResourceNamespace: "qa",
					tunneloperator.LabelResourceSpecHash:  "h2",
				},
			},
			Report: v1alpha1.InfraAssessmentReportData{
				Summary: v1alpha1.InfraAssessmentSummary{
					LowCount:      9,
					CriticalCount: 2,
				},
			},
		})
		require.NoError(t, err)

		var found v1alpha1.InfraAssessmentReport
		err = testClient.Get(context.TODO(), types.NamespacedName{Namespace: "qa", Name: "role-app"}, &found)
		require.NoError(t, err)

		assert.Equal(t, v1alpha1.InfraAssessmentReport{
			TypeMeta: metav1.TypeMeta{
				Kind:       "InfraAssessmentReport",
				APIVersion: "khulnasoft.github.io/v1alpha1",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name:      "role-app",
				Namespace: "qa",
				Labels: map[string]string{
					tunneloperator.LabelResourceKind:      "Role",
					tunneloperator.LabelResourceName:      "app",
					tunneloperator.LabelResourceNamespace: "qa",
					tunneloperator.LabelResourceSpecHash:  "h2",
				},
				ResourceVersion: "1",
			},
			Report: v1alpha1.InfraAssessmentReportData{
				Summary: v1alpha1.InfraAssessmentSummary{
					LowCount:      9,
					CriticalCount: 2,
				},
			},
		}, found)
	})

	t.Run("Should find InfraAssessmentReport by owner", func(t *testing.T) {
		testClient := fake.NewClientBuilder().WithScheme(kubernetesScheme).WithObjects(
			&v1alpha1.InfraAssessmentReport{
				ObjectMeta: metav1.ObjectMeta{
					Namespace:       "my-namespace",
					Name:            "role-my-deploy-my",
					ResourceVersion: "0",
					Labels: map[string]string{
						tunneloperator.LabelResourceKind:      string(kube.KindDeployment),
						tunneloperator.LabelResourceName:      "role-my-deploy",
						tunneloperator.LabelResourceNamespace: "my-namespace",
					},
				},
				Report: v1alpha1.InfraAssessmentReportData{},
			}, &v1alpha1.InfraAssessmentReport{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "my-namespace",
					Name:      "role-my-sts",
					Labels: map[string]string{
						tunneloperator.LabelResourceKind:      string(kube.KindStatefulSet),
						tunneloperator.LabelResourceName:      "role-my-sts",
						tunneloperator.LabelResourceNamespace: "my-namespace",
					},
				},
				Report: v1alpha1.InfraAssessmentReportData{},
			}).Build()
		resolver := kube.NewObjectResolver(testClient, &kube.CompatibleObjectMapper{})
		readWriter := infraassessment.NewReadWriter(&resolver)
		found, err := readWriter.FindReportByOwner(context.TODO(), kube.ObjectRef{
			Kind:      kube.KindDeployment,
			Name:      "role-my-deploy",
			Namespace: "my-namespace",
		})
		require.NoError(t, err)
		assert.Equal(t, &v1alpha1.InfraAssessmentReport{
			ObjectMeta: metav1.ObjectMeta{
				Namespace:       "my-namespace",
				Name:            "role-my-deploy-my",
				ResourceVersion: "0",
				Labels: map[string]string{
					tunneloperator.LabelResourceKind:      string(kube.KindDeployment),
					tunneloperator.LabelResourceName:      "role-my-deploy",
					tunneloperator.LabelResourceNamespace: "my-namespace",
				},
			},
			Report: v1alpha1.InfraAssessmentReportData{},
		}, found)
	})

	t.Run("Should find InfraAssessmentReport by owner with special name", func(t *testing.T) {
		testClient := fake.NewClientBuilder().WithScheme(kubernetesScheme).WithObjects(
			&v1alpha1.InfraAssessmentReport{
				ObjectMeta: metav1.ObjectMeta{
					Namespace:       "kube-system",
					Name:            "role-79f88497",
					ResourceVersion: "0",
					Labels: map[string]string{
						tunneloperator.LabelResourceKind:      "Role",
						tunneloperator.LabelResourceNameHash:  "79f88497",
						tunneloperator.LabelResourceNamespace: "kube-system",
					},
					Annotations: map[string]string{
						tunneloperator.LabelResourceName: "system:controller:cloud-provider",
					},
				},
				Report: v1alpha1.InfraAssessmentReportData{},
			}, &v1alpha1.InfraAssessmentReport{
				ObjectMeta: metav1.ObjectMeta{
					Namespace:       "kube-system",
					Name:            "role-868458b9d6",
					ResourceVersion: "0",
					Labels: map[string]string{
						tunneloperator.LabelResourceKind:      "Role",
						tunneloperator.LabelResourceNameHash:  "868458b9d6",
						tunneloperator.LabelResourceNamespace: "kube-system",
					},
					Annotations: map[string]string{
						tunneloperator.LabelResourceName: "system:controller:token-cleaner",
					},
				},
				Report: v1alpha1.InfraAssessmentReportData{},
			}).Build()
		resolver := kube.NewObjectResolver(testClient, &kube.CompatibleObjectMapper{})
		readWriter := infraassessment.NewReadWriter(&resolver)
		found, err := readWriter.FindReportByOwner(context.TODO(), kube.ObjectRef{
			Kind:      kube.KindRole,
			Name:      "system:controller:token-cleaner",
			Namespace: "kube-system",
		})
		require.NoError(t, err)
		assert.Equal(t, &v1alpha1.InfraAssessmentReport{
			ObjectMeta: metav1.ObjectMeta{
				Namespace:       "kube-system",
				Name:            "role-868458b9d6",
				ResourceVersion: "0",
				Labels: map[string]string{
					tunneloperator.LabelResourceKind:      "Role",
					tunneloperator.LabelResourceNameHash:  "868458b9d6",
					tunneloperator.LabelResourceNamespace: "kube-system",
				},
				Annotations: map[string]string{
					tunneloperator.LabelResourceName: "system:controller:token-cleaner",
				},
			},
			Report: v1alpha1.InfraAssessmentReportData{},
		}, found)
	})
}
