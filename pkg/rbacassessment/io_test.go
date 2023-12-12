package rbacassessment_test

import (
	"context"
	"k8s.io/api/batch/v1beta1"
	"testing"

	"github.com/khulnasoft/tunnel-operator/pkg/rbacassessment"

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

	t.Run("Should create RbacAssessmentReport", func(t *testing.T) {
		testClient := fake.NewClientBuilder().WithScheme(kubernetesScheme).Build()
		resolver := kube.NewObjectResolver(testClient, &kube.CompatibleObjectMapper{})
		readWriter := rbacassessment.NewReadWriter(&resolver)
		err := readWriter.WriteReport(context.TODO(), v1alpha1.RbacAssessmentReport{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "role-app",
				Namespace: "qa",
				Labels: map[string]string{
					tunneloperator.LabelResourceKind:      "Role",
					tunneloperator.LabelResourceName:      "app",
					tunneloperator.LabelResourceNamespace: "qa",
				},
			},
			Report: v1alpha1.RbacAssessmentReportData{
				Summary: v1alpha1.RbacAssessmentSummary{
					LowCount:      8,
					CriticalCount: 3,
				},
			},
		})
		require.NoError(t, err)

		var found v1alpha1.RbacAssessmentReport
		err = testClient.Get(context.TODO(), types.NamespacedName{Namespace: "qa", Name: "role-app"}, &found)
		require.NoError(t, err)

		assert.Equal(t, v1alpha1.RbacAssessmentReport{
			TypeMeta: metav1.TypeMeta{
				Kind:       "RbacAssessmentReport",
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
			Report: v1alpha1.RbacAssessmentReportData{
				Summary: v1alpha1.RbacAssessmentSummary{
					LowCount:      8,
					CriticalCount: 3,
				},
			},
		}, found)
	})

	t.Run("Should update RbacAssessmentReport", func(t *testing.T) {
		testClient := fake.NewClientBuilder().WithScheme(kubernetesScheme).WithObjects(&v1alpha1.RbacAssessmentReport{
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
			Report: v1alpha1.RbacAssessmentReportData{
				Summary: v1alpha1.RbacAssessmentSummary{
					LowCount:      8,
					CriticalCount: 3,
				},
			},
		}).Build()
		resolver := kube.NewObjectResolver(testClient, &kube.CompatibleObjectMapper{})
		readWriter := rbacassessment.NewReadWriter(&resolver)
		err := readWriter.WriteReport(context.TODO(), v1alpha1.RbacAssessmentReport{
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
			Report: v1alpha1.RbacAssessmentReportData{
				Summary: v1alpha1.RbacAssessmentSummary{
					LowCount:      9,
					CriticalCount: 2,
				},
			},
		})
		require.NoError(t, err)

		var found v1alpha1.RbacAssessmentReport
		err = testClient.Get(context.TODO(), types.NamespacedName{Namespace: "qa", Name: "role-app"}, &found)
		require.NoError(t, err)

		assert.Equal(t, v1alpha1.RbacAssessmentReport{
			TypeMeta: metav1.TypeMeta{
				Kind:       "RbacAssessmentReport",
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
			Report: v1alpha1.RbacAssessmentReportData{
				Summary: v1alpha1.RbacAssessmentSummary{
					LowCount:      9,
					CriticalCount: 2,
				},
			},
		}, found)
	})

	t.Run("Should find RbacAssessmentReport by owner", func(t *testing.T) {
		testClient := fake.NewClientBuilder().WithScheme(kubernetesScheme).WithObjects(
			&v1alpha1.RbacAssessmentReport{
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
				Report: v1alpha1.RbacAssessmentReportData{},
			}, &v1alpha1.RbacAssessmentReport{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "my-namespace",
					Name:      "role-my-sts",
					Labels: map[string]string{
						tunneloperator.LabelResourceKind:      string(kube.KindStatefulSet),
						tunneloperator.LabelResourceName:      "role-my-sts",
						tunneloperator.LabelResourceNamespace: "my-namespace",
					},
				},
				Report: v1alpha1.RbacAssessmentReportData{},
			}).Build()
		resolver := kube.NewObjectResolver(testClient, &kube.CompatibleObjectMapper{})
		readWriter := rbacassessment.NewReadWriter(&resolver)
		found, err := readWriter.FindReportByOwner(context.TODO(), kube.ObjectRef{
			Kind:      kube.KindDeployment,
			Name:      "role-my-deploy",
			Namespace: "my-namespace",
		})
		require.NoError(t, err)
		assert.Equal(t, &v1alpha1.RbacAssessmentReport{
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
			Report: v1alpha1.RbacAssessmentReportData{},
		}, found)
	})

	t.Run("Should find RbacAssessmentReport by owner with special name", func(t *testing.T) {
		testClient := fake.NewClientBuilder().WithScheme(kubernetesScheme).WithObjects(
			&v1alpha1.RbacAssessmentReport{
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
				Report: v1alpha1.RbacAssessmentReportData{},
			}, &v1alpha1.RbacAssessmentReport{
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
				Report: v1alpha1.RbacAssessmentReportData{},
			}).Build()
		resolver := kube.NewObjectResolver(testClient, &kube.CompatibleObjectMapper{})
		readWriter := rbacassessment.NewReadWriter(&resolver)
		found, err := readWriter.FindReportByOwner(context.TODO(), kube.ObjectRef{
			Kind:      kube.KindRole,
			Name:      "system:controller:token-cleaner",
			Namespace: "kube-system",
		})
		require.NoError(t, err)
		assert.Equal(t, &v1alpha1.RbacAssessmentReport{
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
			Report: v1alpha1.RbacAssessmentReportData{},
		}, found)
	})

	t.Run("Should create ClusterRbacAssessmentReport", func(t *testing.T) {
		testClient := fake.NewClientBuilder().WithScheme(kubernetesScheme).Build()
		resolver := kube.NewObjectResolver(testClient, &kube.CompatibleObjectMapper{})
		readWriter := rbacassessment.NewReadWriter(&resolver)
		err := readWriter.WriteClusterReport(context.TODO(), v1alpha1.ClusterRbacAssessmentReport{
			ObjectMeta: metav1.ObjectMeta{
				Name: "clusterrole-admin",
				Labels: map[string]string{
					tunneloperator.LabelResourceKind: "ClusterRole",
					tunneloperator.LabelResourceName: "admin",
				},
			},
			Report: v1alpha1.RbacAssessmentReportData{
				Summary: v1alpha1.RbacAssessmentSummary{
					LowCount:      8,
					CriticalCount: 3,
				},
			},
		})
		require.NoError(t, err)

		var found v1alpha1.ClusterRbacAssessmentReport
		err = testClient.Get(context.TODO(), types.NamespacedName{Name: "clusterrole-admin"}, &found)
		require.NoError(t, err)

		assert.Equal(t, v1alpha1.ClusterRbacAssessmentReport{
			TypeMeta: metav1.TypeMeta{
				Kind:       "ClusterRbacAssessmentReport",
				APIVersion: "khulnasoft.github.io/v1alpha1",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name: "clusterrole-admin",
				Labels: map[string]string{
					tunneloperator.LabelResourceKind: "ClusterRole",
					tunneloperator.LabelResourceName: "admin",
				},
				ResourceVersion: "1",
			},
			Report: v1alpha1.RbacAssessmentReportData{
				Summary: v1alpha1.RbacAssessmentSummary{
					LowCount:      8,
					CriticalCount: 3,
				},
			},
		}, found)
	})

	t.Run("Should update ClusterRbacAssessmentReport", func(t *testing.T) {
		testClient := fake.NewClientBuilder().
			WithScheme(kubernetesScheme).
			WithObjects(
				&v1alpha1.ClusterRbacAssessmentReport{
					ObjectMeta: metav1.ObjectMeta{
						Name:            "clusterrole-admin",
						ResourceVersion: "0",
						Labels: map[string]string{
							tunneloperator.LabelResourceKind:     "ClusterRole",
							tunneloperator.LabelResourceName:     "admin",
							tunneloperator.LabelResourceSpecHash: "h1",
						},
					},
					Report: v1alpha1.RbacAssessmentReportData{
						Summary: v1alpha1.RbacAssessmentSummary{
							LowCount:      8,
							CriticalCount: 3,
						},
					},
				}).
			Build()
		resolver := kube.NewObjectResolver(testClient, &kube.CompatibleObjectMapper{})
		readWriter := rbacassessment.NewReadWriter(&resolver)
		err := readWriter.WriteClusterReport(context.TODO(), v1alpha1.ClusterRbacAssessmentReport{
			ObjectMeta: metav1.ObjectMeta{
				Name: "clusterrole-admin",
				Labels: map[string]string{
					tunneloperator.LabelResourceKind:     "ClusterRole",
					tunneloperator.LabelResourceName:     "admin",
					tunneloperator.LabelResourceSpecHash: "h2",
				},
			},
			Report: v1alpha1.RbacAssessmentReportData{
				Summary: v1alpha1.RbacAssessmentSummary{
					LowCount:      9,
					CriticalCount: 2,
				},
			},
		})
		require.NoError(t, err)

		var found v1alpha1.ClusterRbacAssessmentReport
		err = testClient.Get(context.TODO(), types.NamespacedName{Name: "clusterrole-admin"}, &found)
		require.NoError(t, err)

		assert.Equal(t, v1alpha1.ClusterRbacAssessmentReport{
			TypeMeta: metav1.TypeMeta{
				Kind:       "ClusterRbacAssessmentReport",
				APIVersion: "khulnasoft.github.io/v1alpha1",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name: "clusterrole-admin",
				Labels: map[string]string{
					tunneloperator.LabelResourceKind:     "ClusterRole",
					tunneloperator.LabelResourceName:     "admin",
					tunneloperator.LabelResourceSpecHash: "h2",
				},
				ResourceVersion: "1",
			},
			Report: v1alpha1.RbacAssessmentReportData{
				Summary: v1alpha1.RbacAssessmentSummary{
					LowCount:      9,
					CriticalCount: 2,
				},
			},
		}, found)
	})

	t.Run("Should find ClusterRbacAssessmentReport by owner", func(t *testing.T) {
		testClient := fake.NewClientBuilder().
			WithScheme(kubernetesScheme).
			WithObjects(
				&v1alpha1.ClusterRbacAssessmentReport{
					ObjectMeta: metav1.ObjectMeta{
						Name:            "clusterrole-viewer",
						ResourceVersion: "1",
						Labels: map[string]string{
							tunneloperator.LabelResourceKind:      "ClusterRole",
							tunneloperator.LabelResourceName:      "viewer",
							tunneloperator.LabelResourceNamespace: "",
						},
					},
					Report: v1alpha1.RbacAssessmentReportData{},
				},
				&v1alpha1.ClusterRbacAssessmentReport{
					ObjectMeta: metav1.ObjectMeta{
						Name:            "clusterrole-editor",
						ResourceVersion: "1",
						Labels: map[string]string{
							tunneloperator.LabelResourceKind:      "ClusterRole",
							tunneloperator.LabelResourceName:      "editor",
							tunneloperator.LabelResourceNamespace: "",
						},
					},
					Report: v1alpha1.RbacAssessmentReportData{},
				}, &v1beta1.CronJob{}).
			Build()
		resolver := kube.NewObjectResolver(testClient, &kube.CompatibleObjectMapper{})
		readWriter := rbacassessment.NewReadWriter(&resolver)
		found, err := readWriter.FindClusterReportByOwner(context.TODO(), kube.ObjectRef{
			Kind: "ClusterRole",
			Name: "editor",
		})
		require.NoError(t, err)
		assert.Equal(t, &v1alpha1.ClusterRbacAssessmentReport{
			ObjectMeta: metav1.ObjectMeta{
				Name:            "clusterrole-editor",
				ResourceVersion: "1",
				Labels: map[string]string{
					tunneloperator.LabelResourceKind:      "ClusterRole",
					tunneloperator.LabelResourceName:      "editor",
					tunneloperator.LabelResourceNamespace: "",
				},
			},
			Report: v1alpha1.RbacAssessmentReportData{},
		}, found)
	})
}
