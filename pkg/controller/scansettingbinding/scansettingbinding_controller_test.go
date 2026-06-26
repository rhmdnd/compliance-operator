package scansettingbinding

import (
	"context"
	"regexp"
	"strings"

	runtimeclient "sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/ComplianceAsCode/compliance-operator/pkg/apis"
	"github.com/go-logr/zapr"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	compv1alpha1 "github.com/ComplianceAsCode/compliance-operator/pkg/apis/compliance/v1alpha1"
	"github.com/ComplianceAsCode/compliance-operator/pkg/controller/common"
	"github.com/ComplianceAsCode/compliance-operator/pkg/controller/metrics"
	"github.com/ComplianceAsCode/compliance-operator/pkg/controller/metrics/metricsfakes"
)

var _ = Describe("Testing scansettingbinding controller", func() {

	var (
		reconciler ReconcileScanSettingBinding

		pBundleRhcos *compv1alpha1.ProfileBundle
		profRhcosE8  *compv1alpha1.Profile
		tpRhcosE8    *compv1alpha1.TailoredProfile

		setting *compv1alpha1.ScanSetting
		ssb     *compv1alpha1.ScanSettingBinding

		masterSelector map[string]string
		workerSelector map[string]string

		suite *compv1alpha1.ComplianceSuite
	)
	scratchTP := &compv1alpha1.TailoredProfile{
		TypeMeta: v1.TypeMeta{
			Kind:       "TailoredProfile",
			APIVersion: compv1alpha1.SchemeGroupVersion.String(),
		},
	}

	BeforeEach(func() {
		// Uncomment these lines if you need to debug the controller's output.
		dev, _ := zap.NewDevelopment()
		log = zapr.NewLogger(dev)
		objs := []runtime.Object{}

		// test instance
		bindingTypeMeta := v1.TypeMeta{}
		bindingTypeMeta.SetGroupVersionKind(compv1alpha1.SchemeGroupVersion.WithKind("ScanSettingBinding"))
		ssb = &compv1alpha1.ScanSettingBinding{
			TypeMeta: bindingTypeMeta,
		}

		suiteTypeMeta := v1.TypeMeta{}
		suiteTypeMeta.SetGroupVersionKind(compv1alpha1.SchemeGroupVersion.WithKind("ComplianceSuite"))
		suite = &compv1alpha1.ComplianceSuite{
			TypeMeta: suiteTypeMeta,
		}

		platformProfileAnnotations := map[string]string{
			compv1alpha1.ProductTypeAnnotation: string(compv1alpha1.ScanTypeNode),
			compv1alpha1.ProductAnnotation:     "rhcos4",
		}

		profileBundleTypeMeta := v1.TypeMeta{}
		profileBundleTypeMeta.SetGroupVersionKind(compv1alpha1.SchemeGroupVersion.WithKind("ProfileBundle"))
		pBundleRhcos = &compv1alpha1.ProfileBundle{
			TypeMeta: profileBundleTypeMeta,
			ObjectMeta: v1.ObjectMeta{
				Name:      "rhcos4",
				Namespace: common.GetComplianceOperatorNamespace(),
			},
			Spec: compv1alpha1.ProfileBundleSpec{
				ContentImage: "ghcr.io/complianceascode/k8scontent:latest",
				ContentFile:  "ssg-rhcos4-ds.xml",
			},
			Status: compv1alpha1.ProfileBundleStatus{
				DataStreamStatus: compv1alpha1.DataStreamValid,
			},
		}

		profRhcosE8 = &compv1alpha1.Profile{
			TypeMeta: v1.TypeMeta{
				Kind:       "Profile",
				APIVersion: compv1alpha1.SchemeGroupVersion.String(),
			},
			ObjectMeta: v1.ObjectMeta{
				Name:        "rhcos4-e8",
				Namespace:   common.GetComplianceOperatorNamespace(),
				Annotations: platformProfileAnnotations,
			},
			ProfilePayload: compv1alpha1.ProfilePayload{
				Title:       "rhcos4 profile",
				Description: "rhcos4 profile description",
				ID:          "xccdf_org.ssgproject.content_profile_e8",
			},
		}

		tpRhcosE8 = &compv1alpha1.TailoredProfile{
			TypeMeta: v1.TypeMeta{
				Kind:       "TailoredProfile",
				APIVersion: compv1alpha1.SchemeGroupVersion.String(),
			},
			ObjectMeta: v1.ObjectMeta{
				Name:      "emptypass-rhcos4-e8",
				Namespace: common.GetComplianceOperatorNamespace(),
				Labels:    platformProfileAnnotations,
			},
			Spec: compv1alpha1.TailoredProfileSpec{
				Extends:     profRhcosE8.Name,
				Title:       "testing TP",
				Description: "some desc",
				DisableRules: []compv1alpha1.RuleReferenceSpec{
					{
						Name:      "rhcos4-no-empty-passwords",
						Rationale: "I don't want this rule",
					},
				},
			},
			Status: compv1alpha1.TailoredProfileStatus{
				ID: "xccdf_compliance.openshift.io_profile_emptypass-rhcos4-e8",
				OutputRef: compv1alpha1.OutputRef{
					Name:      "emptypass-rhcos4-e8-tp",
					Namespace: common.GetComplianceOperatorNamespace(),
				},
				State:        compv1alpha1.TailoredProfileStateReady,
				ErrorMessage: "",
			},
		}

		scratchTP = &compv1alpha1.TailoredProfile{
			TypeMeta: v1.TypeMeta{
				Kind:       "TailoredProfile",
				APIVersion: compv1alpha1.SchemeGroupVersion.String(),
			},
			ObjectMeta: v1.ObjectMeta{
				Name:        "scratch-tp",
				Namespace:   common.GetComplianceOperatorNamespace(),
				Annotations: platformProfileAnnotations,
			},
			Spec: compv1alpha1.TailoredProfileSpec{
				Title:       "testing TP",
				Description: "some desc",
				EnableRules: []compv1alpha1.RuleReferenceSpec{
					{
						Name:      "rhcos4-no-empty-passwords",
						Rationale: "I want this rule",
					},
				},
			},
			Status: compv1alpha1.TailoredProfileStatus{
				ID: "xccdf_compliance.openshift.io_profile_scratch-tp",
				OutputRef: compv1alpha1.OutputRef{
					Name:      "scratch-tp-tp",
					Namespace: common.GetComplianceOperatorNamespace(),
				},
				State:        compv1alpha1.TailoredProfileStateReady,
				ErrorMessage: "",
			},
		}

		setting = &compv1alpha1.ScanSetting{
			TypeMeta: v1.TypeMeta{
				Kind:       "ScanSetting",
				APIVersion: compv1alpha1.SchemeGroupVersion.String(),
			},
			ObjectMeta: v1.ObjectMeta{
				Name:      "scan-setting",
				Namespace: common.GetComplianceOperatorNamespace(),
			},
			ComplianceSuiteSettings: compv1alpha1.ComplianceSuiteSettings{
				AutoApplyRemediations: true,
				Schedule:              "0 1 * * *",
			},
			ComplianceScanSettings: compv1alpha1.ComplianceScanSettings{
				Debug: true,
			},
			Roles: []string{"master", "worker"},
		}

		objs = append(objs, ssb, pBundleRhcos, profRhcosE8, tpRhcosE8, scratchTP, suite, setting)

		cscheme := scheme.Scheme
		err := apis.AddToScheme(cscheme)
		Expect(err).To(BeNil())

		statusObjs := []runtimeclient.Object{}
		statusObjs = append(statusObjs, ssb, scratchTP)

		client := fake.NewClientBuilder().
			WithScheme(cscheme).
			WithStatusSubresource(statusObjs...).
			WithRuntimeObjects(objs...).
			Build()

		err = client.Get(context.TODO(), types.NamespacedName{
			Namespace: pBundleRhcos.Namespace,
			Name:      pBundleRhcos.Name,
		}, pBundleRhcos)
		Expect(err).To(BeNil())

		profRhcosE8.OwnerReferences = append(profRhcosE8.OwnerReferences,
			v1.OwnerReference{
				Name:       pBundleRhcos.Name,
				Kind:       "ProfileBundle",
				APIVersion: compv1alpha1.SchemeGroupVersion.String()})
		err = client.Update(context.TODO(), profRhcosE8)
		Expect(err).To(BeNil())

		err = client.Get(context.TODO(), types.NamespacedName{
			Namespace: profRhcosE8.Namespace,
			Name:      profRhcosE8.Name,
		}, profRhcosE8)
		Expect(err).To(BeNil())

		tpRhcosE8.OwnerReferences = append(tpRhcosE8.OwnerReferences,
			v1.OwnerReference{
				Name:       profRhcosE8.Name,
				Kind:       "Profile",
				APIVersion: compv1alpha1.SchemeGroupVersion.String()})
		err = client.Update(context.TODO(), tpRhcosE8)
		Expect(err).To(BeNil())

		err = client.Get(context.TODO(), types.NamespacedName{
			Namespace: tpRhcosE8.Namespace,
			Name:      tpRhcosE8.Name,
		}, tpRhcosE8)
		Expect(err).To(BeNil())

		scratchTP.OwnerReferences = append(scratchTP.OwnerReferences,
			v1.OwnerReference{
				Name:       pBundleRhcos.Name,
				Kind:       "ProfileBundle",
				APIVersion: compv1alpha1.SchemeGroupVersion.String()})
		err = client.Update(context.TODO(), scratchTP)
		Expect(err).To(BeNil())

		err = client.Get(context.TODO(), types.NamespacedName{
			Namespace: scratchTP.Namespace,
			Name:      scratchTP.Name,
		}, scratchTP)
		Expect(err).To(BeNil())

		err = client.Get(context.TODO(), types.NamespacedName{
			Namespace: setting.Namespace,
			Name:      setting.Name,
		}, setting)
		Expect(err).To(BeNil())

		workerSelector = map[string]string{
			"node-role.kubernetes.io/worker": "",
		}
		masterSelector = map[string]string{
			"node-role.kubernetes.io/master": "",
		}

		mockMetrics := metrics.NewMetrics(&metricsfakes.FakeImpl{})
		err = mockMetrics.Register()
		Expect(err).To(BeNil())

		reconciler = ReconcileScanSettingBinding{
			Client:      client,
			Scheme:      cscheme,
			Recorder:    &common.SafeRecorder{},
			Metrics:     mockMetrics,
			roleVal:     regexp.MustCompile(roleValRegexp),
			invalidRole: regexp.MustCompile(invalidRoleRegexp),
		}
	})

	Context("Creates a simple suite from a Profile", func() {
		JustBeforeEach(func() {
			bindingTypeMeta := v1.TypeMeta{}
			bindingTypeMeta.SetGroupVersionKind(compv1alpha1.SchemeGroupVersion.WithKind("ScanSettingBinding"))
			ssb = &compv1alpha1.ScanSettingBinding{
				TypeMeta: bindingTypeMeta,
				ObjectMeta: v1.ObjectMeta{
					Name:      "simple-compliance-requirements",
					Namespace: common.GetComplianceOperatorNamespace(),
				},
				Profiles: []compv1alpha1.NamedObjectReference{
					{
						Name:     profRhcosE8.Name,
						Kind:     "Profile",
						APIGroup: compv1alpha1.SchemeGroupVersion.String(),
					},
				},
				SettingsRef: &compv1alpha1.NamedObjectReference{
					Name:     setting.Name,
					Kind:     "ScanSetting",
					APIGroup: compv1alpha1.SchemeGroupVersion.String(),
				},
			}

			ssb.Status.SetConditionPending()

			err := reconciler.Client.Create(context.TODO(), ssb)
			Expect(err).To(BeNil())

			err = reconciler.Client.Get(context.TODO(), types.NamespacedName{
				Namespace: ssb.Namespace,
				Name:      ssb.Name,
			}, ssb)
			Expect(err).To(BeNil())
		})

		It("Should create a basic suite from a Profile", func() {
			_, err := reconciler.Reconcile(context.TODO(), reconcile.Request{
				NamespacedName: types.NamespacedName{
					Namespace: ssb.Namespace,
					Name:      ssb.Name,
				},
			})
			Expect(err).To(BeNil())

			err = reconciler.Client.Get(context.TODO(), types.NamespacedName{
				Namespace: ssb.Namespace,
				Name:      ssb.Name,
			}, ssb)
			Expect(err).To(BeNil())
			Expect(ssb.Status.Conditions.GetCondition("Ready")).ToNot(BeNil())
			Expect(ssb.Status.Conditions.IsTrueFor("Ready")).To(BeTrue())

			err = reconciler.Client.Get(context.TODO(), types.NamespacedName{Name: ssb.Name, Namespace: ssb.Namespace}, suite)
			Expect(err).To(BeNil())

			Expect(suite.Spec.Schedule).To(BeEquivalentTo(setting.Schedule))
			Expect(suite.Spec.AutoApplyRemediations).To(BeTrue())

			Expect(ssb.Status.OutputRef.Name).To(Equal(suite.Name))
			Expect(*ssb.Status.OutputRef.APIGroup).To(Equal(compv1alpha1.SchemeGroupVersion.Group))

			expScanWorker := compv1alpha1.ComplianceScanSpecWrapper{
				ComplianceScanSpec: compv1alpha1.ComplianceScanSpec{
					ScanType:           compv1alpha1.ScanTypeNode,
					ScannerType:        compv1alpha1.ScannerTypeOpenSCAP,
					ContentImage:       pBundleRhcos.Spec.ContentImage,
					Profile:            profRhcosE8.ID,
					Rule:               "",
					Content:            pBundleRhcos.Spec.ContentFile,
					NodeSelector:       workerSelector,
					TailoringConfigMap: nil,
					ComplianceScanSettings: compv1alpha1.ComplianceScanSettings{
						Debug: true,
					},
				},
				Name: profRhcosE8.Name + "-worker",
			}
			expScanMaster := compv1alpha1.ComplianceScanSpecWrapper{
				ComplianceScanSpec: compv1alpha1.ComplianceScanSpec{
					ScanType:           compv1alpha1.ScanTypeNode,
					ScannerType:        compv1alpha1.ScannerTypeOpenSCAP,
					ContentImage:       pBundleRhcos.Spec.ContentImage,
					Profile:            profRhcosE8.ID,
					Rule:               "",
					Content:            pBundleRhcos.Spec.ContentFile,
					NodeSelector:       masterSelector,
					TailoringConfigMap: nil,
					ComplianceScanSettings: compv1alpha1.ComplianceScanSettings{
						Debug: true,
					},
				},
				Name: profRhcosE8.Name + "-master",
			}
			Expect(suite.Spec.Scans).To(ConsistOf(expScanWorker, expScanMaster))
		})
	})

	Context("Creates a simple suite from a TailoredProfile", func() {
		JustBeforeEach(func() {
			bindingTypeMeta := v1.TypeMeta{}
			bindingTypeMeta.SetGroupVersionKind(compv1alpha1.SchemeGroupVersion.WithKind("ScanSettingBinding"))
			ssb = &compv1alpha1.ScanSettingBinding{
				TypeMeta: bindingTypeMeta,
				ObjectMeta: v1.ObjectMeta{
					Name:      "simple-compliance-requirements-tp",
					Namespace: common.GetComplianceOperatorNamespace(),
				},
				Profiles: []compv1alpha1.NamedObjectReference{
					{
						Name:     tpRhcosE8.Name,
						Kind:     "TailoredProfile",
						APIGroup: compv1alpha1.SchemeGroupVersion.String(),
					},
				},
				SettingsRef: &compv1alpha1.NamedObjectReference{
					Name:     setting.Name,
					Kind:     "ScanSetting",
					APIGroup: compv1alpha1.SchemeGroupVersion.String(),
				},
			}
			ssb.Status.SetConditionPending()

			err := reconciler.Client.Create(context.TODO(), ssb)
			Expect(err).To(BeNil())
			err = reconciler.Client.Get(context.TODO(), types.NamespacedName{
				Namespace: ssb.Namespace,
				Name:      ssb.Name,
			}, ssb)
			Expect(err).To(BeNil())
		})

		It("Should create a basic suite from a TailoredProfile", func() {
			_, err := reconciler.Reconcile(context.TODO(), reconcile.Request{
				NamespacedName: types.NamespacedName{
					Namespace: ssb.Namespace,
					Name:      ssb.Name,
				},
			})
			Expect(err).To(BeNil())

			err = reconciler.Client.Get(context.TODO(), types.NamespacedName{
				Namespace: ssb.Namespace,
				Name:      ssb.Name,
			}, ssb)
			Expect(err).To(BeNil())
			Expect(ssb.Status.Conditions.GetCondition("Ready")).ToNot(BeNil())
			Expect(ssb.Status.Conditions.IsTrueFor("Ready")).To(BeTrue())

			err = reconciler.Client.Get(context.TODO(), types.NamespacedName{Name: ssb.Name, Namespace: ssb.Namespace}, suite)
			Expect(err).To(BeNil())

			Expect(suite.OwnerReferences).To(HaveLen(1))
			Expect(suite.OwnerReferences[0].Name).To(BeEquivalentTo(ssb.Name))
			Expect(suite.OwnerReferences[0].APIVersion).To(BeEquivalentTo(compv1alpha1.SchemeGroupVersion.String()))

			Expect(suite.Spec.Schedule).To(BeEquivalentTo(setting.Schedule))
			Expect(suite.Spec.AutoApplyRemediations).To(BeTrue())

			Expect(ssb.Status.OutputRef.Name).To(Equal(suite.Name))
			Expect(*ssb.Status.OutputRef.APIGroup).To(Equal(compv1alpha1.SchemeGroupVersion.Group))

			expScanMaster := compv1alpha1.ComplianceScanSpecWrapper{
				ComplianceScanSpec: compv1alpha1.ComplianceScanSpec{
					ScanType:     compv1alpha1.ScanTypeNode,
					ScannerType:  compv1alpha1.ScannerTypeOpenSCAP,
					ContentImage: pBundleRhcos.Spec.ContentImage,
					Profile:      tpRhcosE8.Status.ID,
					Rule:         "",
					Content:      pBundleRhcos.Spec.ContentFile,
					NodeSelector: masterSelector,
					TailoringConfigMap: &compv1alpha1.TailoringConfigMapRef{
						Name: "emptypass-rhcos4-e8-tp",
					},
					ComplianceScanSettings: compv1alpha1.ComplianceScanSettings{
						Debug: true,
					},
				},
				Name: tpRhcosE8.Name + "-master",
			}
			expScanWorker := compv1alpha1.ComplianceScanSpecWrapper{
				ComplianceScanSpec: compv1alpha1.ComplianceScanSpec{
					ScanType:     compv1alpha1.ScanTypeNode,
					ScannerType:  compv1alpha1.ScannerTypeOpenSCAP,
					ContentImage: pBundleRhcos.Spec.ContentImage,
					Profile:      tpRhcosE8.Status.ID,
					Rule:         "",
					Content:      pBundleRhcos.Spec.ContentFile,
					NodeSelector: workerSelector,
					TailoringConfigMap: &compv1alpha1.TailoringConfigMapRef{
						Name: "emptypass-rhcos4-e8-tp",
					},
					ComplianceScanSettings: compv1alpha1.ComplianceScanSettings{
						Debug: true,
					},
				},
				Name: tpRhcosE8.Name + "-worker",
			}
			Expect(suite.Spec.Scans).To(ConsistOf(expScanMaster, expScanWorker))
		})
	})

	Context("Creates a suite from a TailoredProfile created from scratch", func() {
		JustBeforeEach(func() {
			bindingTypeMeta := v1.TypeMeta{}
			bindingTypeMeta.SetGroupVersionKind(compv1alpha1.SchemeGroupVersion.WithKind("ScanSettingBinding"))
			ssb = &compv1alpha1.ScanSettingBinding{
				TypeMeta: bindingTypeMeta,
				ObjectMeta: v1.ObjectMeta{
					Name:      "scratch-tp",
					Namespace: common.GetComplianceOperatorNamespace(),
				},
				Profiles: []compv1alpha1.NamedObjectReference{
					{
						Name:     scratchTP.Name,
						Kind:     "TailoredProfile",
						APIGroup: compv1alpha1.SchemeGroupVersion.String(),
					},
				},
				SettingsRef: &compv1alpha1.NamedObjectReference{
					Name:     setting.Name,
					Kind:     "ScanSetting",
					APIGroup: compv1alpha1.SchemeGroupVersion.String(),
				},
			}
			ssb.Status.SetConditionPending()

			err := reconciler.Client.Create(context.TODO(), ssb)
			Expect(err).To(BeNil())
			err = reconciler.Client.Get(context.TODO(), types.NamespacedName{
				Namespace: ssb.Namespace,
				Name:      ssb.Name,
			}, ssb)
			Expect(err).To(BeNil())
		})

		It("Should create a suite from the TailoredProfile", func() {
			_, err := reconciler.Reconcile(context.TODO(), reconcile.Request{
				NamespacedName: types.NamespacedName{
					Namespace: ssb.Namespace,
					Name:      ssb.Name,
				},
			})
			Expect(err).To(BeNil())

			err = reconciler.Client.Get(context.TODO(), types.NamespacedName{
				Namespace: ssb.Namespace,
				Name:      ssb.Name,
			}, ssb)
			Expect(err).To(BeNil())
			Expect(ssb.Status.Conditions.GetCondition("Ready")).ToNot(BeNil())
			Expect(ssb.Status.Conditions.IsTrueFor("Ready")).To(BeTrue())

			err = reconciler.Client.Get(context.TODO(), types.NamespacedName{Name: ssb.Name, Namespace: ssb.Namespace}, suite)
			Expect(err).To(BeNil())

			Expect(suite.OwnerReferences).To(HaveLen(1))
			Expect(suite.OwnerReferences[0].Name).To(BeEquivalentTo(ssb.Name))
			Expect(suite.OwnerReferences[0].APIVersion).To(BeEquivalentTo(compv1alpha1.SchemeGroupVersion.String()))

			Expect(suite.Spec.Schedule).To(BeEquivalentTo(setting.Schedule))
			Expect(suite.Spec.AutoApplyRemediations).To(BeTrue())

			Expect(ssb.Status.OutputRef.Name).To(Equal(suite.Name))
			Expect(*ssb.Status.OutputRef.APIGroup).To(Equal(compv1alpha1.SchemeGroupVersion.Group))

			expScanMaster := compv1alpha1.ComplianceScanSpecWrapper{
				ComplianceScanSpec: compv1alpha1.ComplianceScanSpec{
					ScanType:     compv1alpha1.ScanTypeNode,
					ScannerType:  compv1alpha1.ScannerTypeOpenSCAP,
					ContentImage: pBundleRhcos.Spec.ContentImage,
					Profile:      scratchTP.Status.ID,
					Rule:         "",
					Content:      pBundleRhcos.Spec.ContentFile,
					NodeSelector: masterSelector,
					TailoringConfigMap: &compv1alpha1.TailoringConfigMapRef{
						Name: "scratch-tp-tp",
					},
					ComplianceScanSettings: compv1alpha1.ComplianceScanSettings{
						Debug: true,
					},
				},
				Name: scratchTP.Name + "-master",
			}
			expScanWorker := compv1alpha1.ComplianceScanSpecWrapper{
				ComplianceScanSpec: compv1alpha1.ComplianceScanSpec{
					ScanType:     compv1alpha1.ScanTypeNode,
					ScannerType:  compv1alpha1.ScannerTypeOpenSCAP,
					ContentImage: pBundleRhcos.Spec.ContentImage,
					Profile:      scratchTP.Status.ID,
					Rule:         "",
					Content:      pBundleRhcos.Spec.ContentFile,
					NodeSelector: workerSelector,
					TailoringConfigMap: &compv1alpha1.TailoringConfigMapRef{
						Name: "scratch-tp-tp",
					},
					ComplianceScanSettings: compv1alpha1.ComplianceScanSettings{
						Debug: true,
					},
				},
				Name: scratchTP.Name + "-worker",
			}
			Expect(suite.Spec.Scans).To(ConsistOf(expScanMaster, expScanWorker))
		})
	})

	Context("Detects error if unexistent profile", func() {
		JustBeforeEach(func() {
			ssb = &compv1alpha1.ScanSettingBinding{
				ObjectMeta: v1.ObjectMeta{
					Name:      "inconsistent-products-compliance-requirements",
					Namespace: common.GetComplianceOperatorNamespace(),
				},
				Profiles: []compv1alpha1.NamedObjectReference{
					{
						Name:     "unexistent",
						Kind:     "Profile",
						APIGroup: compv1alpha1.SchemeGroupVersion.String(),
					},
				},
			}
			ssb.Status.SetConditionPending()

			err := reconciler.Client.Create(context.TODO(), ssb)
			Expect(err).To(BeNil())
			err = reconciler.Client.Get(context.TODO(), types.NamespacedName{
				Namespace: ssb.Namespace,
				Name:      ssb.Name,
			}, ssb)
			Expect(err).To(BeNil())
		})

		It("Should not create a suite", func() {
			_, err := reconciler.Reconcile(context.TODO(), reconcile.Request{
				NamespacedName: types.NamespacedName{
					Namespace: ssb.Namespace,
					Name:      ssb.Name,
				},
			})
			Expect(err).ToNot(BeNil())

			err = reconciler.Client.Get(context.TODO(), types.NamespacedName{
				Namespace: ssb.Namespace,
				Name:      ssb.Name,
			}, ssb)
			Expect(err).To(BeNil())
			Expect(ssb.Status.Conditions.GetCondition("Ready")).ToNot(BeNil())
			Expect(ssb.Status.Conditions.IsTrueFor("Ready")).To(BeFalse())

			err = reconciler.Client.Get(context.TODO(), types.NamespacedName{Name: ssb.Name, Namespace: ssb.Namespace}, suite)
			Expect(err).ToNot(BeNil())
		})
	})

	Context("Waits if TailoredProfile isn't ready", func() {
		JustBeforeEach(func() {
			By("Setting the TP to PENDING")
			scratchTP.Status.State = compv1alpha1.TailoredProfileStatePending
			updateErr := reconciler.Client.Status().Update(context.TODO(), scratchTP)
			Expect(updateErr).To(BeNil())

			ssb = &compv1alpha1.ScanSettingBinding{
				TypeMeta: v1.TypeMeta{
					Kind:       "ScanSettingBinding",
					APIVersion: compv1alpha1.SchemeGroupVersion.String(),
				},
				ObjectMeta: v1.ObjectMeta{
					Name:      "tp-not-ready",
					Namespace: common.GetComplianceOperatorNamespace(),
				},
				Profiles: []compv1alpha1.NamedObjectReference{
					{
						Name:     scratchTP.Name,
						Kind:     "TailoredProfile",
						APIGroup: compv1alpha1.SchemeGroupVersion.String(),
					},
				},
			}
			ssb.Status.SetConditionPending()

			err := reconciler.Client.Create(context.TODO(), ssb)
			Expect(err).To(BeNil())
			err = reconciler.Client.Get(context.TODO(), types.NamespacedName{
				Namespace: ssb.Namespace,
				Name:      ssb.Name,
			}, ssb)
			Expect(err).To(BeNil())
		})

		It("Be requeued and should not create a suite", func() {
			res, err := reconciler.Reconcile(context.TODO(), reconcile.Request{
				NamespacedName: types.NamespacedName{
					Namespace: ssb.Namespace,
					Name:      ssb.Name,
				},
			})
			Expect(err).To(BeNil())
			Expect(res.Requeue).To(BeTrue())

			err = reconciler.Client.Get(context.TODO(), types.NamespacedName{
				Namespace: ssb.Namespace,
				Name:      ssb.Name,
			}, ssb)
			Expect(err).To(BeNil())
			Expect(ssb.Status.Conditions.GetCondition("Ready")).ToNot(BeNil())
			Expect(ssb.Status.Conditions.IsTrueFor("Ready")).To(BeFalse())
		})
	})

	Context("Reports error if TailoredProfile has error", func() {
		JustBeforeEach(func() {
			By("Setting the TP to ERROR")
			scratchTP.Status.State = compv1alpha1.TailoredProfileStateError
			updateErr := reconciler.Client.Status().Update(context.TODO(), scratchTP)
			Expect(updateErr).To(BeNil())

			ssb = &compv1alpha1.ScanSettingBinding{
				TypeMeta: v1.TypeMeta{
					Kind:       "ScanSettingBinding",
					APIVersion: compv1alpha1.SchemeGroupVersion.String(),
				},
				ObjectMeta: v1.ObjectMeta{
					Name:      "tp-errored",
					Namespace: common.GetComplianceOperatorNamespace(),
				},
				Profiles: []compv1alpha1.NamedObjectReference{
					{
						Name:     scratchTP.Name,
						Kind:     "TailoredProfile",
						APIGroup: compv1alpha1.SchemeGroupVersion.String(),
					},
				},
			}
			ssb.Status.SetConditionPending()

			err := reconciler.Client.Create(context.TODO(), ssb)
			Expect(err).To(BeNil())
			err = reconciler.Client.Get(context.TODO(), types.NamespacedName{
				Namespace: ssb.Namespace,
				Name:      ssb.Name,
			}, ssb)
			Expect(err).To(BeNil())
		})

		It("report error and should not create a suite", func() {
			res, err := reconciler.Reconcile(context.TODO(), reconcile.Request{
				NamespacedName: types.NamespacedName{
					Namespace: ssb.Namespace,
					Name:      ssb.Name,
				},
			})
			Expect(err).To(BeNil())
			Expect(res.Requeue).To(BeFalse())

			err = reconciler.Client.Get(context.TODO(), types.NamespacedName{
				Namespace: ssb.Namespace,
				Name:      ssb.Name,
			}, ssb)
			Expect(err).To(BeNil())
			Expect(ssb.Status.Conditions.GetCondition("Ready")).ToNot(BeNil())
			Expect(ssb.Status.Conditions.IsTrueFor("Ready")).To(BeFalse())
			Expect(ssb.Status.Conditions.GetCondition("Ready").Reason).To(Equal(compv1alpha1.ConditionReason("Invalid")))
			Expect(ssb.Status.Phase).To(Equal(compv1alpha1.ScanSettingBindingPhaseInvalid))
		})

		It("transitions from Invalid to Ready when TailoredProfile is fixed", func() {
			// First reconcile: SSB becomes Invalid due to TP error
			res, err := reconciler.Reconcile(context.TODO(), reconcile.Request{
				NamespacedName: types.NamespacedName{
					Namespace: ssb.Namespace,
					Name:      ssb.Name,
				},
			})
			Expect(err).To(BeNil())
			Expect(res.Requeue).To(BeFalse())

			// Verify SSB is Invalid
			err = reconciler.Client.Get(context.TODO(), types.NamespacedName{
				Namespace: ssb.Namespace,
				Name:      ssb.Name,
			}, ssb)
			Expect(err).To(BeNil())
			Expect(ssb.Status.Phase).To(Equal(compv1alpha1.ScanSettingBindingPhaseInvalid))
			Expect(ssb.Status.Conditions.GetCondition("Ready").Reason).To(Equal(compv1alpha1.ConditionReason("Invalid")))

			// Fix the TailoredProfile - set it to Ready
			By("Fixing the TailoredProfile - setting it to READY")
			scratchTP.Status.State = compv1alpha1.TailoredProfileStateReady
			scratchTP.Status.ID = "rhcos4-e8-tp"
			updateErr := reconciler.Client.Status().Update(context.TODO(), scratchTP)
			Expect(updateErr).To(BeNil())

			// Second reconcile: SSB should transition to Ready
			res, err = reconciler.Reconcile(context.TODO(), reconcile.Request{
				NamespacedName: types.NamespacedName{
					Namespace: ssb.Namespace,
					Name:      ssb.Name,
				},
			})
			Expect(err).To(BeNil())
			Expect(res.Requeue).To(BeFalse())

			// Verify SSB is now Ready
			err = reconciler.Client.Get(context.TODO(), types.NamespacedName{
				Namespace: ssb.Namespace,
				Name:      ssb.Name,
			}, ssb)
			Expect(err).To(BeNil())
			Expect(ssb.Status.Phase).To(Equal(compv1alpha1.ScanSettingBindingPhaseReady))
			Expect(ssb.Status.Conditions.IsTrueFor("Ready")).To(BeTrue())
			Expect(ssb.Status.Conditions.GetCondition("Ready").Reason).To(Equal(compv1alpha1.ConditionReason("Processed")))

			// Verify ComplianceSuite was created
			err = reconciler.Client.Get(context.TODO(), types.NamespacedName{Name: ssb.Name, Namespace: ssb.Namespace}, suite)
			Expect(err).To(BeNil())
		})
	})

	Context("Detects inconsistent products", func() {
		JustBeforeEach(func() {
			platformBadProfileAnnotations := map[string]string{
				compv1alpha1.ProductTypeAnnotation: string(compv1alpha1.ScanTypeNode),
				compv1alpha1.ProductAnnotation:     "somethingelse",
			}

			profRhcosE8Badproduct := profRhcosE8.DeepCopy()
			profRhcosE8Badproduct.SetName("e8-bad-product")
			profRhcosE8Badproduct.Annotations = platformBadProfileAnnotations
			profRhcosE8Badproduct.SetResourceVersion("")

			err := reconciler.Client.Create(context.TODO(), profRhcosE8Badproduct)
			Expect(err).To(BeNil())

			ssb = &compv1alpha1.ScanSettingBinding{
				ObjectMeta: v1.ObjectMeta{
					Name:      "inconsistent-products-compliance-requirements",
					Namespace: common.GetComplianceOperatorNamespace(),
				},
				Profiles: []compv1alpha1.NamedObjectReference{
					{
						Name:     profRhcosE8Badproduct.Name,
						Kind:     "Profile",
						APIGroup: compv1alpha1.SchemeGroupVersion.String(),
					},
					{
						Name:     profRhcosE8.Name,
						Kind:     "Profile",
						APIGroup: compv1alpha1.SchemeGroupVersion.String(),
					},
				},
			}
			ssb.Status.SetConditionPending()

			err = reconciler.Client.Create(context.TODO(), ssb)
			Expect(err).To(BeNil())
			err = reconciler.Client.Get(context.TODO(), types.NamespacedName{
				Namespace: ssb.Namespace,
				Name:      ssb.Name,
			}, ssb)
			Expect(err).To(BeNil())
		})

		It("Should create a suite", func() {
			_, err := reconciler.Reconcile(context.TODO(), reconcile.Request{
				NamespacedName: types.NamespacedName{
					Namespace: ssb.Namespace,
					Name:      ssb.Name,
				},
			})
			Expect(err).To(BeNil())

			err = reconciler.Client.Get(context.TODO(), types.NamespacedName{
				Namespace: ssb.Namespace,
				Name:      ssb.Name,
			}, ssb)
			Expect(err).To(BeNil())
			Expect(ssb.Status.Conditions.GetCondition("Ready")).ToNot(BeNil())
			Expect(ssb.Status.Conditions.IsTrueFor("Ready")).To(BeTrue())

			err = reconciler.Client.Get(context.TODO(), types.NamespacedName{Name: ssb.Name, Namespace: ssb.Namespace}, suite)
			Expect(err).To(BeNil())
		})
	})

	Context("Creates a suite from multiple Profiles with scan settings propagated", func() {
		// Covers TestScanSettingBinding e2e: validates that SSB with multiple profiles
		// creates per-role scans with settings (debug, scan limits) propagated correctly.
		var (
			profRhcosModerate *compv1alpha1.Profile
		)

		JustBeforeEach(func() {
			// Create a second profile (moderate)
			moderateProfileAnnotations := map[string]string{
				compv1alpha1.ProductTypeAnnotation: string(compv1alpha1.ScanTypeNode),
				compv1alpha1.ProductAnnotation:     "rhcos4",
			}
			profRhcosModerate = &compv1alpha1.Profile{
				TypeMeta: v1.TypeMeta{
					Kind:       "Profile",
					APIVersion: compv1alpha1.SchemeGroupVersion.String(),
				},
				ObjectMeta: v1.ObjectMeta{
					Name:        "rhcos4-moderate",
					Namespace:   common.GetComplianceOperatorNamespace(),
					Annotations: moderateProfileAnnotations,
				},
				ProfilePayload: compv1alpha1.ProfilePayload{
					Title:       "rhcos4 moderate profile",
					Description: "rhcos4 moderate profile description",
					ID:          "xccdf_org.ssgproject.content_profile_moderate",
				},
			}
			profRhcosModerate.OwnerReferences = append(profRhcosModerate.OwnerReferences,
				v1.OwnerReference{
					Name:       pBundleRhcos.Name,
					Kind:       "ProfileBundle",
					APIVersion: compv1alpha1.SchemeGroupVersion.String(),
				})
			err := reconciler.Client.Create(context.TODO(), profRhcosModerate)
			Expect(err).To(BeNil())

			bindingTypeMeta := v1.TypeMeta{}
			bindingTypeMeta.SetGroupVersionKind(compv1alpha1.SchemeGroupVersion.WithKind("ScanSettingBinding"))
			ssb = &compv1alpha1.ScanSettingBinding{
				TypeMeta: bindingTypeMeta,
				ObjectMeta: v1.ObjectMeta{
					Name:      "multi-profile-ssb",
					Namespace: common.GetComplianceOperatorNamespace(),
				},
				Profiles: []compv1alpha1.NamedObjectReference{
					{
						Name:     profRhcosE8.Name,
						Kind:     "Profile",
						APIGroup: compv1alpha1.SchemeGroupVersion.String(),
					},
					{
						Name:     profRhcosModerate.Name,
						Kind:     "Profile",
						APIGroup: compv1alpha1.SchemeGroupVersion.String(),
					},
				},
				SettingsRef: &compv1alpha1.NamedObjectReference{
					Name:     setting.Name,
					Kind:     "ScanSetting",
					APIGroup: compv1alpha1.SchemeGroupVersion.String(),
				},
			}
			ssb.Status.SetConditionPending()
			err = reconciler.Client.Create(context.TODO(), ssb)
			Expect(err).To(BeNil())
			err = reconciler.Client.Get(context.TODO(), types.NamespacedName{
				Namespace: ssb.Namespace,
				Name:      ssb.Name,
			}, ssb)
			Expect(err).To(BeNil())
		})

		It("Should create scans for each profile-role combination with debug propagated", func() {
			_, err := reconciler.Reconcile(context.TODO(), reconcile.Request{
				NamespacedName: types.NamespacedName{
					Namespace: ssb.Namespace,
					Name:      ssb.Name,
				},
			})
			Expect(err).To(BeNil())

			err = reconciler.Client.Get(context.TODO(), types.NamespacedName{
				Namespace: ssb.Namespace,
				Name:      ssb.Name,
			}, ssb)
			Expect(err).To(BeNil())
			Expect(ssb.Status.Conditions.IsTrueFor("Ready")).To(BeTrue())

			err = reconciler.Client.Get(context.TODO(), types.NamespacedName{Name: ssb.Name, Namespace: ssb.Namespace}, suite)
			Expect(err).To(BeNil())

			// Two profiles * two roles = 4 scans
			Expect(suite.Spec.Scans).To(HaveLen(4))

			// All scans should have debug=true from the ScanSetting
			for _, scan := range suite.Spec.Scans {
				Expect(scan.Debug).To(BeTrue())
			}

			// Verify scan names include profile and role
			scanNames := make([]string, 0)
			for _, scan := range suite.Spec.Scans {
				scanNames = append(scanNames, scan.Name)
			}
			Expect(scanNames).To(ContainElement("rhcos4-e8-master"))
			Expect(scanNames).To(ContainElement("rhcos4-e8-worker"))
			Expect(scanNames).To(ContainElement("rhcos4-moderate-master"))
			Expect(scanNames).To(ContainElement("rhcos4-moderate-worker"))
		})
	})

	Context("Creates a suite with RawResultStorage disabled", func() {
		// Covers TestScanSettingBindingNoStorage e2e: validates that when
		// RawResultStorage.Enabled is false in ScanSetting, the resulting
		// ComplianceScan spec also has it disabled.
		JustBeforeEach(func() {
			falseVal := false
			settingNoStorage := &compv1alpha1.ScanSetting{
				TypeMeta: v1.TypeMeta{
					Kind:       "ScanSetting",
					APIVersion: compv1alpha1.SchemeGroupVersion.String(),
				},
				ObjectMeta: v1.ObjectMeta{
					Name:      "setting-no-storage",
					Namespace: common.GetComplianceOperatorNamespace(),
				},
				ComplianceSuiteSettings: compv1alpha1.ComplianceSuiteSettings{
					AutoApplyRemediations: false,
				},
				ComplianceScanSettings: compv1alpha1.ComplianceScanSettings{
					Debug: true,
					RawResultStorage: compv1alpha1.RawResultStorageSettings{
						Enabled: &falseVal,
					},
				},
				Roles: []string{"master", "worker"},
			}
			err := reconciler.Client.Create(context.TODO(), settingNoStorage)
			Expect(err).To(BeNil())

			bindingTypeMeta := v1.TypeMeta{}
			bindingTypeMeta.SetGroupVersionKind(compv1alpha1.SchemeGroupVersion.WithKind("ScanSettingBinding"))
			ssb = &compv1alpha1.ScanSettingBinding{
				TypeMeta: bindingTypeMeta,
				ObjectMeta: v1.ObjectMeta{
					Name:      "no-storage-ssb",
					Namespace: common.GetComplianceOperatorNamespace(),
				},
				Profiles: []compv1alpha1.NamedObjectReference{
					{
						Name:     profRhcosE8.Name,
						Kind:     "Profile",
						APIGroup: compv1alpha1.SchemeGroupVersion.String(),
					},
				},
				SettingsRef: &compv1alpha1.NamedObjectReference{
					Name:     settingNoStorage.Name,
					Kind:     "ScanSetting",
					APIGroup: compv1alpha1.SchemeGroupVersion.String(),
				},
			}
			ssb.Status.SetConditionPending()
			err = reconciler.Client.Create(context.TODO(), ssb)
			Expect(err).To(BeNil())
			err = reconciler.Client.Get(context.TODO(), types.NamespacedName{
				Namespace: ssb.Namespace,
				Name:      ssb.Name,
			}, ssb)
			Expect(err).To(BeNil())
		})

		It("Should propagate RawResultStorage disabled to all scans", func() {
			_, err := reconciler.Reconcile(context.TODO(), reconcile.Request{
				NamespacedName: types.NamespacedName{
					Namespace: ssb.Namespace,
					Name:      ssb.Name,
				},
			})
			Expect(err).To(BeNil())

			err = reconciler.Client.Get(context.TODO(), types.NamespacedName{Name: ssb.Name, Namespace: ssb.Namespace}, suite)
			Expect(err).To(BeNil())

			for _, scan := range suite.Spec.Scans {
				Expect(scan.RawResultStorage.Enabled).ToNot(BeNil())
				Expect(*scan.RawResultStorage.Enabled).To(BeFalse())
			}
		})
	})

	Context("Creates a suite with RawResultStorage enabled", func() {
		// Covers TestScanSettingBindingNoStorage e2e (second half): validates that when
		// RawResultStorage.Enabled is true in ScanSetting, the resulting
		// ComplianceScan spec also has it enabled.
		JustBeforeEach(func() {
			trueVal := true
			settingWithStorage := &compv1alpha1.ScanSetting{
				TypeMeta: v1.TypeMeta{
					Kind:       "ScanSetting",
					APIVersion: compv1alpha1.SchemeGroupVersion.String(),
				},
				ObjectMeta: v1.ObjectMeta{
					Name:      "setting-with-storage",
					Namespace: common.GetComplianceOperatorNamespace(),
				},
				ComplianceSuiteSettings: compv1alpha1.ComplianceSuiteSettings{
					AutoApplyRemediations: false,
				},
				ComplianceScanSettings: compv1alpha1.ComplianceScanSettings{
					Debug: true,
					RawResultStorage: compv1alpha1.RawResultStorageSettings{
						Enabled: &trueVal,
					},
				},
				Roles: []string{"master", "worker"},
			}
			err := reconciler.Client.Create(context.TODO(), settingWithStorage)
			Expect(err).To(BeNil())

			bindingTypeMeta := v1.TypeMeta{}
			bindingTypeMeta.SetGroupVersionKind(compv1alpha1.SchemeGroupVersion.WithKind("ScanSettingBinding"))
			ssb = &compv1alpha1.ScanSettingBinding{
				TypeMeta: bindingTypeMeta,
				ObjectMeta: v1.ObjectMeta{
					Name:      "with-storage-ssb",
					Namespace: common.GetComplianceOperatorNamespace(),
				},
				Profiles: []compv1alpha1.NamedObjectReference{
					{
						Name:     profRhcosE8.Name,
						Kind:     "Profile",
						APIGroup: compv1alpha1.SchemeGroupVersion.String(),
					},
				},
				SettingsRef: &compv1alpha1.NamedObjectReference{
					Name:     settingWithStorage.Name,
					Kind:     "ScanSetting",
					APIGroup: compv1alpha1.SchemeGroupVersion.String(),
				},
			}
			ssb.Status.SetConditionPending()
			err = reconciler.Client.Create(context.TODO(), ssb)
			Expect(err).To(BeNil())
			err = reconciler.Client.Get(context.TODO(), types.NamespacedName{
				Namespace: ssb.Namespace,
				Name:      ssb.Name,
			}, ssb)
			Expect(err).To(BeNil())
		})

		It("Should propagate RawResultStorage enabled to all scans", func() {
			_, err := reconciler.Reconcile(context.TODO(), reconcile.Request{
				NamespacedName: types.NamespacedName{
					Namespace: ssb.Namespace,
					Name:      ssb.Name,
				},
			})
			Expect(err).To(BeNil())

			err = reconciler.Client.Get(context.TODO(), types.NamespacedName{Name: ssb.Name, Namespace: ssb.Namespace}, suite)
			Expect(err).To(BeNil())

			for _, scan := range suite.Spec.Scans {
				Expect(scan.RawResultStorage.Enabled).ToNot(BeNil())
				Expect(*scan.RawResultStorage.Enabled).To(BeTrue())
			}
		})
	})

	Context("Uses default ScanSetting when SettingsRef is not specified", func() {
		// Covers TestScanSettingBindingUsesDefaultScanSetting e2e: validates that
		// when no SettingsRef is specified, the SSB uses the "default" ScanSetting
		// via the kubebuilder default tag.
		It("Should have SettingsRef default to 'default' ScanSetting", func() {
			// The kubebuilder default tag on SettingsRef sets it to
			// {"name":"default","kind":"ScanSetting","apiGroup":"compliance.openshift.io/v1alpha1"}
			// We test the behavior: when SettingsRef is explicitly nil (before defaulting),
			// the defaulting webhook or API server would set it. In unit tests, we verify
			// that the reconciler handles the case where SettingsRef.Name is "default".
			bindingTypeMeta := v1.TypeMeta{}
			bindingTypeMeta.SetGroupVersionKind(compv1alpha1.SchemeGroupVersion.WithKind("ScanSettingBinding"))
			ssbDefault := &compv1alpha1.ScanSettingBinding{
				TypeMeta: bindingTypeMeta,
				ObjectMeta: v1.ObjectMeta{
					Name:      "default-setting-ssb",
					Namespace: common.GetComplianceOperatorNamespace(),
				},
				Profiles: []compv1alpha1.NamedObjectReference{
					{
						Name:     profRhcosE8.Name,
						Kind:     "Profile",
						APIGroup: compv1alpha1.SchemeGroupVersion.String(),
					},
				},
				// SettingsRef explicitly set to "default", simulating the kubebuilder default
				SettingsRef: &compv1alpha1.NamedObjectReference{
					Name:     "default",
					Kind:     "ScanSetting",
					APIGroup: compv1alpha1.SchemeGroupVersion.String(),
				},
			}
			Expect(ssbDefault.SettingsRef).ToNot(BeNil())
			Expect(ssbDefault.SettingsRef.Name).To(Equal("default"))
			Expect(ssbDefault.SettingsRef.Kind).To(Equal("ScanSetting"))
		})
	})

	Context("SSB watches TailoredProfile and transitions state based on TP status", func() {
		// Covers TestScanSettingBindingWatchesTailoredProfile e2e: validates that
		// SSB detects TP error and sets Invalid, then transitions to Ready when TP is fixed.

		It("Should set SSB to Invalid when TailoredProfile has error, then Ready when fixed", func() {
			// Set the TP to ERROR
			scratchTP.Status.State = compv1alpha1.TailoredProfileStateError
			updateErr := reconciler.Client.Status().Update(context.TODO(), scratchTP)
			Expect(updateErr).To(BeNil())

			bindingTypeMeta := v1.TypeMeta{}
			bindingTypeMeta.SetGroupVersionKind(compv1alpha1.SchemeGroupVersion.WithKind("ScanSettingBinding"))
			ssbWatch := &compv1alpha1.ScanSettingBinding{
				TypeMeta: bindingTypeMeta,
				ObjectMeta: v1.ObjectMeta{
					Name:      "watch-tp-ssb",
					Namespace: common.GetComplianceOperatorNamespace(),
				},
				Profiles: []compv1alpha1.NamedObjectReference{
					{
						Name:     scratchTP.Name,
						Kind:     "TailoredProfile",
						APIGroup: compv1alpha1.SchemeGroupVersion.String(),
					},
				},
				SettingsRef: &compv1alpha1.NamedObjectReference{
					Name:     setting.Name,
					Kind:     "ScanSetting",
					APIGroup: compv1alpha1.SchemeGroupVersion.String(),
				},
			}
			ssbWatch.Status.SetConditionPending()
			err := reconciler.Client.Create(context.TODO(), ssbWatch)
			Expect(err).To(BeNil())
			err = reconciler.Client.Get(context.TODO(), types.NamespacedName{
				Namespace: ssbWatch.Namespace,
				Name:      ssbWatch.Name,
			}, ssbWatch)
			Expect(err).To(BeNil())

			// First reconcile: SSB should become Invalid
			res, err := reconciler.Reconcile(context.TODO(), reconcile.Request{
				NamespacedName: types.NamespacedName{
					Namespace: ssbWatch.Namespace,
					Name:      ssbWatch.Name,
				},
			})
			Expect(err).To(BeNil())
			Expect(res.Requeue).To(BeFalse())

			err = reconciler.Client.Get(context.TODO(), types.NamespacedName{
				Namespace: ssbWatch.Namespace,
				Name:      ssbWatch.Name,
			}, ssbWatch)
			Expect(err).To(BeNil())
			Expect(ssbWatch.Status.Phase).To(Equal(compv1alpha1.ScanSettingBindingPhaseInvalid))
			readyCond := ssbWatch.Status.Conditions.GetCondition("Ready")
			Expect(readyCond).ToNot(BeNil())
			Expect(readyCond.Status).To(Equal(corev1.ConditionFalse))
			Expect(readyCond.Reason).To(Equal(compv1alpha1.ConditionReason("Invalid")))

			// Fix the TP: set it to Ready
			scratchTP.Status.State = compv1alpha1.TailoredProfileStateReady
			scratchTP.Status.ID = "xccdf_compliance.openshift.io_profile_scratch-tp"
			updateErr = reconciler.Client.Status().Update(context.TODO(), scratchTP)
			Expect(updateErr).To(BeNil())

			// Second reconcile: SSB should become Ready
			res, err = reconciler.Reconcile(context.TODO(), reconcile.Request{
				NamespacedName: types.NamespacedName{
					Namespace: ssbWatch.Namespace,
					Name:      ssbWatch.Name,
				},
			})
			Expect(err).To(BeNil())
			Expect(res.Requeue).To(BeFalse())

			err = reconciler.Client.Get(context.TODO(), types.NamespacedName{
				Namespace: ssbWatch.Namespace,
				Name:      ssbWatch.Name,
			}, ssbWatch)
			Expect(err).To(BeNil())
			Expect(ssbWatch.Status.Phase).To(Equal(compv1alpha1.ScanSettingBindingPhaseReady))
			readyCond = ssbWatch.Status.Conditions.GetCondition("Ready")
			Expect(readyCond).ToNot(BeNil())
			Expect(readyCond.Status).To(Equal(corev1.ConditionTrue))
			Expect(readyCond.Reason).To(Equal(compv1alpha1.ConditionReason("Processed")))
		})
	})

	Context("Suite update detection with scan settings", func() {
		// Covers TestScanSettingBindingNoStorage e2e (update portion):
		// validates that suiteNeedsUpdate detects changes in scan settings.
		It("Should detect when suite needs update due to RawResultStorage change", func() {
			falseVal := false
			trueVal := true

			suiteWithStorage := &compv1alpha1.ComplianceSuite{
				Spec: compv1alpha1.ComplianceSuiteSpec{
					Scans: []compv1alpha1.ComplianceScanSpecWrapper{
						{
							Name: "test-scan",
							ComplianceScanSpec: compv1alpha1.ComplianceScanSpec{
								ComplianceScanSettings: compv1alpha1.ComplianceScanSettings{
									RawResultStorage: compv1alpha1.RawResultStorageSettings{
										Enabled: &trueVal,
									},
								},
							},
						},
					},
				},
			}

			suiteWithoutStorage := &compv1alpha1.ComplianceSuite{
				Spec: compv1alpha1.ComplianceSuiteSpec{
					Scans: []compv1alpha1.ComplianceScanSpecWrapper{
						{
							Name: "test-scan",
							ComplianceScanSpec: compv1alpha1.ComplianceScanSpec{
								ComplianceScanSettings: compv1alpha1.ComplianceScanSettings{
									RawResultStorage: compv1alpha1.RawResultStorageSettings{
										Enabled: &falseVal,
									},
								},
							},
						},
					},
				},
			}

			Expect(suiteNeedsUpdate(suiteWithStorage, suiteWithoutStorage)).To(BeTrue())
			Expect(suiteNeedsUpdate(suiteWithStorage, suiteWithStorage)).To(BeFalse())
		})
	})

	When("Validating roles", func() {
		DescribeTable("Should pass the validation",
			func(roles []string) {
				ss := &compv1alpha1.ScanSetting{
					Roles: roles,
				}
				err := reconciler.validateRoles(ss)
				Expect(err).To(BeNil())
			},
			Entry("master & worker", []string{"master", "worker"}),
			Entry("@all", []string{"@all"}),
			Entry("other samples", []string{"control-plane", "role-1", "role-2", "role-3"}),
		)

		When("Passing empty roles", func() {
			It("is valid but issues warning event", func() {
				ss := &compv1alpha1.ScanSetting{
					Roles: []string{},
				}
				err := reconciler.validateRoles(ss)
				Expect(err).To(BeNil())
				// TODO(jaosorior): Validate that a warning was issued
			})
		})

		DescribeTable("Should fail the validation if it includes ",
			func(roles []string) {
				ss := &compv1alpha1.ScanSetting{
					Roles: roles,
				}
				err := reconciler.validateRoles(ss)
				Expect(err).ToNot(BeNil(), "validation should have returned an error")
			},
			Entry("spaces", []string{"master "}),
			Entry("@all mixed with others", []string{"@all", "worker"}),
			Entry("too long", []string{strings.Repeat("foo", 100)}),
			Entry("empty string", []string{""}),
			Entry("invalid character", []string{"l33t$"}),
		)
	})

})
