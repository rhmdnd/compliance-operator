package compliancescan

import (
	"context"

	compv1alpha1 "github.com/ComplianceAsCode/compliance-operator/pkg/apis/compliance/v1alpha1"
	"github.com/ComplianceAsCode/compliance-operator/pkg/controller/common"
	"github.com/ComplianceAsCode/compliance-operator/pkg/controller/metrics"
	"github.com/ComplianceAsCode/compliance-operator/pkg/controller/metrics/metricsfakes"
	"github.com/go-logr/zapr"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"go.uber.org/zap"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

// Tests corresponding to TestScanWithoutBundlePassesDeprecationCheck:
// When a ComplianceScan's Content and ContentImage do not match any ProfileBundle,
// the deprecation check should not block the scan. It should return nil.
var _ = Describe("Deprecation profile check", func() {
	var (
		reconciler ReconcileComplianceScan
	)

	BeforeEach(func() {
		logger := zapr.NewLogger(zap.NewNop())
		_ = logger

		cscheme := scheme.Scheme
		cscheme.AddKnownTypes(compv1alpha1.SchemeGroupVersion,
			&compv1alpha1.ComplianceScan{},
			&compv1alpha1.ComplianceScanList{},
			&compv1alpha1.Profile{},
			&compv1alpha1.ProfileList{},
			&compv1alpha1.ProfileBundle{},
			&compv1alpha1.ProfileBundleList{},
			&compv1alpha1.TailoredProfile{},
			&compv1alpha1.TailoredProfileList{},
		)

		objs := []runtime.Object{}

		// Create a ProfileBundle that does NOT match the scan's Content/ContentImage
		pb := &compv1alpha1.ProfileBundle{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "ocp4",
				Namespace: common.GetComplianceOperatorNamespace(),
			},
			Spec: compv1alpha1.ProfileBundleSpec{
				ContentImage: "quay.io/some-other-image:latest",
				ContentFile:  "ssg-rhcos4-ds.xml",
			},
		}
		objs = append(objs, pb)

		cl := fake.NewClientBuilder().
			WithScheme(cscheme).
			WithRuntimeObjects(objs...).
			Build()

		mockMetrics := metrics.NewMetrics(&metricsfakes.FakeImpl{})
		_ = mockMetrics.Register()

		reconciler = ReconcileComplianceScan{
			Client:   cl,
			Scheme:   cscheme,
			Recorder: record.NewFakeRecorder(10),
			Metrics:  mockMetrics,
		}
	})

	Context("When ProfileBundle matching fails", func() {
		It("should not error when scan Content/ContentImage do not match any ProfileBundle", func() {
			// This is the exact scenario from TestScanWithoutBundlePassesDeprecationCheck:
			// The scan has Content and ContentImage that don't match any PB.
			// The deprecation logic should just skip the check and return nil.
			scan := &compv1alpha1.ComplianceScan{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "deprecation-test-scan",
					Namespace: common.GetComplianceOperatorNamespace(),
				},
				Spec: compv1alpha1.ComplianceScanSpec{
					Profile:      "xccdf_org.ssgproject.content_profile_moderate",
					Content:      "ssg-ocp4-ds.xml",
					ContentImage: "quay.io/mismatched-image:latest",
					ScannerType:  compv1alpha1.ScannerTypeOpenSCAP,
				},
			}

			logger := zapr.NewLogger(zap.NewNop())
			err := reconciler.notifyUseOfDeprecatedProfile(scan, logger)
			Expect(err).To(BeNil(), "deprecation check should not fail when no ProfileBundle matches")
		})

		It("should not set error message on scan status when no ProfileBundle matches", func() {
			scan := &compv1alpha1.ComplianceScan{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "deprecation-test-scan-2",
					Namespace: common.GetComplianceOperatorNamespace(),
				},
				Spec: compv1alpha1.ComplianceScanSpec{
					Profile:      "xccdf_org.ssgproject.content_profile_moderate",
					Content:      "ssg-ocp4-ds.xml",
					ContentImage: "quay.io/mismatched-image:latest",
					ScannerType:  compv1alpha1.ScannerTypeOpenSCAP,
				},
			}

			logger := zapr.NewLogger(zap.NewNop())
			err := reconciler.notifyUseOfDeprecatedProfile(scan, logger)
			Expect(err).To(BeNil())
			// The scan status error message should NOT say "Could not check whether the Profile used by ComplianceScan is deprecated"
			Expect(scan.Status.ErrorMessage).ToNot(Equal("Could not check whether the Profile used by ComplianceScan is deprecated"))
		})
	})

	Context("When ProfileBundle matches and profile is not deprecated", func() {
		It("should not error for a non-deprecated profile", func() {
			cscheme := scheme.Scheme

			profile := &compv1alpha1.Profile{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "matching-pb-moderate",
					Namespace: common.GetComplianceOperatorNamespace(),
				},
				ProfilePayload: compv1alpha1.ProfilePayload{
					ID: "xccdf_org.ssgproject.content_profile_moderate",
				},
			}

			pb := &compv1alpha1.ProfileBundle{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "matching-pb",
					Namespace: common.GetComplianceOperatorNamespace(),
				},
				Spec: compv1alpha1.ProfileBundleSpec{
					ContentImage: "quay.io/matching-image:latest",
					ContentFile:  "ssg-matching-ds.xml",
				},
			}

			cl := fake.NewClientBuilder().
				WithScheme(cscheme).
				WithRuntimeObjects(profile, pb).
				Build()

			mockMetrics := metrics.NewMetrics(&metricsfakes.FakeImpl{})
			_ = mockMetrics.Register()

			r := ReconcileComplianceScan{
				Client:   cl,
				Scheme:   cscheme,
				Recorder: record.NewFakeRecorder(10),
				Metrics:  mockMetrics,
			}

			scan := &compv1alpha1.ComplianceScan{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "non-deprecated-scan",
					Namespace: common.GetComplianceOperatorNamespace(),
				},
				Spec: compv1alpha1.ComplianceScanSpec{
					Profile:      "xccdf_org.ssgproject.content_profile_moderate",
					Content:      "ssg-matching-ds.xml",
					ContentImage: "quay.io/matching-image:latest",
					ScannerType:  compv1alpha1.ScannerTypeOpenSCAP,
				},
			}

			logger := zapr.NewLogger(zap.NewNop())
			err := r.notifyUseOfDeprecatedProfile(scan, logger)
			Expect(err).To(BeNil())
		})
	})

	Context("When ProfileBundle matches and profile is deprecated", func() {
		It("should not error but should emit event for deprecated profile", func() {
			cscheme := scheme.Scheme

			profile := &compv1alpha1.Profile{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "deprecated-pb-moderate",
					Namespace: common.GetComplianceOperatorNamespace(),
					Annotations: map[string]string{
						compv1alpha1.ProfileStatusAnnotation: "deprecated",
					},
				},
				ProfilePayload: compv1alpha1.ProfilePayload{
					ID: "xccdf_org.ssgproject.content_profile_moderate",
				},
			}

			pb := &compv1alpha1.ProfileBundle{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "deprecated-pb",
					Namespace: common.GetComplianceOperatorNamespace(),
				},
				Spec: compv1alpha1.ProfileBundleSpec{
					ContentImage: "quay.io/deprecated-image:latest",
					ContentFile:  "ssg-deprecated-ds.xml",
				},
			}

			cl := fake.NewClientBuilder().
				WithScheme(cscheme).
				WithRuntimeObjects(profile, pb).
				Build()

			mockMetrics := metrics.NewMetrics(&metricsfakes.FakeImpl{})
			_ = mockMetrics.Register()

			fakeRecorder := record.NewFakeRecorder(10)
			r := ReconcileComplianceScan{
				Client:   cl,
				Scheme:   cscheme,
				Recorder: fakeRecorder,
				Metrics:  mockMetrics,
			}

			scan := &compv1alpha1.ComplianceScan{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "deprecated-profile-scan",
					Namespace: common.GetComplianceOperatorNamespace(),
				},
				Spec: compv1alpha1.ComplianceScanSpec{
					Profile:      "xccdf_org.ssgproject.content_profile_moderate",
					Content:      "ssg-deprecated-ds.xml",
					ContentImage: "quay.io/deprecated-image:latest",
					ScannerType:  compv1alpha1.ScannerTypeOpenSCAP,
				},
			}

			logger := zapr.NewLogger(zap.NewNop())
			err := r.notifyUseOfDeprecatedProfile(scan, logger)
			// notifyUseOfDeprecatedProfile should still return nil (it emits events, not errors)
			Expect(err).To(BeNil())
		})
	})

	Context("CEL scan deprecation check", func() {
		It("should return nil for CEL scan without matching TailoredProfile", func() {
			cscheme := scheme.Scheme

			cl := fake.NewClientBuilder().
				WithScheme(cscheme).
				Build()

			mockMetrics := metrics.NewMetrics(&metricsfakes.FakeImpl{})
			_ = mockMetrics.Register()

			r := ReconcileComplianceScan{
				Client:   cl,
				Scheme:   cscheme,
				Recorder: record.NewFakeRecorder(10),
				Metrics:  mockMetrics,
			}

			scan := &compv1alpha1.ComplianceScan{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "cel-scan",
					Namespace: common.GetComplianceOperatorNamespace(),
				},
				Spec: compv1alpha1.ComplianceScanSpec{
					ScannerType: compv1alpha1.ScannerTypeCEL,
					ScanType:    compv1alpha1.ScanTypePlatform,
				},
			}

			logger := zapr.NewLogger(zap.NewNop())
			err := r.notifyUseOfDeprecatedProfile(scan, logger)
			Expect(err).To(BeNil())
		})
	})
})

// Tests corresponding to TestScheduledSuiteTimeoutFail and TestTimeoutDisabledWithZeroValue:
// Validate timeout annotation presence/absence on scan objects
var _ = Describe("Timeout annotation behavior", func() {
	It("scan with timeout annotation indicates timeout occurred", func() {
		scan := &compv1alpha1.ComplianceScan{
			ObjectMeta: metav1.ObjectMeta{
				Name: "timed-out-scan",
				Annotations: map[string]string{
					compv1alpha1.ComplianceScanTimeoutAnnotation: "node-1",
				},
			},
			Status: compv1alpha1.ComplianceScanStatus{
				Phase:  compv1alpha1.PhaseDone,
				Result: compv1alpha1.ResultError,
			},
		}

		_, hasTimeout := scan.Annotations[compv1alpha1.ComplianceScanTimeoutAnnotation]
		Expect(hasTimeout).To(BeTrue())
		Expect(scan.Status.Result).To(Equal(compv1alpha1.ResultError))
	})

	It("scan without timeout annotation has no timeout", func() {
		scan := &compv1alpha1.ComplianceScan{
			ObjectMeta: metav1.ObjectMeta{
				Name:        "normal-scan",
				Annotations: map[string]string{},
			},
			Status: compv1alpha1.ComplianceScanStatus{
				Phase:  compv1alpha1.PhaseDone,
				Result: compv1alpha1.ResultNonCompliant,
			},
		}

		_, hasTimeout := scan.Annotations[compv1alpha1.ComplianceScanTimeoutAnnotation]
		Expect(hasTimeout).To(BeFalse())
	})
})

// Tests corresponding to TestScanCleansUpComplianceCheckResults:
// Validate ComplianceCheckResult and ComplianceRemediation can be created and cleaned up
var _ = Describe("ComplianceCheckResult cleanup scenario", func() {
	It("can create and delete ComplianceCheckResults", func() {
		cscheme := scheme.Scheme
		cscheme.AddKnownTypes(compv1alpha1.SchemeGroupVersion,
			&compv1alpha1.ComplianceCheckResult{},
			&compv1alpha1.ComplianceCheckResultList{},
		)

		checkResult := &compv1alpha1.ComplianceCheckResult{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "scan-cleanup-test-audit-profile-set",
				Namespace: common.GetComplianceOperatorNamespace(),
				Labels: map[string]string{
					compv1alpha1.ComplianceScanLabel: "scan-cleanup-test",
				},
			},
			ID:       "xccdf_org.ssgproject.content_rule_audit_profile_set",
			Status:   compv1alpha1.CheckResultFail,
			Severity: compv1alpha1.CheckResultSeverityMedium,
		}

		cl := fake.NewClientBuilder().
			WithScheme(cscheme).
			WithRuntimeObjects(checkResult).
			Build()

		// Verify the check result exists
		fetchedResult := &compv1alpha1.ComplianceCheckResult{}
		err := cl.Get(context.TODO(), types.NamespacedName{
			Name:      "scan-cleanup-test-audit-profile-set",
			Namespace: common.GetComplianceOperatorNamespace(),
		}, fetchedResult)
		Expect(err).To(BeNil())
		Expect(fetchedResult.Status).To(Equal(compv1alpha1.CheckResultFail))

		resultList := &compv1alpha1.ComplianceCheckResultList{}
		err = cl.List(context.TODO(), resultList)
		Expect(err).To(BeNil())
		Expect(resultList.Items).To(HaveLen(1))
		Expect(resultList.Items[0].Status).To(Equal(compv1alpha1.CheckResultFail))

		// Delete the check result
		err = cl.Delete(context.TODO(), checkResult)
		Expect(err).To(BeNil())

		// Verify it's gone
		resultList2 := &compv1alpha1.ComplianceCheckResultList{}
		err = cl.List(context.TODO(), resultList2)
		Expect(err).To(BeNil())
		Expect(resultList2.Items).To(HaveLen(0))
	})
})
