package v1alpha1

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var _ = Describe("ComplianceSuite type helpers", func() {

	// Corresponds to e2e TestSuiteWithInvalidScheduleShowsError and
	// TestScheduledSuite
	When("testing suite settings", func() {
		It("ShouldApplyRemediations returns false when not set", func() {
			suite := &ComplianceSuite{
				Spec: ComplianceSuiteSpec{
					ComplianceSuiteSettings: ComplianceSuiteSettings{
						AutoApplyRemediations: false,
					},
				},
			}
			Expect(suite.ShouldApplyRemediations()).To(BeFalse())
		})

		It("ShouldApplyRemediations returns true when AutoApplyRemediations is set", func() {
			suite := &ComplianceSuite{
				Spec: ComplianceSuiteSpec{
					ComplianceSuiteSettings: ComplianceSuiteSettings{
						AutoApplyRemediations: true,
					},
				},
			}
			Expect(suite.ShouldApplyRemediations()).To(BeTrue())
		})

		It("ShouldApplyRemediations returns true when annotation is set", func() {
			suite := &ComplianceSuite{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						ApplyRemediationsAnnotation: "",
					},
				},
			}
			Expect(suite.ShouldApplyRemediations()).To(BeTrue())
		})
	})

	// Corresponds to e2e TestScheduledSuite (schedule field)
	When("testing schedule settings", func() {
		It("stores the schedule in the spec", func() {
			suite := &ComplianceSuite{
				Spec: ComplianceSuiteSpec{
					ComplianceSuiteSettings: ComplianceSuiteSettings{
						Schedule: "*/2 * * * *",
					},
				},
			}
			Expect(suite.Spec.Schedule).To(Equal("*/2 * * * *"))
		})

		It("stores an empty schedule", func() {
			suite := &ComplianceSuite{
				Spec: ComplianceSuiteSpec{
					ComplianceSuiteSettings: ComplianceSuiteSettings{
						Schedule: "",
					},
				},
			}
			Expect(suite.Spec.Schedule).To(BeEmpty())
		})
	})

	When("computing LowestCommonState", func() {
		It("returns PhasePending when no scan statuses exist", func() {
			suite := &ComplianceSuite{}
			Expect(suite.LowestCommonState()).To(Equal(PhasePending))
		})

		It("returns PhaseDone when all scans are done", func() {
			suite := &ComplianceSuite{
				Status: ComplianceSuiteStatus{
					ScanStatuses: []ComplianceScanStatusWrapper{
						{ComplianceScanStatus: ComplianceScanStatus{Phase: PhaseDone}},
						{ComplianceScanStatus: ComplianceScanStatus{Phase: PhaseDone}},
					},
				},
			}
			Expect(suite.LowestCommonState()).To(Equal(PhaseDone))
		})
	})

	When("computing LowestCommonResult", func() {
		It("returns ResultNotAvailable when no scan statuses exist", func() {
			suite := &ComplianceSuite{}
			Expect(suite.LowestCommonResult()).To(Equal(ResultNotAvailable))
		})

		It("returns ResultCompliant when all scans are compliant", func() {
			suite := &ComplianceSuite{
				Status: ComplianceSuiteStatus{
					ScanStatuses: []ComplianceScanStatusWrapper{
						{ComplianceScanStatus: ComplianceScanStatus{Result: ResultCompliant}},
					},
				},
			}
			Expect(suite.LowestCommonResult()).To(Equal(ResultCompliant))
		})
	})

	When("testing ComplianceScanFromWrapper", func() {
		It("creates a scan with the wrapper name", func() {
			sw := &ComplianceScanSpecWrapper{
				Name: "test-scan",
				ComplianceScanSpec: ComplianceScanSpec{
					Profile: "xccdf_org.ssgproject.content_profile_moderate",
				},
			}
			scan := ComplianceScanFromWrapper(sw)
			Expect(scan.Name).To(Equal("test-scan"))
			Expect(scan.Spec.Profile).To(Equal("xccdf_org.ssgproject.content_profile_moderate"))
		})
	})

	// Corresponds to e2e TestScheduledSuiteNoStorage and TestScheduledSuitePlatformNoStorage
	When("testing RawResultStorage settings", func() {
		It("defaults Enabled to nil (which means true by default)", func() {
			settings := RawResultStorageSettings{}
			Expect(settings.Enabled).To(BeNil())
		})

		It("can be set to false to disable storage", func() {
			falseVal := false
			settings := RawResultStorageSettings{
				Enabled: &falseVal,
			}
			Expect(*settings.Enabled).To(BeFalse())
		})

		It("can be set to true explicitly", func() {
			trueVal := true
			settings := RawResultStorageSettings{
				Enabled: &trueVal,
			}
			Expect(*settings.Enabled).To(BeTrue())
		})
	})

	// Corresponds to e2e TestScheduledSuitePlatformNoStorage
	When("testing scan type constants", func() {
		It("ScanTypePlatform is set correctly", func() {
			Expect(string(ScanTypePlatform)).To(Equal("Platform"))
		})

		It("ScanTypeNode is set correctly", func() {
			Expect(string(ScanTypeNode)).To(Equal("Node"))
		})
	})

	// Corresponds to e2e TestScheduledSuiteUpdate
	When("testing ScanSpecDiffers", func() {
		It("returns false when specs are identical", func() {
			sw := &ComplianceScanSpecWrapper{
				Name: "test-scan",
				ComplianceScanSpec: ComplianceScanSpec{
					Profile: "test-profile",
					ComplianceScanSettings: ComplianceScanSettings{
						RawResultStorage: RawResultStorageSettings{
							Size:     DefaultRawStorageSize,
							Rotation: DefaultStorageRotation,
						},
					},
				},
			}
			scan := &ComplianceScan{
				ObjectMeta: metav1.ObjectMeta{Name: "test-scan"},
				Spec: ComplianceScanSpec{
					Profile: "test-profile",
					ComplianceScanSettings: ComplianceScanSettings{
						RawResultStorage: RawResultStorageSettings{
							Size:     DefaultRawStorageSize,
							Rotation: DefaultStorageRotation,
						},
					},
				},
			}
			Expect(sw.ScanSpecDiffers(scan)).To(BeFalse())
		})

		It("returns true when profile differs", func() {
			sw := &ComplianceScanSpecWrapper{
				Name: "test-scan",
				ComplianceScanSpec: ComplianceScanSpec{
					Profile: "new-profile",
					ComplianceScanSettings: ComplianceScanSettings{
						RawResultStorage: RawResultStorageSettings{
							Size:     DefaultRawStorageSize,
							Rotation: DefaultStorageRotation,
						},
					},
				},
			}
			scan := &ComplianceScan{
				ObjectMeta: metav1.ObjectMeta{Name: "test-scan"},
				Spec: ComplianceScanSpec{
					Profile: "old-profile",
					ComplianceScanSettings: ComplianceScanSettings{
						RawResultStorage: RawResultStorageSettings{
							Size:     DefaultRawStorageSize,
							Rotation: DefaultStorageRotation,
						},
					},
				},
			}
			Expect(sw.ScanSpecDiffers(scan)).To(BeTrue())
		})

		It("returns true when name differs", func() {
			sw := &ComplianceScanSpecWrapper{
				Name:               "scan-a",
				ComplianceScanSpec: ComplianceScanSpec{},
			}
			scan := &ComplianceScan{
				ObjectMeta: metav1.ObjectMeta{Name: "scan-b"},
				Spec:       ComplianceScanSpec{},
			}
			Expect(sw.ScanSpecDiffers(scan)).To(BeTrue())
		})
	})
})
