package v1alpha1

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var _ = Describe("ComplianceScan type validation", func() {
	var scan *ComplianceScan

	BeforeEach(func() {
		scan = &ComplianceScan{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-scan",
				Namespace: "test-ns",
			},
			Spec: ComplianceScanSpec{
				Profile:      "xccdf_org.ssgproject.content_profile_moderate",
				Content:      "ssg-rhcos4-ds.xml",
				ContentImage: "quay.io/example/content:latest",
			},
		}
	})

	Context("GetScanTypeIfValid", func() {
		It("returns ScanTypeNode for 'Node' scan type", func() {
			scan.Spec.ScanType = ScanTypeNode
			scanType, err := scan.GetScanTypeIfValid()
			Expect(err).To(BeNil())
			Expect(scanType).To(Equal(ScanTypeNode))
		})

		It("returns ScanTypePlatform for 'Platform' scan type", func() {
			scan.Spec.ScanType = ScanTypePlatform
			scanType, err := scan.GetScanTypeIfValid()
			Expect(err).To(BeNil())
			Expect(scanType).To(Equal(ScanTypePlatform))
		})

		It("returns error for invalid scan type like 'BadScanType'", func() {
			scan.Spec.ScanType = "BadScanType"
			_, err := scan.GetScanTypeIfValid()
			Expect(err).To(Equal(ErrUnkownScanType))
		})

		It("returns error for empty scan type", func() {
			scan.Spec.ScanType = ""
			_, err := scan.GetScanTypeIfValid()
			Expect(err).To(Equal(ErrUnkownScanType))
		})

		It("is case-insensitive for 'node'", func() {
			scan.Spec.ScanType = "node"
			scanType, err := scan.GetScanTypeIfValid()
			Expect(err).To(BeNil())
			Expect(scanType).To(Equal(ScanTypeNode))
		})

		It("is case-insensitive for 'platform'", func() {
			scan.Spec.ScanType = "platform"
			scanType, err := scan.GetScanTypeIfValid()
			Expect(err).To(BeNil())
			Expect(scanType).To(Equal(ScanTypePlatform))
		})
	})

	Context("GetScannerTypeIfValid", func() {
		It("returns ScannerTypeOpenSCAP for 'OpenSCAP'", func() {
			scan.Spec.ScannerType = ScannerTypeOpenSCAP
			scannerType, err := scan.GetScannerTypeIfValid()
			Expect(err).To(BeNil())
			Expect(scannerType).To(Equal(ScannerTypeOpenSCAP))
		})

		It("returns ScannerTypeCEL for 'CEL'", func() {
			scan.Spec.ScannerType = ScannerTypeCEL
			scannerType, err := scan.GetScannerTypeIfValid()
			Expect(err).To(BeNil())
			Expect(scannerType).To(Equal(ScannerTypeCEL))
		})

		It("returns error for invalid scanner type", func() {
			scan.Spec.ScannerType = "BadScanner"
			_, err := scan.GetScannerTypeIfValid()
			Expect(err).To(Equal(ErrUnkownScanerType))
		})
	})

	Context("NeedsRescan", func() {
		It("returns false when annotations are nil", func() {
			scan.Annotations = nil
			Expect(scan.NeedsRescan()).To(BeFalse())
		})

		It("returns false when rescan annotation is absent", func() {
			scan.Annotations = map[string]string{"other": "value"}
			Expect(scan.NeedsRescan()).To(BeFalse())
		})

		It("returns true when rescan annotation is present", func() {
			scan.Annotations = map[string]string{ComplianceScanRescanAnnotation: ""}
			Expect(scan.NeedsRescan()).To(BeTrue())
		})
	})

	Context("IsStrictNodeScan", func() {
		It("defaults to true when StrictNodeScan is nil", func() {
			scan.Spec.StrictNodeScan = nil
			Expect(scan.IsStrictNodeScan()).To(BeTrue())
		})

		It("returns true when StrictNodeScan is explicitly true", func() {
			trueVal := true
			scan.Spec.StrictNodeScan = &trueVal
			Expect(scan.IsStrictNodeScan()).To(BeTrue())
		})

		It("returns false when StrictNodeScan is explicitly false", func() {
			falseVal := false
			scan.Spec.StrictNodeScan = &falseVal
			Expect(scan.IsStrictNodeScan()).To(BeFalse())
		})
	})

	Context("TailoringConfigMap reference", func() {
		It("allows nil TailoringConfigMap", func() {
			scan.Spec.TailoringConfigMap = nil
			Expect(scan.Spec.TailoringConfigMap).To(BeNil())
		})

		It("captures the ConfigMap name when set", func() {
			scan.Spec.TailoringConfigMap = &TailoringConfigMapRef{
				Name: "my-tailoring-cm",
			}
			Expect(scan.Spec.TailoringConfigMap.Name).To(Equal("my-tailoring-cm"))
		})

		It("captures empty ConfigMap name when set to empty string", func() {
			scan.Spec.TailoringConfigMap = &TailoringConfigMapRef{
				Name: "",
			}
			Expect(scan.Spec.TailoringConfigMap).NotTo(BeNil())
			Expect(scan.Spec.TailoringConfigMap.Name).To(BeEmpty())
		})
	})

	Context("Scan result and phase comparisons", func() {
		It("stateCompare returns lower phase", func() {
			Expect(stateCompare(PhasePending, PhaseDone)).To(Equal(PhasePending))
			Expect(stateCompare(PhaseDone, PhasePending)).To(Equal(PhasePending))
			Expect(stateCompare(PhaseRunning, PhaseRunning)).To(Equal(PhaseRunning))
		})

		It("resultCompare returns lower result", func() {
			Expect(resultCompare(ResultCompliant, ResultError)).To(Equal(ResultError))
			Expect(resultCompare(ResultError, ResultCompliant)).To(Equal(ResultError))
			Expect(resultCompare(ResultNotAvailable, ResultCompliant)).To(Equal(ResultNotAvailable))
		})
	})
})
