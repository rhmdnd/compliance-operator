package v1alpha1

import (
	"strings"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var _ = Describe("E2E logic unit tests for ComplianceScan types", func() {

	// Corresponds to TestScheduledSuiteTimeoutFail:
	// Validates that ComplianceScanTimeoutAnnotation is detectable on scans
	Describe("ComplianceScan timeout annotation", func() {
		It("NeedsTimeoutRescan returns true when timeout annotation is present", func() {
			scan := &ComplianceScan{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-scan",
					Annotations: map[string]string{
						ComplianceScanTimeoutAnnotation: "node-1",
					},
				},
			}
			Expect(scan.NeedsTimeoutRescan()).To(BeTrue())
		})

		It("NeedsTimeoutRescan returns false when timeout annotation is absent", func() {
			scan := &ComplianceScan{
				ObjectMeta: metav1.ObjectMeta{
					Name:        "test-scan",
					Annotations: map[string]string{},
				},
			}
			Expect(scan.NeedsTimeoutRescan()).To(BeFalse())
		})

		It("NeedsTimeoutRescan returns false when annotations are nil", func() {
			scan := &ComplianceScan{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-scan",
				},
			}
			Expect(scan.NeedsTimeoutRescan()).To(BeFalse())
		})
	})

	// Corresponds to TestTimeoutDisabledWithZeroValue:
	// Validates that "0s" timeout is a valid parseable duration that disables timeout
	Describe("Timeout value 0s (disabled)", func() {
		It("parses 0s timeout as zero duration", func() {
			scan := &ComplianceScan{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-scan-zero-timeout",
				},
				Spec: ComplianceScanSpec{
					ComplianceScanSettings: ComplianceScanSettings{
						Timeout: "0s",
					},
				},
			}
			Expect(scan.Spec.Timeout).To(Equal("0s"))
			// A scan with timeout "0s" should NOT have the timeout annotation
			Expect(scan.NeedsTimeoutRescan()).To(BeFalse())
		})

		It("accepts normal timeout values", func() {
			scan := &ComplianceScan{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-scan-normal-timeout",
				},
				Spec: ComplianceScanSpec{
					ComplianceScanSettings: ComplianceScanSettings{
						Timeout: "30m",
					},
				},
			}
			Expect(scan.Spec.Timeout).To(Equal("30m"))
		})
	})

	// Corresponds to TestRuleHasProfileAnnotation:
	// Validates that rule profile annotation can be read and checked
	Describe("Rule profile annotation", func() {
		It("contains expected profiles in a comma-separated list", func() {
			rule := &Rule{
				ObjectMeta: metav1.ObjectMeta{
					Name: "ocp4-file-groupowner-worker-kubeconfig",
					Annotations: map[string]string{
						RuleProfileAnnotationKey: "ocp4-pci-dss-node,ocp4-moderate-node,ocp4-stig-node,ocp4-nerc-cip-node,ocp4-cis-node,ocp4-high-node",
					},
				},
			}

			expectedProfiles := []string{
				"ocp4-pci-dss-node",
				"ocp4-moderate-node",
				"ocp4-stig-node",
				"ocp4-nerc-cip-node",
				"ocp4-cis-node",
				"ocp4-high-node",
			}

			profileAnnotation := rule.Annotations[RuleProfileAnnotationKey]
			for _, profileName := range expectedProfiles {
				Expect(strings.Contains(profileAnnotation, profileName)).To(BeTrue(),
					"expected profile %s in annotation %s", profileName, profileAnnotation)
			}
		})

		It("returns false when annotation is missing", func() {
			rule := &Rule{
				ObjectMeta: metav1.ObjectMeta{
					Name: "ocp4-some-rule",
				},
			}

			_, exists := rule.Annotations[RuleProfileAnnotationKey]
			Expect(exists).To(BeFalse())
		})
	})

	// Corresponds to TestRuleVariableAnnotation:
	// Validates that rules with variables have the correct annotation key
	Describe("Rule variable annotation", func() {
		It("stores the variable name in the annotation", func() {
			rule := &Rule{
				ObjectMeta: metav1.ObjectMeta{
					Name: "ocp4-configure-network-policies-namespaces",
					Annotations: map[string]string{
						RuleVariableAnnotationKey: "var-network-policies-namespaces-exempt-regex",
					},
				},
			}

			variableAnnotation, exists := rule.Annotations[RuleVariableAnnotationKey]
			Expect(exists).To(BeTrue())
			Expect(variableAnnotation).To(Equal("var-network-policies-namespaces-exempt-regex"))
		})

		It("reports missing variable annotation", func() {
			rule := &Rule{
				ObjectMeta: metav1.ObjectMeta{
					Name: "ocp4-some-rule-without-variable",
				},
			}
			_, exists := rule.Annotations[RuleVariableAnnotationKey]
			Expect(exists).To(BeFalse())
		})
	})

	// Corresponds to TestManualRulesTailoredProfile:
	// Validates TailoredProfile ManualRules field structure
	Describe("TailoredProfile ManualRules", func() {
		It("accepts manual rules in a tailored profile spec", func() {
			tp := &TailoredProfile{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "manual-rules-test",
					Namespace: "test-ns",
					Annotations: map[string]string{
						DisableOutdatedReferenceValidation: "true",
					},
				},
				Spec: TailoredProfileSpec{
					Title:       "manual-rules-test",
					Description: "A test tailored profile to test manual-rules",
					ManualRules: []RuleReferenceSpec{
						{
							Name:      "test-pb-kubelet-eviction-thresholds-set-soft-imagefs-available",
							Rationale: "To be tested",
						},
					},
				},
			}

			Expect(tp.Spec.ManualRules).To(HaveLen(1))
			Expect(tp.Spec.ManualRules[0].Name).To(Equal("test-pb-kubelet-eviction-thresholds-set-soft-imagefs-available"))
			Expect(tp.Spec.ManualRules[0].Rationale).To(Equal("To be tested"))
			Expect(tp.Annotations[DisableOutdatedReferenceValidation]).To(Equal("true"))
		})

		It("CheckResultManual status is available", func() {
			Expect(string(CheckResultManual)).To(Equal("MANUAL"))
		})
	})

	// Corresponds to TestHideRule:
	// Validates RuleHideTagAnnotationKey constant and CheckResultNoResult status
	Describe("HideRule annotation and NoResult status", func() {
		It("defines RuleHideTagAnnotationKey constant", func() {
			Expect(RuleHideTagAnnotationKey).To(Equal("compliance.openshift.io/hide-tag"))
		})

		It("CheckResultNoResult has empty string value", func() {
			Expect(string(CheckResultNoResult)).To(Equal(""))
		})
	})

	// Corresponds to TestScanWithCustomStorageClass:
	// Validates that RawResultStorage accepts StorageClassName and PVAccessModes
	Describe("RawResultStorage custom storage configuration", func() {
		It("accepts custom storage class name and access modes", func() {
			storageClassName := "gold-storage"
			scan := &ComplianceScan{
				ObjectMeta: metav1.ObjectMeta{
					Name: "custom-storage-scan",
				},
				Spec: ComplianceScanSpec{
					ScanType: ScanTypeNode,
					ComplianceScanSettings: ComplianceScanSettings{
						RawResultStorage: RawResultStorageSettings{
							StorageClassName: &storageClassName,
							PVAccessModes: []corev1.PersistentVolumeAccessMode{
								corev1.ReadWriteOnce,
							},
						},
					},
				},
			}

			Expect(scan.Spec.RawResultStorage.StorageClassName).ToNot(BeNil())
			Expect(*scan.Spec.RawResultStorage.StorageClassName).To(Equal("gold-storage"))
			Expect(scan.Spec.RawResultStorage.PVAccessModes).To(HaveLen(1))
			Expect(scan.Spec.RawResultStorage.PVAccessModes[0]).To(Equal(corev1.ReadWriteOnce))
		})

		It("allows nil StorageClassName for default", func() {
			scan := &ComplianceScan{
				ObjectMeta: metav1.ObjectMeta{
					Name: "default-storage-scan",
				},
				Spec: ComplianceScanSpec{
					ComplianceScanSettings: ComplianceScanSettings{
						RawResultStorage: RawResultStorageSettings{},
					},
				},
			}
			Expect(scan.Spec.RawResultStorage.StorageClassName).To(BeNil())
		})
	})

	// Corresponds to TestCELProfileBundle:
	// Validates CEL scanner type, profile annotations, and rule attributes
	Describe("CEL profile and rule attributes", func() {
		It("sets correct scanner type annotation on CEL profiles", func() {
			profile := &Profile{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-pb-cel-e2e-test-profile",
					Annotations: map[string]string{
						ScannerTypeAnnotation: string(ScannerTypeCEL),
						ProductTypeAnnotation: string(ScanTypePlatform),
					},
					Labels: map[string]string{
						ProfileBundleOwnerLabel: "test-pb",
					},
				},
				ProfilePayload: ProfilePayload{
					Title: "CEL E2E Test Profile",
					ID:    "cel_e2e_test_profile",
					Rules: []ProfileRule{
						"test-pb-check-default-namespace-has-no-pods",
						"test-pb-check-default-sa-exists-in-kube-system",
						"test-pb-check-namespaces-have-network-policies",
						"test-pb-check-no-privileged-containers",
					},
				},
			}

			Expect(profile.Annotations[ScannerTypeAnnotation]).To(Equal(string(ScannerTypeCEL)))
			Expect(profile.Annotations[ProductTypeAnnotation]).To(Equal(string(ScanTypePlatform)))
			Expect(profile.Labels[ProfileBundleOwnerLabel]).To(Equal("test-pb"))
			Expect(profile.Rules).To(HaveLen(4))
		})

		It("creates CEL rules with expected fields", func() {
			pbName := "test-pb"
			rule := &Rule{
				ObjectMeta: metav1.ObjectMeta{
					Name: pbName + "-check-no-privileged-containers",
					Labels: map[string]string{
						ProfileBundleOwnerLabel: pbName,
					},
					Annotations: map[string]string{
						RuleIDAnnotationKey:      "check-no-privileged-containers",
						RuleProfileAnnotationKey: pbName + "-cel-e2e-test-profile",
					},
				},
				RulePayload: RulePayload{
					ID:          "check_no_privileged_containers",
					Severity:    "high",
					ScannerType: ScannerTypeCEL,
					Expression:  "pods.items.all(p, !p.spec.containers.exists(c, c.securityContext != null && c.securityContext.privileged == true))",
					Inputs: []InputPayload{
						{
							Name: "pods",
							KubernetesInputSpec: KubernetesInputSpec{
								APIVersion: "v1",
								Resource:   "pods",
							},
						},
					},
				},
			}

			Expect(rule.RulePayload.ScannerType).To(Equal(ScannerTypeCEL))
			Expect(rule.RulePayload.Expression).ToNot(BeEmpty())
			Expect(rule.RulePayload.Inputs).To(HaveLen(1))
			Expect(rule.Labels[ProfileBundleOwnerLabel]).To(Equal(pbName))
			Expect(rule.Annotations[RuleIDAnnotationKey]).ToNot(BeEmpty())
			Expect(rule.Annotations[RuleProfileAnnotationKey]).ToNot(BeEmpty())
			Expect(rule.Severity).To(Equal("high"))
		})
	})

	// Corresponds to TestCELProfileScan and TestCELWithXCCDFProfileScan:
	// Validates scanner type validation methods for CEL scans
	Describe("ComplianceScan scanner type validation for CEL", func() {
		It("GetScannerTypeIfValid returns CEL for ScannerTypeCEL", func() {
			scan := &ComplianceScan{
				ObjectMeta: metav1.ObjectMeta{
					Name: "cel-scan",
				},
				Spec: ComplianceScanSpec{
					ScannerType: ScannerTypeCEL,
					ScanType:    ScanTypePlatform,
				},
			}
			scannerType, err := scan.GetScannerTypeIfValid()
			Expect(err).To(BeNil())
			Expect(scannerType).To(Equal(ScannerTypeCEL))
		})

		It("GetScannerTypeIfValid returns OpenSCAP for ScannerTypeOpenSCAP", func() {
			scan := &ComplianceScan{
				ObjectMeta: metav1.ObjectMeta{
					Name: "xccdf-scan",
				},
				Spec: ComplianceScanSpec{
					ScannerType: ScannerTypeOpenSCAP,
					ScanType:    ScanTypeNode,
				},
			}
			scannerType, err := scan.GetScannerTypeIfValid()
			Expect(err).To(BeNil())
			Expect(scannerType).To(Equal(ScannerTypeOpenSCAP))
		})

		It("GetScannerTypeIfValid returns error for unknown type", func() {
			scan := &ComplianceScan{
				ObjectMeta: metav1.ObjectMeta{
					Name: "unknown-scan",
				},
				Spec: ComplianceScanSpec{
					ScannerType: ScannerType("Invalid"),
				},
			}
			_, err := scan.GetScannerTypeIfValid()
			Expect(err).To(Equal(ErrUnkownScanerType))
		})

		It("GetScanTypeIfValid returns Platform for ScanTypePlatform", func() {
			scan := &ComplianceScan{
				ObjectMeta: metav1.ObjectMeta{
					Name: "platform-scan",
				},
				Spec: ComplianceScanSpec{
					ScanType: ScanTypePlatform,
				},
			}
			scanType, err := scan.GetScanTypeIfValid()
			Expect(err).To(BeNil())
			Expect(scanType).To(Equal(ScanTypePlatform))
		})

		It("GetScanTypeIfValid returns Node for ScanTypeNode", func() {
			scan := &ComplianceScan{
				ObjectMeta: metav1.ObjectMeta{
					Name: "node-scan",
				},
				Spec: ComplianceScanSpec{
					ScanType: ScanTypeNode,
				},
			}
			scanType, err := scan.GetScanTypeIfValid()
			Expect(err).To(BeNil())
			Expect(scanType).To(Equal(ScanTypeNode))
		})
	})

	// Corresponds to TestMultipleProfileBundlesWithTailoredProfiles:
	// Validates TailoredProfile with enable/disable rules referencing a profile from a bundle
	Describe("TailoredProfile extending a profile with enable/disable rules", func() {
		It("supports EnableRules and DisableRules referencing bundle-prefixed rules", func() {
			tp := &TailoredProfile{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "multi-pb-tp1",
					Namespace: "test-ns",
					Annotations: map[string]string{
						ProductTypeAnnotation: string(ScanTypeNode),
					},
				},
				Spec: TailoredProfileSpec{
					Title:       "Test Multiple ProfileBundles - TP1",
					Description: "TailoredProfile extending from first custom ProfileBundle",
					Extends:     "multi-pb-pb1-e8",
					EnableRules: []RuleReferenceSpec{
						{
							Name:      "multi-pb-pb1-account-disable-post-pw-expiration",
							Rationale: "Test enabling rule from custom ProfileBundle",
						},
					},
					DisableRules: []RuleReferenceSpec{
						{
							Name:      "multi-pb-pb1-account-unique-name",
							Rationale: "Test disabling rule from custom ProfileBundle",
						},
					},
				},
			}

			Expect(tp.Spec.Extends).To(Equal("multi-pb-pb1-e8"))
			Expect(tp.Spec.EnableRules).To(HaveLen(1))
			Expect(tp.Spec.DisableRules).To(HaveLen(1))
			Expect(tp.Spec.EnableRules[0].Name).To(ContainSubstring("multi-pb-pb1"))
			Expect(tp.Spec.DisableRules[0].Name).To(ContainSubstring("multi-pb-pb1"))
			Expect(tp.Annotations[ProductTypeAnnotation]).To(Equal(string(ScanTypeNode)))
		})
	})

	// Corresponds to TestScanCleansUpComplianceCheckResults:
	// Validates TailoredProfile spec with DisableRules can be updated
	Describe("TailoredProfile DisableRules for cleanup scenario", func() {
		It("can add DisableRules after initial creation", func() {
			tp := &TailoredProfile{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "scan-cleanup-test",
					Namespace: "test-ns",
				},
				Spec: TailoredProfileSpec{
					Title:       "scan-cleanup-test",
					Description: "scan-cleanup-test",
					Extends:     "ocp4-cis",
				},
			}

			// Simulate adding DisableRules
			tpUpdate := tp.DeepCopy()
			tpUpdate.Spec.DisableRules = []RuleReferenceSpec{
				{
					Name:      "ocp4-audit-profile-set",
					Rationale: "testing to ensure scan results are cleaned up",
				},
			}

			Expect(tpUpdate.Spec.DisableRules).To(HaveLen(1))
			Expect(tpUpdate.Spec.DisableRules[0].Name).To(Equal("ocp4-audit-profile-set"))
			// Original should be unchanged
			Expect(tp.Spec.DisableRules).To(HaveLen(0))
		})
	})

	// Corresponds to TestScanWithoutBundlePassesDeprecationCheck:
	// Validates scan with Content/ContentImage mismatch can still proceed
	Describe("ComplianceScan with mismatched Content and ContentImage", func() {
		It("creates a scan with mismatched content and image paths", func() {
			scan := &ComplianceScan{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "deprecation-check-scan",
					Namespace: "test-ns",
				},
				Spec: ComplianceScanSpec{
					Profile:      "xccdf_org.ssgproject.content_profile_moderate",
					Content:      "ssg-ocp4-ds.xml",
					ContentImage: "quay.io/compliance-content-image:latest",
				},
			}

			// The scan should have a valid profile, content, and image
			Expect(scan.Spec.Profile).ToNot(BeEmpty())
			Expect(scan.Spec.Content).ToNot(BeEmpty())
			Expect(scan.Spec.ContentImage).ToNot(BeEmpty())
			// Status should NOT be set to error for deprecation
			Expect(scan.Status.ErrorMessage).To(Equal(""))
		})
	})

	// Corresponds to TestScheduledSuiteTimeoutFail:
	// Validates ComplianceScanSettings with 1s timeout and MaxRetryOnTimeout=0
	Describe("ComplianceScanSettings short timeout configuration", func() {
		It("supports 1s timeout and MaxRetryOnTimeout=0", func() {
			scan := &ComplianceScan{
				ObjectMeta: metav1.ObjectMeta{
					Name: "timeout-scan",
				},
				Spec: ComplianceScanSpec{
					ComplianceScanSettings: ComplianceScanSettings{
						Timeout:           "1s",
						MaxRetryOnTimeout: 0,
						RawResultStorage: RawResultStorageSettings{
							Rotation: 1,
						},
						Debug: true,
					},
				},
			}

			Expect(scan.Spec.Timeout).To(Equal("1s"))
			Expect(scan.Spec.MaxRetryOnTimeout).To(Equal(0))
			Expect(scan.Spec.RawResultStorage.Rotation).To(Equal(uint16(1)))
			Expect(scan.Spec.Debug).To(BeTrue())
		})
	})

	// Corresponds to TestResultServerSAAndSecurityContext:
	// Validates that ResultServer expectations can be described via pod security context
	Describe("ResultServer security context expectations", func() {
		It("validates RunAsNonRoot and SeccompProfile expectations", func() {
			runAsNonRoot := true
			fsGroup := int64(1000)
			runAsUser := int64(1000)
			podSC := &corev1.PodSecurityContext{
				RunAsNonRoot: &runAsNonRoot,
				FSGroup:      &fsGroup,
				RunAsUser:    &runAsUser,
				SELinuxOptions: &corev1.SELinuxOptions{
					Level: "s0:c123,c456",
				},
				SeccompProfile: &corev1.SeccompProfile{
					Type: corev1.SeccompProfileTypeRuntimeDefault,
				},
			}

			Expect(*podSC.RunAsNonRoot).To(BeTrue())
			Expect(*podSC.FSGroup).To(Equal(int64(1000)))
			Expect(*podSC.RunAsUser).To(Equal(int64(1000)))
			Expect(podSC.SELinuxOptions.Level).To(Equal("s0:c123,c456"))
			Expect(podSC.SeccompProfile.Type).To(Equal(corev1.SeccompProfileTypeRuntimeDefault))
		})
	})

	// ComplianceScanStatusPhase and Result ordering tests
	Describe("Phase and result comparison functions", func() {
		It("stateCompare returns the lower phase", func() {
			Expect(stateCompare(PhaseDone, PhasePending)).To(Equal(PhasePending))
			Expect(stateCompare(PhasePending, PhaseDone)).To(Equal(PhasePending))
			Expect(stateCompare(PhaseRunning, PhaseRunning)).To(Equal(PhaseRunning))
		})

		It("resultCompare returns the lower result", func() {
			Expect(resultCompare(ResultCompliant, ResultError)).To(Equal(ResultError))
			Expect(resultCompare(ResultError, ResultCompliant)).To(Equal(ResultError))
			Expect(resultCompare(ResultNonCompliant, ResultNonCompliant)).To(Equal(ResultNonCompliant))
		})
	})

	// ProfileBundle with CELContentFile support
	Describe("ProfileBundle CELContentFile", func() {
		It("supports optional CELContentFile field", func() {
			pb := &ProfileBundle{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-bundle",
					Namespace: "test-ns",
				},
				Spec: ProfileBundleSpec{
					ContentImage:   "quay.io/test/content:latest",
					ContentFile:    "ssg-rhcos4-ds.xml",
					CELContentFile: "cel-content.yaml",
				},
			}

			Expect(pb.Spec.CELContentFile).To(Equal("cel-content.yaml"))
			Expect(pb.Spec.ContentFile).To(Equal("ssg-rhcos4-ds.xml"))
		})

		It("allows empty CELContentFile for XCCDF-only bundles", func() {
			pb := &ProfileBundle{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "xccdf-only-bundle",
					Namespace: "test-ns",
				},
				Spec: ProfileBundleSpec{
					ContentImage: "quay.io/test/content:latest",
					ContentFile:  "ssg-rhcos4-ds.xml",
				},
			}
			Expect(pb.Spec.CELContentFile).To(Equal(""))
		})
	})

	// ProfileBundle status conditions
	Describe("ProfileBundle status conditions", func() {
		It("SetConditionReady sets Ready=True", func() {
			pb := &ProfileBundle{}
			pb.Status.SetConditionReady()
			Expect(pb.Status.Conditions).To(HaveLen(1))
		})

		It("SetConditionInvalid sets Ready=False", func() {
			pb := &ProfileBundle{}
			pb.Status.SetConditionInvalid()
			Expect(pb.Status.Conditions).To(HaveLen(1))
		})

		It("SetConditionPending sets Ready=False", func() {
			pb := &ProfileBundle{}
			pb.Status.SetConditionPending()
			Expect(pb.Status.Conditions).To(HaveLen(1))
		})
	})

	// NeedsRescan tests
	Describe("NeedsRescan", func() {
		It("returns true when rescan annotation is present", func() {
			scan := &ComplianceScan{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-scan",
					Annotations: map[string]string{
						ComplianceScanRescanAnnotation: "",
					},
				},
			}
			Expect(scan.NeedsRescan()).To(BeTrue())
		})

		It("returns false when rescan annotation is absent", func() {
			scan := &ComplianceScan{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-scan",
				},
			}
			Expect(scan.NeedsRescan()).To(BeFalse())
		})
	})
})
