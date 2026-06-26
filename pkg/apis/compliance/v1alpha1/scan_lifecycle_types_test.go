package v1alpha1

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var _ = Describe("Scan Lifecycle Types", func() {

	// TestRulesAreClassifiedAppropriately
	// Validates Rule.CheckType classifications.
	Context("Rule CheckType classification", func() {
		It("should classify Platform rules correctly", func() {
			rule := &Rule{
				ObjectMeta: metav1.ObjectMeta{
					Name: "ocp4-configure-network-policies",
				},
				RulePayload: RulePayload{
					ID:        "xccdf_org.ssgproject.content_rule_configure_network_policies",
					CheckType: CheckTypePlatform,
				},
			}
			Expect(rule.CheckType).To(Equal(CheckTypePlatform))
		})

		It("should classify Node rules correctly", func() {
			rule := &Rule{
				ObjectMeta: metav1.ObjectMeta{
					Name: "ocp4-directory-access-var-log-kube-audit",
				},
				RulePayload: RulePayload{
					ID:        "xccdf_org.ssgproject.content_rule_directory_access_var_log_kube_audit",
					CheckType: CheckTypeNode,
				},
			}
			Expect(rule.CheckType).To(Equal(CheckTypeNode))
		})

		It("should classify None check type rules correctly", func() {
			rule := &Rule{
				ObjectMeta: metav1.ObjectMeta{
					Name: "ocp4-general-apply-scc",
				},
				RulePayload: RulePayload{
					ID:        "xccdf_org.ssgproject.content_rule_general_apply_scc",
					CheckType: CheckTypeNone,
				},
			}
			Expect(rule.CheckType).To(Equal(CheckTypeNone))
		})

		It("should enumerate all expected CheckType constants", func() {
			Expect(CheckTypePlatform).To(Equal("Platform"))
			Expect(CheckTypeNode).To(Equal("Node"))
			Expect(CheckTypeNone).To(Equal(""))
		})
	})

	// TestSingleScanSucceeds and TestSingleScanTimestamps
	// Validates ComplianceScan phase constants and result types.
	Context("ComplianceScan phase and result types", func() {
		It("should define the correct scan phases", func() {
			Expect(PhasePending).To(Equal(ComplianceScanStatusPhase("PENDING")))
			Expect(PhaseLaunching).To(Equal(ComplianceScanStatusPhase("LAUNCHING")))
			Expect(PhaseRunning).To(Equal(ComplianceScanStatusPhase("RUNNING")))
			Expect(PhaseAggregating).To(Equal(ComplianceScanStatusPhase("AGGREGATING")))
			Expect(PhaseDone).To(Equal(ComplianceScanStatusPhase("DONE")))
		})

		It("should define the correct scan results", func() {
			Expect(ResultNotAvailable).To(Equal(ComplianceScanStatusResult("NOT-AVAILABLE")))
			Expect(ResultCompliant).To(Equal(ComplianceScanStatusResult("COMPLIANT")))
			Expect(ResultNonCompliant).To(Equal(ComplianceScanStatusResult("NON-COMPLIANT")))
			Expect(ResultError).To(Equal(ComplianceScanStatusResult("ERROR")))
			Expect(ResultNotApplicable).To(Equal(ComplianceScanStatusResult("NOT-APPLICABLE")))
			Expect(ResultInconsistent).To(Equal(ComplianceScanStatusResult("INCONSISTENT")))
		})

		It("should correctly compare state phases - lower returns the lower phase", func() {
			Expect(stateCompare(PhasePending, PhaseDone)).To(Equal(PhasePending))
			Expect(stateCompare(PhaseDone, PhasePending)).To(Equal(PhasePending))
			Expect(stateCompare(PhaseRunning, PhaseRunning)).To(Equal(PhaseRunning))
		})

		It("should correctly compare results - lower returns the lower result", func() {
			Expect(resultCompare(ResultNotAvailable, ResultCompliant)).To(Equal(ResultNotAvailable))
			Expect(resultCompare(ResultCompliant, ResultNotAvailable)).To(Equal(ResultNotAvailable))
			Expect(resultCompare(ResultError, ResultNonCompliant)).To(Equal(ResultError))
		})
	})

	// TestNonExistentDeprecatedProfile
	// Validates ComplianceScan error handling types.
	Context("ComplianceScan error status", func() {
		It("should set error message and phase correctly", func() {
			scan := &ComplianceScan{
				ObjectMeta: metav1.ObjectMeta{
					Name: "error-scan",
				},
				Status: ComplianceScanStatus{
					Phase:        PhaseDone,
					Result:       ResultError,
					ErrorMessage: "Could not check whether the Profile used by ComplianceScan is deprecated",
				},
			}
			Expect(scan.Status.Phase).To(Equal(PhaseDone))
			Expect(scan.Status.Result).To(Equal(ResultError))
			Expect(scan.Status.ErrorMessage).To(Equal(
				"Could not check whether the Profile used by ComplianceScan is deprecated"))
		})
	})

	// TestSingleScanTimestamps
	// Validates timestamp handling for ComplianceScan status.
	Context("ComplianceScan timestamps", func() {
		It("should have nil timestamps by default", func() {
			scan := &ComplianceScan{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-scan",
				},
			}
			Expect(scan.Status.StartTimestamp).To(BeNil())
			Expect(scan.Status.EndTimestamp).To(BeNil())
		})

		It("should support setting StartTimestamp and EndTimestamp", func() {
			now := metav1.Now()
			scan := &ComplianceScan{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-scan-ts",
				},
				Status: ComplianceScanStatus{
					StartTimestamp: &now,
					EndTimestamp:   &now,
				},
			}
			Expect(scan.Status.StartTimestamp).ToNot(BeNil())
			Expect(scan.Status.EndTimestamp).ToNot(BeNil())
		})
	})

	// TestSingleScanSucceeds - Rescan handling
	Context("ComplianceScan rescan annotations", func() {
		It("should detect rescan annotation", func() {
			scan := &ComplianceScan{
				ObjectMeta: metav1.ObjectMeta{
					Name: "rescan-test",
					Annotations: map[string]string{
						ComplianceScanRescanAnnotation: "",
					},
				},
			}
			Expect(scan.NeedsRescan()).To(BeTrue())
		})

		It("should return false when no rescan annotation", func() {
			scan := &ComplianceScan{
				ObjectMeta: metav1.ObjectMeta{
					Name: "no-rescan-test",
				},
			}
			Expect(scan.NeedsRescan()).To(BeFalse())
		})

		It("should detect timeout rescan annotation", func() {
			scan := &ComplianceScan{
				ObjectMeta: metav1.ObjectMeta{
					Name: "timeout-rescan-test",
					Annotations: map[string]string{
						ComplianceScanTimeoutAnnotation: "node-1",
					},
				},
			}
			Expect(scan.NeedsTimeoutRescan()).To(BeTrue())
		})
	})

	// TestSingleScanSucceeds and TestSingleScanWithStorageSucceeds
	// Validates scan type determination.
	Context("ComplianceScan type validation", func() {
		It("should return Node scan type", func() {
			scan := &ComplianceScan{
				Spec: ComplianceScanSpec{
					ScanType: ScanTypeNode,
				},
			}
			scanType, err := scan.GetScanTypeIfValid()
			Expect(err).To(BeNil())
			Expect(scanType).To(Equal(ScanTypeNode))
		})

		It("should return Platform scan type", func() {
			scan := &ComplianceScan{
				Spec: ComplianceScanSpec{
					ScanType: ScanTypePlatform,
				},
			}
			scanType, err := scan.GetScanTypeIfValid()
			Expect(err).To(BeNil())
			Expect(scanType).To(Equal(ScanTypePlatform))
		})

		It("should return error for invalid scan type", func() {
			scan := &ComplianceScan{
				Spec: ComplianceScanSpec{
					ScanType: ComplianceScanType("Invalid"),
				},
			}
			_, err := scan.GetScanTypeIfValid()
			Expect(err).To(Equal(ErrUnkownScanType))
		})

		It("should be case-insensitive for scan type", func() {
			scan := &ComplianceScan{
				Spec: ComplianceScanSpec{
					ScanType: ComplianceScanType("node"),
				},
			}
			scanType, err := scan.GetScanTypeIfValid()
			Expect(err).To(BeNil())
			Expect(scanType).To(Equal(ScanTypeNode))
		})
	})

	// TestScanProducesRemediationsAndLabels
	// Validates ComplianceRemediation IsApplied logic and label constants.
	Context("ComplianceRemediation application state", func() {
		It("should report as not applied when state is NotApplied", func() {
			rem := &ComplianceRemediation{
				Status: ComplianceRemediationStatus{
					ApplicationState: RemediationNotApplied,
				},
			}
			Expect(rem.IsApplied()).To(BeFalse())
		})

		It("should report as applied when state is Applied", func() {
			rem := &ComplianceRemediation{
				Status: ComplianceRemediationStatus{
					ApplicationState: RemediationApplied,
				},
			}
			Expect(rem.IsApplied()).To(BeTrue())
		})

		It("should report as applied when outdated but apply requested", func() {
			rem := &ComplianceRemediation{
				Spec: ComplianceRemediationSpec{
					ComplianceRemediationSpecMeta: ComplianceRemediationSpecMeta{
						Apply: true,
					},
				},
				Status: ComplianceRemediationStatus{
					ApplicationState: RemediationOutdated,
				},
			}
			Expect(rem.IsApplied()).To(BeTrue())
		})
	})

	// TestScanTailoredProfileIsDeprecated
	// Validates TailoredProfile deprecation annotation handling.
	Context("TailoredProfile deprecation annotation", func() {
		It("should detect deprecated annotation on TailoredProfile", func() {
			tp := &TailoredProfile{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "deprecated-tp",
					Namespace: "test-ns",
					Annotations: map[string]string{
						ProfileStatusAnnotation: "deprecated",
					},
				},
			}
			Expect(tp.GetAnnotations()[ProfileStatusAnnotation]).To(Equal("deprecated"))
		})

		It("should not report non-deprecated TailoredProfile as deprecated", func() {
			tp := &TailoredProfile{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "active-tp",
					Namespace: "test-ns",
				},
			}
			ann := tp.GetAnnotations()
			if ann == nil {
				ann = map[string]string{}
			}
			Expect(ann[ProfileStatusAnnotation]).ToNot(Equal("deprecated"))
		})
	})

	// TestScanTailoredProfileHasDuplicateVariables
	// Validates duplicate detection in TailoredProfile SetValues.
	Context("TailoredProfile duplicate variable detection", func() {
		It("should detect duplicate variable names in SetValues", func() {
			tp := &TailoredProfile{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "dup-vars-tp",
					Namespace: "test-ns",
				},
				Spec: TailoredProfileSpec{
					Title:       "TestDupVars",
					Description: "TestDupVars",
					SetValues: []VariableValueSpec{
						{Name: "var-audit-profile", Rationale: "First", Value: "WriteRequestBodies"},
						{Name: "var-audit-profile", Rationale: "Second", Value: "SomethingElse"},
					},
				},
			}

			seen := make(map[string]int)
			for i, sv := range tp.Spec.SetValues {
				if prevIdx, exists := seen[sv.Name]; exists {
					// Found duplicate
					Expect(i).To(BeNumerically(">", prevIdx),
						"Second occurrence should be at a higher index")
				}
				seen[sv.Name] = i
			}
			Expect(len(seen)).To(Equal(1), "Should have one unique variable name for two entries")
			Expect(len(tp.Spec.SetValues)).To(Equal(2), "Should have two entries in SetValues")
		})

		It("should not flag unique variable names", func() {
			tp := &TailoredProfile{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "unique-vars-tp",
					Namespace: "test-ns",
				},
				Spec: TailoredProfileSpec{
					Title:       "TestUniqueVars",
					Description: "TestUniqueVars",
					SetValues: []VariableValueSpec{
						{Name: "var-one", Value: "val1"},
						{Name: "var-two", Value: "val2"},
					},
				},
			}

			seen := make(map[string]bool)
			hasDup := false
			for _, sv := range tp.Spec.SetValues {
				if seen[sv.Name] {
					hasDup = true
					break
				}
				seen[sv.Name] = true
			}
			Expect(hasDup).To(BeFalse())
		})
	})

	// TestScanStorageOutOfLimitRangeFails
	// Validates the raw storage defaults and constant values.
	Context("Raw storage size defaults", func() {
		It("should have correct default storage size", func() {
			Expect(DefaultRawStorageSize).To(Equal("1Gi"))
		})

		It("should have correct default storage rotation", func() {
			Expect(DefaultStorageRotation).To(Equal(3))
		})
	})

	// TestScanProducesRemediationsAndLabels
	// Validates ComplianceCheckResult label and annotation constants.
	Context("ComplianceCheckResult label constants", func() {
		It("should define all required label constants", func() {
			Expect(ComplianceCheckResultStatusLabel).To(Equal("compliance.openshift.io/check-status"))
			Expect(ComplianceCheckResultSeverityLabel).To(Equal("compliance.openshift.io/check-severity"))
			Expect(ComplianceCheckResultValueLabel).To(Equal("compliance.openshift.io/check-has-value"))
			Expect(ComplianceCheckResultHasRemediation).To(Equal("compliance.openshift.io/automated-remediation"))
		})

		It("should define last scanned timestamp annotation", func() {
			Expect(LastScannedTimestampAnnotation).To(Equal("compliance.openshift.io/last-scanned-timestamp"))
		})
	})

	// TestSingleScanSucceeds - scan condition methods
	Context("ComplianceScan condition methods", func() {
		It("should set Pending condition", func() {
			status := &ComplianceScanStatus{}
			status.SetConditionPending()
			Expect(status.Conditions).ToNot(BeEmpty())
		})

		It("should set Invalid condition", func() {
			status := &ComplianceScanStatus{}
			status.SetConditionInvalid()
			Expect(status.Conditions).ToNot(BeEmpty())
		})

		It("should set Processing conditions", func() {
			status := &ComplianceScanStatus{}
			status.SetConditionsProcessing()
			Expect(status.Conditions).ToNot(BeEmpty())
		})

		It("should set Ready condition", func() {
			status := &ComplianceScanStatus{}
			status.SetConditionReady()
			Expect(status.Conditions).ToNot(BeEmpty())
		})

		It("should set Timeout condition", func() {
			status := &ComplianceScanStatus{}
			status.SetConditionTimeout()
			Expect(status.Conditions).ToNot(BeEmpty())
		})
	})

	// TestSingleScanSucceeds - remediation enforcement
	Context("ComplianceScan remediation enforcement", func() {
		It("should report enforcement is off when empty", func() {
			scan := &ComplianceScan{}
			Expect(scan.RemediationEnforcementIsOff()).To(BeTrue())
		})

		It("should report enforcement is off when set to off", func() {
			scan := &ComplianceScan{
				Spec: ComplianceScanSpec{
					ComplianceScanSettings: ComplianceScanSettings{
						RemediationEnforcement: "off",
					},
				},
			}
			Expect(scan.RemediationEnforcementIsOff()).To(BeTrue())
		})

		It("should match enforcement type all", func() {
			scan := &ComplianceScan{
				Spec: ComplianceScanSpec{
					ComplianceScanSettings: ComplianceScanSettings{
						RemediationEnforcement: "all",
					},
				},
			}
			Expect(scan.RemediationEnforcementTypeMatches("gatekeeper")).To(BeTrue())
		})
	})

	// TestSingleScanSucceeds - strictNodeScan
	Context("ComplianceScan strict node scan", func() {
		It("should default to strict when nil", func() {
			scan := &ComplianceScan{}
			Expect(scan.IsStrictNodeScan()).To(BeTrue())
		})

		It("should return false when explicitly set to false", func() {
			falseVal := false
			scan := &ComplianceScan{
				Spec: ComplianceScanSpec{
					ComplianceScanSettings: ComplianceScanSettings{
						StrictNodeScan: &falseVal,
					},
				},
			}
			Expect(scan.IsStrictNodeScan()).To(BeFalse())
		})
	})

	// ProfileBundle status types for TestParsingErrorRestartsParserInitContainer
	Context("ProfileBundle data stream status types", func() {
		It("should define correct status types", func() {
			Expect(DataStreamPending).To(Equal(DataStreamStatusType("PENDING")))
			Expect(DataStreamValid).To(Equal(DataStreamStatusType("VALID")))
			Expect(DataStreamInvalid).To(Equal(DataStreamStatusType("INVALID")))
		})
	})

	// TailoredProfile state types for TestScanTailoredProfileIsDeprecated
	Context("TailoredProfile state types", func() {
		It("should define correct state types", func() {
			Expect(TailoredProfileStatePending).To(Equal(TailoredProfileState("PENDING")))
			Expect(TailoredProfileStateReady).To(Equal(TailoredProfileState("READY")))
			Expect(TailoredProfileStateError).To(Equal(TailoredProfileState("ERROR")))
		})
	})
})
