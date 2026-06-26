package v1alpha1

import (
	"reflect"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
)

var _ = Describe("Testing ComplianceRemediation API", func() {
	When("handling ComplianceRemediationPayload sub-API", func() {
		var payload *ComplianceRemediationPayload

		BeforeEach(func() {
			payload = &ComplianceRemediationPayload{}
		})

		It("handles normalizing payload with no object", func() {
			n := payload.normalized()
			Expect(n).ToNot(BeNil())
			Expect(n.Object).To(BeNil())
		})

		It("normalizes missing annotations", func() {
			cm := &corev1.ConfigMap{
				TypeMeta: metav1.TypeMeta{
					Kind:       "ConfigMap",
					APIVersion: "v1",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "my-cm",
					Namespace: "test-ns",
				},
				Data: map[string]string{
					"key": "val",
				},
			}

			unstructuredCM, err := runtime.DefaultUnstructuredConverter.ToUnstructured(cm)
			Expect(err).ToNot(HaveOccurred())
			payload.Object = &unstructured.Unstructured{
				Object: unstructuredCM,
			}
			Expect(payload.Object.GetAnnotations()).To(BeNil())
			n := payload.normalized()
			Expect(n.Object.GetAnnotations()).ToNot(BeNil())

			// ensure that normalized doesn't change more than it needs to
			normalizedCm := corev1.ConfigMap{}
			err = runtime.DefaultUnstructuredConverter.FromUnstructured(n.Object.Object, &normalizedCm)
			Expect(err).ToNot(HaveOccurred())
			// explicitly not comparing the TypeMeta because 1) if it got modified, FromUnstructured would
			// have failed and 2) this is the only nested struct that gets modified by normalize()
			reflect.DeepEqual(cm.ObjectMeta, &normalizedCm.ObjectMeta)
			reflect.DeepEqual(cm.Data, &normalizedCm.Data)
		})
	})

	var rem *ComplianceRemediation
	When("parsing dependency references", func() {
		BeforeEach(func() {
			rem = &ComplianceRemediation{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{},
				},
			}

		})
		It("parses a cluster-scoped resource correctly", func() {
			rem.Annotations[RemediationObjectDependencyAnnotation] = `[{"apiVersion":"templates.gatekeeper.sh/v1beta1","kind":"ConstraintTemplate","name":"etcdencryptedonly"}]`
			deps, err := rem.ParseRemediationDependencyRefs()
			Expect(err).To(BeNil())
			Expect(deps).To(HaveLen(1))
			Expect(deps[0].APIVersion).To(Equal("templates.gatekeeper.sh/v1beta1"))
			Expect(deps[0].Kind).To(Equal("ConstraintTemplate"))
			Expect(deps[0].Name).To(Equal("etcdencryptedonly"))
		})
		It("parses a namespaced-scoped resource correctly", func() {
			rem.Annotations[RemediationObjectDependencyAnnotation] = `[{"apiVersion":"v1","kind":"Secret","name":"foo","namespace":"bar"}]`
			deps, err := rem.ParseRemediationDependencyRefs()
			Expect(err).To(BeNil())
			Expect(deps).To(HaveLen(1))
			Expect(deps[0].APIVersion).To(Equal("v1"))
			Expect(deps[0].Kind).To(Equal("Secret"))
			Expect(deps[0].Name).To(Equal("foo"))
			Expect(deps[0].Namespace).To(Equal("bar"))
		})
		It("returns an empty list if dependency annotation is empty string", func() {
			rem.Annotations[RemediationObjectDependencyAnnotation] = ""
			deps, err := rem.ParseRemediationDependencyRefs()
			Expect(err).To(BeNil())
			Expect(deps).To(HaveLen(0))
		})
		It("returns an error if json is malformed", func() {
			rem.Annotations[RemediationObjectDependencyAnnotation] = `[{"apiVersion":"v1","kind":"Secret","name":"foo","namespace":"bar"]`
			_, err := rem.ParseRemediationDependencyRefs()
			Expect(err).ToNot(BeNil())
		})
		It("returns an error if no annotation is set", func() {
			_, err := rem.ParseRemediationDependencyRefs()
			Expect(err).ToNot(BeNil())
			Expect(err).To(MatchError(KubeDepsNotFound))
		})
	})

	// Corresponds to e2e TestApplyGenericRemediation (operator annotation check)
	When("managing remediation annotations", func() {
		It("marks an object as created by the operator", func() {
			cm := &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-cm",
					Namespace: "test-ns",
				},
			}
			Expect(RemediationWasCreatedByOperator(cm)).To(BeFalse())

			AddRemediationAnnotation(cm)
			Expect(RemediationWasCreatedByOperator(cm)).To(BeTrue())
		})

		It("returns false when annotations are nil", func() {
			cm := &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name: "no-annotations-cm",
				},
			}
			Expect(RemediationWasCreatedByOperator(cm)).To(BeFalse())
		})

		It("returns false when annotation key is absent", func() {
			cm := &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name: "other-annotations-cm",
					Annotations: map[string]string{
						"some-other-key": "value",
					},
				},
			}
			Expect(RemediationWasCreatedByOperator(cm)).To(BeFalse())
		})
	})

	// Corresponds to e2e TestApplyGenericRemediation / TestPatchGenericRemediation
	When("testing remediation ownership labels", func() {
		It("adds scan and suite labels to target objects", func() {
			rem := &ComplianceRemediation{
				ObjectMeta: metav1.ObjectMeta{
					Name: "rem-with-labels",
					Labels: map[string]string{
						ComplianceScanLabel: "my-scan",
						SuiteLabel:          "my-suite",
					},
				},
			}
			cm := &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name: "target-cm",
				},
			}
			rem.AddOwnershipLabels(cm)
			Expect(cm.Labels[ComplianceScanLabel]).To(Equal("my-scan"))
			Expect(cm.Labels[SuiteLabel]).To(Equal("my-suite"))
		})

		It("does not set empty scan or suite labels", func() {
			rem := &ComplianceRemediation{
				ObjectMeta: metav1.ObjectMeta{
					Name:   "rem-no-labels",
					Labels: map[string]string{},
				},
			}
			cm := &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name: "target-cm",
				},
			}
			rem.AddOwnershipLabels(cm)
			Expect(cm.Labels).ToNot(HaveKey(ComplianceScanLabel))
			Expect(cm.Labels).ToNot(HaveKey(SuiteLabel))
		})
	})

	// Corresponds to e2e TestGenericRemediationFailsWithUnknownType
	When("testing remediation status helpers", func() {
		It("IsApplied returns true when status is Applied", func() {
			rem := &ComplianceRemediation{
				ObjectMeta: metav1.ObjectMeta{Name: "rem-applied"},
				Spec: ComplianceRemediationSpec{
					ComplianceRemediationSpecMeta: ComplianceRemediationSpecMeta{Apply: true},
				},
				Status: ComplianceRemediationStatus{
					ApplicationState: RemediationApplied,
				},
			}
			Expect(rem.IsApplied()).To(BeTrue())
		})

		It("IsApplied returns false when status is Error", func() {
			rem := &ComplianceRemediation{
				ObjectMeta: metav1.ObjectMeta{Name: "rem-error"},
				Spec: ComplianceRemediationSpec{
					ComplianceRemediationSpecMeta: ComplianceRemediationSpecMeta{Apply: true},
				},
				Status: ComplianceRemediationStatus{
					ApplicationState: RemediationError,
				},
			}
			Expect(rem.IsApplied()).To(BeFalse())
		})

		It("IsApplied returns false when status is NotApplied", func() {
			rem := &ComplianceRemediation{
				ObjectMeta: metav1.ObjectMeta{Name: "rem-notapplied"},
				Spec: ComplianceRemediationSpec{
					ComplianceRemediationSpecMeta: ComplianceRemediationSpecMeta{Apply: false},
				},
				Status: ComplianceRemediationStatus{
					ApplicationState: RemediationNotApplied,
				},
			}
			Expect(rem.IsApplied()).To(BeFalse())
		})
	})
})
