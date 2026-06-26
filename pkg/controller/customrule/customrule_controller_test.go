package customrule

import (
	"context"
	"testing"

	"github.com/ComplianceAsCode/compliance-operator/pkg/apis"
	"github.com/ComplianceAsCode/compliance-operator/pkg/apis/compliance/v1alpha1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

func TestCustomRuleReconciler_Reconcile(t *testing.T) {
	// Register types with the scheme
	s := scheme.Scheme
	apis.AddToScheme(s)

	tests := []struct {
		name           string
		rule           *v1alpha1.CustomRule
		expectedPhase  string
		expectError    bool
		expectedErrMsg string
	}{
		{
			name: "Valid CustomRule with simple CEL expression",
			rule: &v1alpha1.CustomRule{
				ObjectMeta: metav1.ObjectMeta{
					Name:       "valid-rule",
					Namespace:  "test",
					Generation: 1,
				},
				Spec: v1alpha1.CustomRuleSpec{
					RulePayload: v1alpha1.RulePayload{
						ID:          "test-rule-1",
						Title:       "Test Rule",
						Description: "A test rule for validation",
						Severity:    "medium",
						ScannerType: v1alpha1.ScannerTypeCEL,
						Expression:  "pods.items.all(pod, pod.spec.containers.all(container, container.securityContext.runAsNonRoot == true))",
						Inputs: []v1alpha1.InputPayload{
							{
								Name: "pods",
								KubernetesInputSpec: v1alpha1.KubernetesInputSpec{
									Group:      "",
									APIVersion: "v1",
									Resource:   "pods",
								},
							},
						},
						FailureReason: "All containers must run as non-root",
					},
				},
			},
			expectedPhase: v1alpha1.CustomRulePhaseReady,
			expectError:   false,
		},
		{
			name: "Invalid CustomRule with invalid CEL syntax",
			rule: &v1alpha1.CustomRule{
				ObjectMeta: metav1.ObjectMeta{
					Name:       "invalid-cel-syntax",
					Namespace:  "test",
					Generation: 1,
				},
				Spec: v1alpha1.CustomRuleSpec{
					RulePayload: v1alpha1.RulePayload{
						ID:          "test-rule-2",
						Title:       "Invalid Rule",
						Description: "A rule with invalid CEL syntax",
						Severity:    "high",
						ScannerType: v1alpha1.ScannerTypeCEL,
						Expression:  "this is not &&& valid CEL syntax", // Invalid CEL syntax
						Inputs: []v1alpha1.InputPayload{
							{
								Name: "test",
								KubernetesInputSpec: v1alpha1.KubernetesInputSpec{
									APIVersion: "v1",
									Resource:   "pods",
								},
							},
						},
						FailureReason: "This should fail",
					},
				},
			},
			expectedPhase:  v1alpha1.CustomRulePhaseError,
			expectError:    false,
			expectedErrMsg: "CEL expression compilation failed",
		},
		{
			name: "Valid CustomRule with multiple inputs",
			rule: &v1alpha1.CustomRule{
				ObjectMeta: metav1.ObjectMeta{
					Name:       "valid-multi-input",
					Namespace:  "test",
					Generation: 1,
				},
				Spec: v1alpha1.CustomRuleSpec{
					RulePayload: v1alpha1.RulePayload{
						ID:          "test-rule-5",
						Title:       "Multi-input Rule",
						Description: "A rule with multiple inputs",
						Severity:    "medium",
						ScannerType: v1alpha1.ScannerTypeCEL,
						Expression:  "namespaces.items.all(ns, networkpolicies.items.exists(np, np.metadata.namespace == ns.metadata.name))",
						Inputs: []v1alpha1.InputPayload{
							{
								Name: "namespaces",
								KubernetesInputSpec: v1alpha1.KubernetesInputSpec{
									Group:      "",
									APIVersion: "v1",
									Resource:   "namespaces",
								},
							},
							{
								Name: "networkpolicies",
								KubernetesInputSpec: v1alpha1.KubernetesInputSpec{
									Group:      "networking.k8s.io",
									APIVersion: "v1",
									Resource:   "networkpolicies",
								},
							},
						},
						FailureReason: "All namespaces must have network policies",
					},
				},
			},
			expectedPhase: v1alpha1.CustomRulePhaseReady,
			expectError:   false,
		},
		{
			name: "Valid CustomRule with multiple inputs and missing one input",
			rule: &v1alpha1.CustomRule{
				ObjectMeta: metav1.ObjectMeta{
					Name:       "valid-multi-input-missing-one-input",
					Namespace:  "test",
					Generation: 1,
				},
				Spec: v1alpha1.CustomRuleSpec{
					RulePayload: v1alpha1.RulePayload{
						ID:          "test-rule-5",
						Title:       "Multi-input Rule",
						Description: "A rule with multiple inputs",
						Severity:    "medium",
						ScannerType: v1alpha1.ScannerTypeCEL,
						Expression:  "namespaces.items.all(ns, networkpolicies-non-existent.items.exists(np, np.metadata.namespace == ns.metadata.name))",
						Inputs: []v1alpha1.InputPayload{
							{
								Name: "namespaces",
								KubernetesInputSpec: v1alpha1.KubernetesInputSpec{
									Group:      "",
									APIVersion: "v1",
									Resource:   "namespaces",
								},
							},
							{
								Name: "networkpolicies",
								KubernetesInputSpec: v1alpha1.KubernetesInputSpec{
									Group:      "networking.k8s.io",
									APIVersion: "v1",
									Resource:   "networkpolicies",
								},
							},
						},
						FailureReason: "All namespaces must have network policies",
					},
				},
			},
			expectedPhase: v1alpha1.CustomRulePhaseError,
			expectError:   false,
		},
		{
			name: "Invalid CustomRule with undefined input reference in expression",
			rule: &v1alpha1.CustomRule{
				ObjectMeta: metav1.ObjectMeta{
					Name:       "invalid-undefined-reference",
					Namespace:  "test",
					Generation: 1,
				},
				Spec: v1alpha1.CustomRuleSpec{
					RulePayload: v1alpha1.RulePayload{
						ID:          "test-rule-6",
						Title:       "Undefined Reference Rule",
						Description: "A rule referencing undefined inputs",
						Severity:    "medium",
						ScannerType: v1alpha1.ScannerTypeCEL,
						Expression:  "undefinedInput.items.size() > 0", // References 'undefinedInput' not in inputs
						Inputs: []v1alpha1.InputPayload{
							{
								Name: "test",
								KubernetesInputSpec: v1alpha1.KubernetesInputSpec{
									APIVersion: "v1",
									Resource:   "pods",
								},
							},
						},
						FailureReason: "This should fail validation",
					},
				},
			},
			expectedPhase:  v1alpha1.CustomRulePhaseError,
			expectError:    false,
			expectedErrMsg: "CEL expression compilation failed",
		},
		// --- Tests corresponding to e2e TestCustomRuleCheckTypeAndScannerTypeValidation ---
		{
			name: "Invalid CustomRule with Node checkType rejected",
			rule: &v1alpha1.CustomRule{
				ObjectMeta: metav1.ObjectMeta{
					Name:       "invalid-checktype-node",
					Namespace:  "test",
					Generation: 1,
				},
				Spec: v1alpha1.CustomRuleSpec{
					RulePayload: v1alpha1.RulePayload{
						ID:          "invalid-checktype-node",
						Title:       "Invalid CheckType Rule",
						Description: "This rule has invalid checkType",
						Severity:    "low",
						CheckType:   "Node",
						ScannerType: v1alpha1.ScannerTypeCEL,
						Expression:  "pods.items.size() >= 0",
						Inputs: []v1alpha1.InputPayload{
							{
								Name: "pods",
								KubernetesInputSpec: v1alpha1.KubernetesInputSpec{
									APIVersion: "v1",
									Resource:   "pods",
								},
							},
						},
						FailureReason: "This should fail validation due to invalid checkType",
					},
				},
			},
			expectedPhase:  v1alpha1.CustomRulePhaseError,
			expectError:    false,
			expectedErrMsg: "checkType must be 'Platform'",
		},
		{
			name: "Invalid CustomRule with OpenSCAP scannerType rejected",
			rule: &v1alpha1.CustomRule{
				ObjectMeta: metav1.ObjectMeta{
					Name:       "invalid-scannertype-openscap",
					Namespace:  "test",
					Generation: 1,
				},
				Spec: v1alpha1.CustomRuleSpec{
					RulePayload: v1alpha1.RulePayload{
						ID:          "invalid-scannertype-openscap",
						Title:       "Invalid ScannerType Rule",
						Description: "This rule has invalid scannerType",
						Severity:    "low",
						CheckType:   "Platform",
						ScannerType: v1alpha1.ScannerTypeOpenSCAP,
						Expression:  "pods.items.size() >= 0",
						Inputs: []v1alpha1.InputPayload{
							{
								Name: "pods",
								KubernetesInputSpec: v1alpha1.KubernetesInputSpec{
									APIVersion: "v1",
									Resource:   "pods",
								},
							},
						},
						FailureReason: "This should fail validation due to invalid scannerType",
					},
				},
			},
			expectedPhase:  v1alpha1.CustomRulePhaseError,
			expectError:    false,
			expectedErrMsg: "scannerType must be 'CEL'",
		},
		{
			name: "Valid CustomRule with Platform checkType and CEL scannerType accepted",
			rule: &v1alpha1.CustomRule{
				ObjectMeta: metav1.ObjectMeta{
					Name:       "valid-platform-cel",
					Namespace:  "test",
					Generation: 1,
				},
				Spec: v1alpha1.CustomRuleSpec{
					RulePayload: v1alpha1.RulePayload{
						ID:          "valid-platform-cel",
						Title:       "Valid Rule",
						Description: "This rule has valid checkType and scannerType",
						Severity:    "low",
						CheckType:   "Platform",
						ScannerType: v1alpha1.ScannerTypeCEL,
						Expression:  "pods.items.size() >= 0",
						Inputs: []v1alpha1.InputPayload{
							{
								Name: "pods",
								KubernetesInputSpec: v1alpha1.KubernetesInputSpec{
									APIVersion: "v1",
									Resource:   "pods",
								},
							},
						},
						FailureReason: "This should pass validation",
					},
				},
			},
			expectedPhase: v1alpha1.CustomRulePhaseReady,
			expectError:   false,
		},
		{
			name: "Valid CustomRule with empty checkType defaults to Platform",
			rule: &v1alpha1.CustomRule{
				ObjectMeta: metav1.ObjectMeta{
					Name:       "valid-empty-checktype",
					Namespace:  "test",
					Generation: 1,
				},
				Spec: v1alpha1.CustomRuleSpec{
					RulePayload: v1alpha1.RulePayload{
						ID:          "valid-empty-checktype",
						Title:       "Valid Empty CheckType Rule",
						Description: "This rule has empty checkType which should be valid",
						Severity:    "low",
						ScannerType: v1alpha1.ScannerTypeCEL,
						Expression:  "pods.items.size() >= 0",
						Inputs: []v1alpha1.InputPayload{
							{
								Name: "pods",
								KubernetesInputSpec: v1alpha1.KubernetesInputSpec{
									APIVersion: "v1",
									Resource:   "pods",
								},
							},
						},
						FailureReason: "This should pass validation with empty checkType",
					},
				},
			},
			expectedPhase: v1alpha1.CustomRulePhaseReady,
			expectError:   false,
		},
		// --- Tests corresponding to e2e TestCustomRuleValidation (invalid CEL expression) ---
		{
			name: "Invalid CEL expression with non-existent function rejected",
			rule: &v1alpha1.CustomRule{
				ObjectMeta: metav1.ObjectMeta{
					Name:       "invalid-function",
					Namespace:  "test",
					Generation: 1,
				},
				Spec: v1alpha1.CustomRuleSpec{
					RulePayload: v1alpha1.RulePayload{
						ID:          "invalid-function",
						Title:       "Invalid Rule",
						Description: "This rule has invalid CEL expression with non-existent function",
						Severity:    "low",
						ScannerType: v1alpha1.ScannerTypeCEL,
						Expression:  "pods.items.all(pod, invalid_function_that_doesnt_exist(pod))",
						Inputs: []v1alpha1.InputPayload{
							{
								Name: "pods",
								KubernetesInputSpec: v1alpha1.KubernetesInputSpec{
									APIVersion: "v1",
									Resource:   "pods",
								},
							},
						},
						FailureReason: "This should fail validation",
					},
				},
			},
			expectedPhase:  v1alpha1.CustomRulePhaseError,
			expectError:    false,
			expectedErrMsg: "CEL expression compilation failed",
		},
		// --- Tests corresponding to e2e TestCustomRuleValidation (undeclared variable) ---
		{
			name: "Undeclared variable in expression rejected",
			rule: &v1alpha1.CustomRule{
				ObjectMeta: metav1.ObjectMeta{
					Name:       "undeclared-variable",
					Namespace:  "test",
					Generation: 1,
				},
				Spec: v1alpha1.CustomRuleSpec{
					RulePayload: v1alpha1.RulePayload{
						ID:          "undeclared-variable",
						Title:       "Undeclared Variable Rule",
						Description: "This rule uses undeclared variables",
						Severity:    "low",
						ScannerType: v1alpha1.ScannerTypeCEL,
						Expression:  "pods.items.all(pod, deployments.items.exists(d, d.metadata.name == pod.metadata.name))",
						Inputs: []v1alpha1.InputPayload{
							{
								Name: "pods",
								KubernetesInputSpec: v1alpha1.KubernetesInputSpec{
									APIVersion: "v1",
									Resource:   "pods",
								},
							},
							// 'deployments' is used in the expression but not declared as input
						},
						FailureReason: "This should fail validation due to undeclared variable",
					},
				},
			},
			expectedPhase:  v1alpha1.CustomRulePhaseError,
			expectError:    false,
			expectedErrMsg: "CEL expression compilation failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create fake client with the rule
			fakeClient := fake.NewClientBuilder().
				WithScheme(s).
				WithRuntimeObjects(tt.rule).
				WithStatusSubresource(tt.rule).
				Build()

			// Create reconciler
			r := &CustomRuleReconciler{
				Client: fakeClient,
				Scheme: s,
			}

			// Create reconcile request
			req := reconcile.Request{
				NamespacedName: types.NamespacedName{
					Name:      tt.rule.Name,
					Namespace: tt.rule.Namespace,
				},
			}

			// Perform reconciliation
			ctx := context.Background()
			result, err := r.Reconcile(ctx, req)

			// Check error expectation
			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}

			// Check that the rule status was updated
			updatedRule := &v1alpha1.CustomRule{}
			err = fakeClient.Get(ctx, req.NamespacedName, updatedRule)
			require.NoError(t, err)

			// Verify status fields
			assert.Equal(t, tt.expectedPhase, updatedRule.Status.Phase, "Phase should match expected")

			if tt.expectedErrMsg != "" {
				assert.Contains(t, updatedRule.Status.ErrorMessage, tt.expectedErrMsg, "Error message should contain expected text")
			}

			// Check that ObservedGeneration was updated
			assert.Equal(t, tt.rule.Generation, updatedRule.Status.ObservedGeneration, "ObservedGeneration should be updated")

			// Check that LastValidationTime was set
			assert.NotNil(t, updatedRule.Status.LastValidationTime, "LastValidationTime should be set")

			// For error cases, check requeue
			if tt.expectedPhase == v1alpha1.CustomRulePhaseError {
				assert.True(t, result.RequeueAfter > 0, "Failed validation should trigger requeue")
			}
		})
	}
}

// TestCustomRuleCascadingStatusUpdate corresponds to e2e TestCustomRuleCascadingStatusUpdate.
// It validates that when a CustomRule changes from valid to invalid expression,
// the controller correctly transitions its status from Ready to Error, and that
// fixing the expression transitions it back to Ready.
func TestCustomRuleCascadingStatusUpdate(t *testing.T) {
	s := scheme.Scheme
	apis.AddToScheme(s)

	// Step 1: Create a valid CustomRule and reconcile it to Ready
	rule := &v1alpha1.CustomRule{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "cascading-rule",
			Namespace:  "test",
			Generation: 1,
		},
		Spec: v1alpha1.CustomRuleSpec{
			RulePayload: v1alpha1.RulePayload{
				ID:          "cascading-rule",
				Title:       "Pods Must Have Security Context",
				Description: "Ensures all pods have security context",
				Severity:    "medium",
				ScannerType: v1alpha1.ScannerTypeCEL,
				Expression:  "pods.items.all(pod, pod.spec.securityContext != null)",
				Inputs: []v1alpha1.InputPayload{
					{
						Name: "pods",
						KubernetesInputSpec: v1alpha1.KubernetesInputSpec{
							APIVersion: "v1",
							Resource:   "pods",
						},
					},
				},
				FailureReason: "Pod(s) found without security context",
			},
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(s).
		WithRuntimeObjects(rule).
		WithStatusSubresource(rule).
		Build()

	r := &CustomRuleReconciler{
		Client: fakeClient,
		Scheme: s,
	}

	req := reconcile.Request{
		NamespacedName: types.NamespacedName{
			Name:      rule.Name,
			Namespace: rule.Namespace,
		},
	}

	ctx := context.Background()

	// First reconcile: should become Ready
	_, err := r.Reconcile(ctx, req)
	require.NoError(t, err)

	updatedRule := &v1alpha1.CustomRule{}
	err = fakeClient.Get(ctx, req.NamespacedName, updatedRule)
	require.NoError(t, err)
	assert.Equal(t, v1alpha1.CustomRulePhaseReady, updatedRule.Status.Phase, "Rule should be Ready after valid expression")

	// Step 2: Update with invalid expression (simulating the cascading error trigger)
	updatedRule.Spec.Expression = "podsx.items.all(pod, pod.spec.securityContext != null)"
	updatedRule.Generation = 2 // Bump generation so the controller re-validates
	err = fakeClient.Update(ctx, updatedRule)
	require.NoError(t, err)

	// Reconcile again: should transition to Error
	result, err := r.Reconcile(ctx, req)
	require.NoError(t, err)

	err = fakeClient.Get(ctx, req.NamespacedName, updatedRule)
	require.NoError(t, err)
	assert.Equal(t, v1alpha1.CustomRulePhaseError, updatedRule.Status.Phase, "Rule should be Error after invalid expression")
	assert.Contains(t, updatedRule.Status.ErrorMessage, "CEL expression compilation failed")
	assert.True(t, result.RequeueAfter > 0, "Error state should trigger requeue")

	// Step 3: Fix the expression back to valid
	updatedRule.Spec.Expression = "pods.items.all(pod, pod.spec.securityContext != null)"
	updatedRule.Generation = 3
	err = fakeClient.Update(ctx, updatedRule)
	require.NoError(t, err)

	// Reconcile: should recover to Ready
	_, err = r.Reconcile(ctx, req)
	require.NoError(t, err)

	err = fakeClient.Get(ctx, req.NamespacedName, updatedRule)
	require.NoError(t, err)
	assert.Equal(t, v1alpha1.CustomRulePhaseReady, updatedRule.Status.Phase, "Rule should recover to Ready after fixing expression")
	assert.Empty(t, updatedRule.Status.ErrorMessage, "Error message should be cleared")
}

// TestCustomRuleSkipsAlreadyValidatedGeneration corresponds to the optimization
// check in the reconciler that skips re-validation when the generation hasn't changed.
func TestCustomRuleSkipsAlreadyValidatedGeneration(t *testing.T) {
	s := scheme.Scheme
	apis.AddToScheme(s)

	rule := &v1alpha1.CustomRule{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "skip-gen-rule",
			Namespace:  "test",
			Generation: 1,
		},
		Spec: v1alpha1.CustomRuleSpec{
			RulePayload: v1alpha1.RulePayload{
				ID:          "skip-gen-rule",
				Title:       "Test Rule",
				ScannerType: v1alpha1.ScannerTypeCEL,
				Expression:  "pods.items.size() >= 0",
				Inputs: []v1alpha1.InputPayload{
					{
						Name: "pods",
						KubernetesInputSpec: v1alpha1.KubernetesInputSpec{
							APIVersion: "v1",
							Resource:   "pods",
						},
					},
				},
			},
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(s).
		WithRuntimeObjects(rule).
		WithStatusSubresource(rule).
		Build()

	r := &CustomRuleReconciler{
		Client: fakeClient,
		Scheme: s,
	}

	req := reconcile.Request{
		NamespacedName: types.NamespacedName{
			Name:      rule.Name,
			Namespace: rule.Namespace,
		},
	}

	ctx := context.Background()

	// First reconcile: validates and sets Ready
	_, err := r.Reconcile(ctx, req)
	require.NoError(t, err)

	updatedRule := &v1alpha1.CustomRule{}
	err = fakeClient.Get(ctx, req.NamespacedName, updatedRule)
	require.NoError(t, err)
	assert.Equal(t, v1alpha1.CustomRulePhaseReady, updatedRule.Status.Phase)
	assert.Equal(t, int64(1), updatedRule.Status.ObservedGeneration)

	firstValidationTime := updatedRule.Status.LastValidationTime

	// Second reconcile: same generation, should skip validation (no status change)
	_, err = r.Reconcile(ctx, req)
	require.NoError(t, err)

	err = fakeClient.Get(ctx, req.NamespacedName, updatedRule)
	require.NoError(t, err)
	assert.Equal(t, v1alpha1.CustomRulePhaseReady, updatedRule.Status.Phase)
	// LastValidationTime should remain the same since validation was skipped
	assert.Equal(t, firstValidationTime, updatedRule.Status.LastValidationTime)
}
