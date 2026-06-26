package celvalidation

import (
	"testing"

	"github.com/ComplianceAsCode/compliance-operator/pkg/apis/compliance/v1alpha1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateCELRule(t *testing.T) {
	tests := []struct {
		name      string
		ruleName  string
		payload   v1alpha1.RulePayload
		wantErr   bool
		errSubstr string
	}{
		{
			name:     "valid CEL rule with single input",
			ruleName: "test-valid-rule",
			payload: v1alpha1.RulePayload{
				Title:       "Valid Rule",
				Description: "A valid CEL rule",
				ScannerType: v1alpha1.ScannerTypeCEL,
				Expression:  "pods.items.size() > 0",
				Inputs: []v1alpha1.InputPayload{{
					Name: "pods",
					KubernetesInputSpec: v1alpha1.KubernetesInputSpec{
						APIVersion: "v1",
						Resource:   "pods",
					},
				}},
			},
			wantErr: false,
		},
		{
			name:     "valid CEL rule with multiple inputs",
			ruleName: "test-multi-input",
			payload: v1alpha1.RulePayload{
				Title:       "Multi Input Rule",
				ScannerType: v1alpha1.ScannerTypeCEL,
				Expression:  "pods.items.size() > 0 && configmaps.items.size() > 0",
				Inputs: []v1alpha1.InputPayload{
					{
						Name: "pods",
						KubernetesInputSpec: v1alpha1.KubernetesInputSpec{
							APIVersion: "v1",
							Resource:   "pods",
						},
					},
					{
						Name: "configmaps",
						KubernetesInputSpec: v1alpha1.KubernetesInputSpec{
							APIVersion: "v1",
							Resource:   "configmaps",
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name:     "valid CEL rule without metadata",
			ruleName: "no-metadata",
			payload: v1alpha1.RulePayload{
				ScannerType: v1alpha1.ScannerTypeCEL,
				Expression:  "nodes.items.size() >= 3",
				Inputs: []v1alpha1.InputPayload{{
					Name: "nodes",
					KubernetesInputSpec: v1alpha1.KubernetesInputSpec{
						APIVersion: "v1",
						Resource:   "nodes",
					},
				}},
			},
			wantErr: false,
		},
		{
			name:     "invalid CEL syntax",
			ruleName: "bad-syntax",
			payload: v1alpha1.RulePayload{
				ScannerType: v1alpha1.ScannerTypeCEL,
				Expression:  "this is not &&& valid CEL",
				Inputs: []v1alpha1.InputPayload{{
					Name: "pods",
					KubernetesInputSpec: v1alpha1.KubernetesInputSpec{
						APIVersion: "v1",
						Resource:   "pods",
					},
				}},
			},
			wantErr:   true,
			errSubstr: "CEL expression compilation failed",
		},
		{
			name:     "undeclared variable reference",
			ruleName: "undeclared-ref",
			payload: v1alpha1.RulePayload{
				ScannerType: v1alpha1.ScannerTypeCEL,
				Expression:  "undeclaredVar.items.size() > 0",
				Inputs: []v1alpha1.InputPayload{{
					Name: "pods",
					KubernetesInputSpec: v1alpha1.KubernetesInputSpec{
						APIVersion: "v1",
						Resource:   "pods",
					},
				}},
			},
			wantErr:   true,
			errSubstr: "CEL expression compilation failed",
		},
		{
			name:     "empty expression",
			ruleName: "empty-expr",
			payload: v1alpha1.RulePayload{
				ScannerType: v1alpha1.ScannerTypeCEL,
				Expression:  "",
				Inputs: []v1alpha1.InputPayload{{
					Name: "pods",
					KubernetesInputSpec: v1alpha1.KubernetesInputSpec{
						APIVersion: "v1",
						Resource:   "pods",
					},
				}},
			},
			wantErr: true,
		},
		{
			name:     "no inputs rejected by SDK",
			ruleName: "no-inputs",
			payload: v1alpha1.RulePayload{
				ScannerType: v1alpha1.ScannerTypeCEL,
				Expression:  "true",
			},
			wantErr:   true,
			errSubstr: "at least one input is required",
		},
		// --- Tests corresponding to e2e TestCustomRuleValidation (invalid function) ---
		{
			name:     "invalid CEL expression with non-existent function",
			ruleName: "invalid-function",
			payload: v1alpha1.RulePayload{
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
			},
			wantErr:   true,
			errSubstr: "CEL expression compilation failed",
		},
		// --- Tests corresponding to e2e TestCustomRuleValidation (undeclared variable in expression) ---
		{
			name:     "undeclared variable deployments used in expression but not declared as input",
			ruleName: "undeclared-deployments",
			payload: v1alpha1.RulePayload{
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
					// 'deployments' is used in the expression but NOT declared here
				},
			},
			wantErr:   true,
			errSubstr: "CEL expression compilation failed",
		},
		// --- Tests corresponding to e2e TestCustomRuleWithMultipleInputs ---
		{
			name:     "valid multiple inputs with namespaces and network policies",
			ruleName: "multi-input-netpol",
			payload: v1alpha1.RulePayload{
				Title:       "Namespaces Must Have Network Policies",
				Description: "Ensures all namespaces have at least one network policy",
				ScannerType: v1alpha1.ScannerTypeCEL,
				Expression: `namespaces.items.all(ns,
					ns.metadata.name.startsWith("kube-") ||
					ns.metadata.name == "default" ||
					networkpolicies.items.exists(np,
						np.metadata.namespace == ns.metadata.name
					)
				)`,
				Inputs: []v1alpha1.InputPayload{
					{
						Name: "namespaces",
						KubernetesInputSpec: v1alpha1.KubernetesInputSpec{
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
			},
			wantErr: false,
		},
		// --- Tests corresponding to e2e TestCustomRuleTailoredProfile (CEL expression with filter) ---
		{
			name:     "valid CEL expression with filter and label check",
			ruleName: "filter-label-check",
			payload: v1alpha1.RulePayload{
				Title:       "Test Pods Must Have Security Context",
				Description: "Ensures test pods with specific label have proper security context",
				ScannerType: v1alpha1.ScannerTypeCEL,
				Expression: `pods.items.filter(pod,
					has(pod.metadata.labels) &&
					"customrule-test" in pod.metadata.labels &&
					pod.metadata.labels["customrule-test"] == "test-value"
				).all(pod,
					has(pod.spec.securityContext) &&
					pod.spec.securityContext.runAsNonRoot == true
				)`,
				Inputs: []v1alpha1.InputPayload{
					{
						Name: "pods",
						KubernetesInputSpec: v1alpha1.KubernetesInputSpec{
							APIVersion:        "v1",
							Resource:          "pods",
							ResourceNamespace: "test-ns",
						},
					},
				},
				FailureReason: "Test pod(s) found without proper security context",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateCELRule(tt.ruleName, &tt.payload)
			if tt.wantErr {
				require.Error(t, err)
				if tt.errSubstr != "" {
					assert.Contains(t, err.Error(), tt.errSubstr)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
