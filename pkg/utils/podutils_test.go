package utils

import (
	"testing"

	schedulev1 "k8s.io/api/scheduling/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

// TestValidatePriorityClassExist_EmptyName corresponds to e2e
// TestScheduledSuiteInvalidPriorityClass: when no priority class name is
// provided the validation should succeed without checking the API.
func TestValidatePriorityClassExist_EmptyName(t *testing.T) {
	cscheme := scheme.Scheme
	cl := fake.NewClientBuilder().WithScheme(cscheme).Build()

	exists, msg := ValidatePriorityClassExist("", cl)
	if !exists {
		t.Fatalf("expected empty name to pass validation, got: %s", msg)
	}
	if msg != "" {
		t.Fatalf("expected empty message, got: %s", msg)
	}
}

// TestValidatePriorityClassExist_Found corresponds to e2e
// TestScheduledSuitePriorityClass: a priority class that exists should
// pass validation.
func TestValidatePriorityClassExist_Found(t *testing.T) {
	cscheme := scheme.Scheme
	err := schedulev1.AddToScheme(cscheme)
	if err != nil {
		t.Fatalf("failed to add scheduling to scheme: %v", err)
	}

	pc := &schedulev1.PriorityClass{
		ObjectMeta: metav1.ObjectMeta{
			Name: "high-priority",
		},
		Value: 100,
	}

	cl := fake.NewClientBuilder().
		WithScheme(cscheme).
		WithRuntimeObjects([]runtime.Object{pc}...).
		Build()

	exists, msg := ValidatePriorityClassExist("high-priority", cl)
	if !exists {
		t.Fatalf("expected priority class to be found, got: %s", msg)
	}
	if msg != "" {
		t.Fatalf("expected empty message, got: %s", msg)
	}
}

// TestValidatePriorityClassExist_NotFound corresponds to e2e
// TestScheduledSuiteInvalidPriorityClass: a priority class name that
// does not exist should fail validation.
func TestValidatePriorityClassExist_NotFound(t *testing.T) {
	cscheme := scheme.Scheme
	err := schedulev1.AddToScheme(cscheme)
	if err != nil {
		t.Fatalf("failed to add scheduling to scheme: %v", err)
	}

	cl := fake.NewClientBuilder().
		WithScheme(cscheme).
		Build()

	exists, msg := ValidatePriorityClassExist("nonexistent-priority", cl)
	if exists {
		t.Fatal("expected priority class not to be found")
	}
	if msg == "" {
		t.Fatal("expected error message when priority class not found")
	}
}
