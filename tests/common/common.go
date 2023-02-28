package common

import "github.com/ComplianceAsCode/compliance-operator/tests/e2e/framework"

func SetUp(f *framework.Framework) error {
	return nil
}

// TearDown runs after all tests complete and provides an opportunity to cleanup anything
// created or configured in Setup. This function is invoked per run and not after individual
// tests. Tests should explicitly add functions to t.Cleanup if they create resources that
// need to be cleaned up after that specific test completes.
func TearDown(f *framework.Framework) error {
	return nil
}
