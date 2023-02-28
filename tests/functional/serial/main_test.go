package serial

import (
	"os"
	"testing"

	"github.com/ComplianceAsCode/compliance-operator/tests/common"
	"github.com/ComplianceAsCode/compliance-operator/tests/e2e/framework"
)

// TestMain sets up, runs, and cleans up all serial tests, which must run
// serially so they don't interfere with each other.
func TestMain(m *testing.M) {

	f := framework.NewFramework()

	// Setup shared resources to use when testing, like installing the Compliance Operator
	common.SetUp(f)

	c := m.Run()

	// Last chance to clean up anything from the test run. This function is ideal for
	// cleaning up things created or configured in SetUp(). Tests that create resources
	// should clean up those resources using t.Cleanup() instead of deferring cleanup or
	// using common.TearDown() so that resources are isolated to the test that created them.
	common.TearDown(f)

	os.Exit(c)
}

func TestSuiteScan(t *testing.T) {}
