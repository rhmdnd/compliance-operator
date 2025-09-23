package parallel_e2e

import (
	"context"
	"errors"
	"fmt"
	"log"
	"math/rand"
	"os"
	"strings"
	"testing"

	compv1alpha1 "github.com/ComplianceAsCode/compliance-operator/pkg/apis/compliance/v1alpha1"
	"github.com/ComplianceAsCode/compliance-operator/tests/e2e/framework"
	corev1 "k8s.io/api/core/v1"
	schedulingv1 "k8s.io/api/scheduling/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

var brokenContentImagePath string
var contentImagePath string

func TestMain(m *testing.M) {
	f := framework.NewFramework()
	err := f.SetUp()
	if err != nil {
		log.Fatal(err)
	}

	contentImagePath = os.Getenv("CONTENT_IMAGE")
	if contentImagePath == "" {
		fmt.Println("Please set the 'CONTENT_IMAGE' environment variable")
		os.Exit(1)
	}

	brokenContentImagePath = os.Getenv("BROKEN_CONTENT_IMAGE")

	if brokenContentImagePath == "" {
		fmt.Println("Please set the 'BROKEN_CONTENT_IMAGE' environment variable")
		os.Exit(1)
	}

	exitCode := m.Run()
	if exitCode == 0 || (exitCode > 0 && f.CleanUpOnError()) {
		if err = f.TearDown(); err != nil {
			log.Fatal(err)
		}
	}
	os.Exit(exitCode)
}

func TestProfileVersion(t *testing.T) {
	t.Parallel()
	f := framework.Global

	profile := &compv1alpha1.Profile{}
	// We know this profile has a version and it's set in the ComplianceAsCode/content
	profileName := "ocp4-cis"
	if err := f.Client.Get(context.TODO(), types.NamespacedName{Namespace: f.OperatorNamespace, Name: profileName}, profile); err != nil {
		t.Fatalf("failed to get profile %s: %s", profileName, err)
	}
	if profile.Version == "" {
		t.Fatalf("expected profile %s to have version set", profileName)
	}
}

func TestProfileModification(t *testing.T) {
	t.Parallel()
	f := framework.Global
	const (
		removedRule         = "chronyd-no-chronyc-network"
		unlinkedRule        = "chronyd-client-only"
		moderateProfileName = "moderate"
	)
	var (
		baselineImage = fmt.Sprintf("%s:%s", brokenContentImagePath, "proff_diff_baseline")
		modifiedImage = fmt.Sprintf("%s:%s", brokenContentImagePath, "proff_diff_mod")
	)

	prefixName := func(profName, ruleBaseName string) string { return profName + "-" + ruleBaseName }

	pbName := framework.GetObjNameFromTest(t)
	origPb, err := f.CreateProfileBundle(pbName, baselineImage, framework.RhcosContentFile)
	if err != nil {
		t.Fatalf("failed to create ProfileBundle: %s", err)
	}
	// This should get cleaned up at the end of the test
	defer f.Client.Delete(context.TODO(), origPb)

	if err := f.WaitForProfileBundleStatus(pbName, compv1alpha1.DataStreamValid); err != nil {
		t.Fatalf("failed waiting for the ProfileBundle to become available: %s", err)
	}
	if err := f.AssertMustHaveParsedProfiles(pbName, string(compv1alpha1.ScanTypeNode), "redhat_enterprise_linux_coreos_4"); err != nil {
		t.Fatalf("failed checking profiles in ProfileBundle: %s", err)
	}

	// Check that the rule we removed exists in the original profile
	removedRuleName := prefixName(pbName, removedRule)
	err, found := f.DoesRuleExist(origPb.Namespace, removedRuleName)
	if err != nil {
		t.Fatal(err)
	} else if found != true {
		t.Fatalf("expected rule %s to exist in namespace %s", removedRuleName, origPb.Namespace)
	}

	// Check that the rule we unlined in the modified profile is linked in the original
	profileName := prefixName(pbName, moderateProfileName)
	profilePreUpdate := &compv1alpha1.Profile{}
	if err := f.Client.Get(context.TODO(), types.NamespacedName{Namespace: origPb.Namespace, Name: profileName}, profilePreUpdate); err != nil {
		t.Fatalf("failed to get profile %s", profileName)
	}
	unlinkedRuleName := prefixName(pbName, unlinkedRule)
	found = framework.IsRuleInProfile(unlinkedRuleName, profilePreUpdate)
	if found == false {
		t.Fatalf("failed to find rule %s in profile %s", unlinkedRule, profileName)
	}

	// update the image with a new hash
	modPb := origPb.DeepCopy()
	if err := f.Client.Get(context.TODO(), types.NamespacedName{Namespace: modPb.Namespace, Name: modPb.Name}, modPb); err != nil {
		t.Fatalf("failed to get ProfileBundle %s", modPb.Name)
	}

	modPb.Spec.ContentImage = modifiedImage
	if err := f.Client.Update(context.TODO(), modPb); err != nil {
		t.Fatalf("failed to update ProfileBundle %s: %s", modPb.Name, err)
	}

	// Wait for the update to happen, the PB will flip first to pending, then to valid
	if err := f.WaitForProfileBundleStatus(pbName, compv1alpha1.DataStreamValid); err != nil {
		t.Fatalf("failed to parse ProfileBundle %s: %s", pbName, err)
	}

	if err := f.AssertProfileBundleMustHaveParsedRules(pbName); err != nil {
		t.Fatal(err)
	}

	// We removed this rule in the update, is must no longer exist
	err, found = f.DoesRuleExist(origPb.Namespace, removedRuleName)
	if err != nil {
		t.Fatal(err)
	} else if found {
		t.Fatalf("rule %s unexpectedly found", removedRuleName)
	}

	// This rule was unlinked
	profilePostUpdate := &compv1alpha1.Profile{}
	if err := f.Client.Get(context.TODO(), types.NamespacedName{Namespace: origPb.Namespace, Name: profileName}, profilePostUpdate); err != nil {
		t.Fatalf("failed to get profile %s: %s", profileName, err)
	}
	framework.IsRuleInProfile(unlinkedRuleName, profilePostUpdate)
	if found {
		t.Fatalf("rule %s unexpectedly found", unlinkedRuleName)
	}
}

func TestProfileISTagUpdate(t *testing.T) {
	t.Parallel()
	f := framework.Global
	const (
		removedRule         = "chronyd-no-chronyc-network"
		unlinkedRule        = "chronyd-client-only"
		moderateProfileName = "moderate"
	)
	var (
		baselineImage = fmt.Sprintf("%s:%s", brokenContentImagePath, "proff_diff_baseline")
		modifiedImage = fmt.Sprintf("%s:%s", brokenContentImagePath, "proff_diff_mod")
	)

	prefixName := func(profName, ruleBaseName string) string { return profName + "-" + ruleBaseName }

	pbName := framework.GetObjNameFromTest(t)
	iSName := pbName

	s, err := f.CreateImageStream(iSName, f.OperatorNamespace, baselineImage)
	if err != nil {
		t.Fatalf("failed to create image stream %s", iSName)
	}
	defer f.Client.Delete(context.TODO(), s)

	baselineImage = fmt.Sprintf("%s:%s", iSName, "latest")
	pb, err := f.CreateProfileBundle(pbName, baselineImage, framework.RhcosContentFile)
	if err != nil {
		t.Fatalf("failed to create ProfileBundle: %s", err)
	}
	defer f.Client.Delete(context.TODO(), pb)

	if err := f.WaitForProfileBundleStatus(pbName, compv1alpha1.DataStreamValid); err != nil {
		t.Fatalf("failed waiting for the ProfileBundle to become available: %s", err)
	}
	if err := f.AssertMustHaveParsedProfiles(pbName, string(compv1alpha1.ScanTypeNode), "redhat_enterprise_linux_coreos_4"); err != nil {
		t.Fatalf("failed checking profiles in ProfileBundle: %s", err)
	}

	// Check that the rule we removed exists in the original profile
	removedRuleName := prefixName(pbName, removedRule)
	err, found := f.DoesRuleExist(pb.Namespace, removedRuleName)
	if err != nil {
		t.Fatal(err)
	} else if !found {
		t.Fatalf("failed to find rule %s in ProfileBundle %s", removedRuleName, pbName)
	}

	// Check that the rule we unlined in the modified profile is linked in the original
	profilePreUpdate := &compv1alpha1.Profile{}
	profileName := prefixName(pbName, moderateProfileName)
	if err := f.Client.Get(context.TODO(), types.NamespacedName{Namespace: pb.Namespace, Name: profileName}, profilePreUpdate); err != nil {
		t.Fatalf("failed to get profile %s", profileName)
	}
	unlinkedRuleName := prefixName(pbName, unlinkedRule)
	found = framework.IsRuleInProfile(unlinkedRuleName, profilePreUpdate)
	if !found {
		t.Fatalf("failed to find rule %s in ProfileBundle %s", unlinkedRuleName, pbName)
	}

	// Update the reference in the image stream
	if err := f.UpdateImageStreamTag(iSName, modifiedImage, f.OperatorNamespace); err != nil {
		t.Fatalf("failed to update image stream %s: %s", iSName, err)
	}

	modifiedImageDigest, err := f.GetImageStreamUpdatedDigest(iSName, f.OperatorNamespace)
	if err != nil {
		t.Fatalf("failed to get digest for image stream %s: %s", iSName, err)
	}

	// Note that when an update happens through an imagestream tag, the operator doesn't get
	// a notification about it... It all happens on the Kube Deployment's side.
	// So we don't need to wait for the profile bundle's statuses
	if err := f.WaitForDeploymentContentUpdate(pbName, modifiedImageDigest); err != nil {
		t.Fatalf("failed waiting for content to update: %s", err)
	}

	if err := f.AssertProfileBundleMustHaveParsedRules(pbName); err != nil {
		t.Fatal(err)
	}

	// We removed this rule in the update, it must no longer exist
	err, found = f.DoesRuleExist(pb.Namespace, removedRuleName)
	if err != nil {
		t.Fatal(err)
	} else if found {
		t.Fatalf("rule %s unexpectedly found", removedRuleName)
	}

	// This rule was unlinked
	profilePostUpdate := &compv1alpha1.Profile{}
	if err := f.Client.Get(context.TODO(), types.NamespacedName{Namespace: pb.Namespace, Name: profileName}, profilePostUpdate); err != nil {
		t.Fatalf("failed to get profile %s", profileName)
	}
	found = framework.IsRuleInProfile(unlinkedRuleName, profilePostUpdate)
	if found {
		t.Fatalf("rule %s unexpectedly found", unlinkedRuleName)
	}
}

func TestProfileISTagOtherNs(t *testing.T) {
	t.Parallel()
	f := framework.Global
	const (
		removedRule         = "chronyd-no-chronyc-network"
		unlinkedRule        = "chronyd-client-only"
		moderateProfileName = "moderate"
	)
	var (
		baselineImage = fmt.Sprintf("%s:%s", brokenContentImagePath, "proff_diff_baseline")
		modifiedImage = fmt.Sprintf("%s:%s", brokenContentImagePath, "proff_diff_mod")
	)

	prefixName := func(profName, ruleBaseName string) string { return profName + "-" + ruleBaseName }

	pbName := framework.GetObjNameFromTest(t)
	iSName := pbName
	otherNs := "openshift"

	stream, err := f.CreateImageStream(iSName, otherNs, baselineImage)
	if err != nil {
		t.Fatalf("failed to create image stream %s\n", iSName)
	}
	defer f.Client.Delete(context.TODO(), stream)

	baselineImage = fmt.Sprintf("%s/%s:%s", otherNs, iSName, "latest")
	pb, err := f.CreateProfileBundle(pbName, baselineImage, framework.RhcosContentFile)
	if err != nil {
		t.Fatalf("failed to create ProfileBundle %s: %s", pbName, err)
	}
	defer f.Client.Delete(context.TODO(), pb)

	if err := f.WaitForProfileBundleStatus(pbName, compv1alpha1.DataStreamValid); err != nil {
		t.Fatalf("failed waiting for ProfileBundle to parse: %s", err)
	}
	if err := f.AssertMustHaveParsedProfiles(pbName, string(compv1alpha1.ScanTypeNode), "redhat_enterprise_linux_coreos_4"); err != nil {
		t.Fatalf("failed to assert profiles in ProfileBundle %s: %s", pbName, err)
	}

	// Check that the rule we removed exists in the original profile
	removedRuleName := prefixName(pbName, removedRule)
	err, found := f.DoesRuleExist(pb.Namespace, removedRuleName)
	if err != nil {
		t.Fatal(err)
	} else if !found {
		t.Fatalf("expected rule %s to exist", removedRuleName)
	}

	// Check that the rule we unlined in the modified profile is linked in the original
	profilePreUpdate := &compv1alpha1.Profile{}
	profileName := prefixName(pbName, moderateProfileName)
	if err := f.Client.Get(context.TODO(), types.NamespacedName{Namespace: pb.Namespace, Name: profileName}, profilePreUpdate); err != nil {
		t.Fatalf("failed to get profile %s: %s", profileName, err)
	}
	unlinkedRuleName := prefixName(pbName, unlinkedRule)
	found = framework.IsRuleInProfile(unlinkedRuleName, profilePreUpdate)
	if !found {
		t.Fatalf("expected to find rule %s in profile %s", unlinkedRuleName, profileName)
	}

	// Update the reference in the image stream
	if err := f.UpdateImageStreamTag(iSName, modifiedImage, otherNs); err != nil {
		t.Fatalf("failed to update image stream %s: %s", iSName, err)
	}

	modifiedImageDigest, err := f.GetImageStreamUpdatedDigest(iSName, otherNs)
	if err != nil {
		t.Fatalf("failed to get digest for image stream %s: %s", iSName, err)
	}

	// Note that when an update happens through an imagestream tag, the operator doesn't get
	// a notification about it... It all happens on the Kube Deployment's side.
	// So we don't need to wait for the profile bundle's statuses
	if err := f.WaitForDeploymentContentUpdate(pbName, modifiedImageDigest); err != nil {
		t.Fatalf("failed waiting for content to update: %s", err)
	}

	if err := f.AssertProfileBundleMustHaveParsedRules(pbName); err != nil {
		t.Fatal(err)
	}
	// We removed this rule in the update, it must no longer exist
	err, found = f.DoesRuleExist(pb.Namespace, removedRuleName)
	if err != nil {
		t.Fatal(err)
	} else if found {
		t.Fatalf("rule %s unexpectedly found", removedRuleName)
	}

	// This rule was unlinked
	profilePostUpdate := &compv1alpha1.Profile{}
	if err := f.Client.Get(context.TODO(), types.NamespacedName{Namespace: pb.Namespace, Name: profileName}, profilePostUpdate); err != nil {
		t.Fatalf("failed to get profile %s", profileName)
	}
	found = framework.IsRuleInProfile(unlinkedRuleName, profilePostUpdate)
	if found {
		t.Fatalf("rule %s unexpectedly found", unlinkedRuleName)
	}

}

func TestInvalidBundleWithUnexistentRef(t *testing.T) {
	t.Parallel()
	f := framework.Global
	const (
		unexistentImage = "bad-namespace/bad-image:latest"
	)

	pbName := framework.GetObjNameFromTest(t)
	pb, err := f.CreateProfileBundle(pbName, unexistentImage, framework.RhcosContentFile)
	if err != nil {
		t.Fatalf("failed to create ProfileBundle %s: %s", pbName, err)
	}
	defer f.Client.Delete(context.TODO(), pb)

	if err := f.WaitForProfileBundleStatus(pbName, compv1alpha1.DataStreamInvalid); err != nil {
		t.Fatal(err)
	}
}

func TestInvalidBundleWithNoTag(t *testing.T) {
	t.Parallel()
	f := framework.Global
	const (
		noTagImage = "bad-namespace/bad-image"
	)

	pbName := framework.GetObjNameFromTest(t)

	pb, err := f.CreateProfileBundle(pbName, noTagImage, framework.RhcosContentFile)
	if err != nil {
		t.Fatalf("failed to create ProfileBundle %s: %s", pbName, err)
	}
	defer f.Client.Delete(context.TODO(), pb)

	if err := f.WaitForProfileBundleStatus(pbName, compv1alpha1.DataStreamInvalid); err != nil {
		t.Fatal(err)
	}
}

func TestServiceMonitoringMetricsTarget(t *testing.T) {
	t.Parallel()
	f := framework.Global

	err := f.SetupRBACForMetricsTest()
	if err != nil {
		t.Fatalf("failed to create service account: %s", err)
	}
	defer f.CleanUpRBACForMetricsTest()

	metricsTargets, err := f.WaitForPrometheusMetricTargets()
	if err != nil {
		t.Fatalf("failed to get prometheus metric targets: %s", err)
	}

	expectedMetricsCount := 2

	err = f.AssertServiceMonitoringMetricsTarget(metricsTargets, expectedMetricsCount)
	if err != nil {
		t.Fatalf("failed to assert metrics target: %s", err)
	}
}

func TestParsingErrorRestartsParserInitContainer(t *testing.T) {
	t.Parallel()
	f := framework.Global
	var (
		badImage  = fmt.Sprintf("%s:%s", brokenContentImagePath, "from")
		goodImage = fmt.Sprintf("%s:%s", brokenContentImagePath, "to")
	)

	pbName := framework.GetObjNameFromTest(t)

	pb, err := f.CreateProfileBundle(pbName, badImage, framework.OcpContentFile)
	if err != nil {
		t.Fatalf("failed to create ProfileBundle %s: %s", pbName, err)
	}
	defer f.Client.Delete(context.TODO(), pb)

	if err := f.WaitForProfileBundleStatus(pbName, compv1alpha1.DataStreamInvalid); err != nil {
		t.Fatal(err)
	}

	// list the pods with profilebundle=pbName
	var lastErr error
	timeouterr := wait.Poll(framework.RetryInterval, framework.Timeout, func() (bool, error) {
		podList := &corev1.PodList{}
		inNs := client.InNamespace(f.OperatorNamespace)
		withLabel := client.MatchingLabels{"profile-bundle": pbName}
		if lastErr := f.Client.List(context.TODO(), podList, inNs, withLabel); lastErr != nil {
			return false, lastErr
		}

		if len(podList.Items) != 1 {
			return false, fmt.Errorf("expected one parser pod, listed %d", len(podList.Items))
		}
		parserPod := &podList.Items[0]

		// check that pod's initContainerStatuses field with name=profileparser has restartCount > 0 and that
		// lastState.Terminated.ExitCode != 0. This way we'll know we're restarting the init container
		// and retrying the parsing
		for i := range parserPod.Status.InitContainerStatuses {
			ics := parserPod.Status.InitContainerStatuses[i]
			if ics.Name != "profileparser" {
				continue
			}
			if ics.RestartCount < 1 {
				log.Println("The profileparser did not restart (yet?)")
				return false, nil
			}

			// wait until we get the restarted state
			if ics.LastTerminationState.Terminated == nil {
				log.Println("The profileparser does not have terminating state")
				return false, nil
			}
			if ics.LastTerminationState.Terminated.ExitCode == 0 {
				return true, fmt.Errorf("profileparser finished unsuccessfully")
			}
		}

		return true, nil
	})

	if err := framework.ProcessErrorOrTimeout(lastErr, timeouterr, "waiting for ProfileBundle parser to restart"); err != nil {
		t.Fatal(err)
	}

	// Fix the image and wait for the profilebundle to be parsed OK
	getPb := &compv1alpha1.ProfileBundle{}
	if err := f.Client.Get(context.TODO(), types.NamespacedName{Name: pbName, Namespace: f.OperatorNamespace}, getPb); err != nil {
		t.Fatalf("failed to get ProfileBundle %s: %s", pbName, err)
	}

	updatePb := getPb.DeepCopy()
	updatePb.Spec.ContentImage = goodImage
	if err := f.Client.Update(context.TODO(), updatePb); err != nil {
		t.Fatalf("failed to update ProfileBundle %s: %s", pbName, err)
	}

	if err := f.WaitForProfileBundleStatus(pbName, compv1alpha1.DataStreamValid); err != nil {
		t.Fatal(err)
	}
	if err := f.WaitForProfileBundleStatus(pbName, compv1alpha1.DataStreamValid); err != nil {
		t.Fatal(err)
	}
}

func TestRulesAreClassifiedAppropriately(t *testing.T) {
	t.Parallel()
	f := framework.Global
	for _, expected := range []struct {
		RuleName  string
		CheckType string
	}{
		{
			"ocp4-configure-network-policies-namespaces",
			compv1alpha1.CheckTypePlatform,
		},
		{
			"ocp4-directory-access-var-log-kube-audit",
			compv1alpha1.CheckTypeNode,
		},
		{
			"ocp4-general-apply-scc",
			compv1alpha1.CheckTypeNone,
		},
		{
			"ocp4-kubelet-enable-protect-kernel-sysctl",
			compv1alpha1.CheckTypeNode,
		},
	} {
		targetRule := &compv1alpha1.Rule{}
		key := types.NamespacedName{
			Name:      expected.RuleName,
			Namespace: f.OperatorNamespace,
		}

		if err := f.Client.Get(context.TODO(), key, targetRule); err != nil {
			t.Fatalf("failed to get rule %s: %s", targetRule.Name, err)
		}

		if targetRule.CheckType != expected.CheckType {
			log.Printf("Expected rule '%s' to be of type '%s'. Instead was: '%s'",
				expected.RuleName, expected.CheckType, targetRule.CheckType)
		}
	}
}

func TestSingleScanSucceeds(t *testing.T) {
	t.Parallel()
	f := framework.Global

	scanName := framework.GetObjNameFromTest(t)
	testScan := &compv1alpha1.ComplianceScan{
		ObjectMeta: metav1.ObjectMeta{
			Name:      scanName,
			Namespace: f.OperatorNamespace,
		},
		Spec: compv1alpha1.ComplianceScanSpec{
			Profile:      "xccdf_org.ssgproject.content_profile_moderate",
			Content:      framework.RhcosContentFile,
			ContentImage: contentImagePath,
			Rule:         "xccdf_org.ssgproject.content_rule_no_netrc_files",
			ComplianceScanSettings: compv1alpha1.ComplianceScanSettings{
				Debug: true,
			},
		},
	}
	// use Context's create helper to create the object and add a cleanup function for the new object
	err := f.Client.Create(context.TODO(), testScan, nil)
	if err != nil {
		t.Fatalf("failed to create scan %s: %s", scanName, err)
	}
	defer f.Client.Delete(context.TODO(), testScan)

	// Verify scanner container security capabilities during running phase
	err = f.WaitForScanStatus(f.OperatorNamespace, scanName, compv1alpha1.PhaseRunning)
	if err != nil {
		t.Fatal(err)
	}

	// Assert scanner container has correct capabilities (drops all, only has CAP_SYS_CHROOT)
	pods, err := f.GetPodsForScan(scanName)
	if err != nil {
		t.Fatal(err)
	}
	if len(pods) < 1 {
		t.Fatal("No scanner pods found for the scan")
	}

	// Find the scanner container and verify its capabilities
	found := false
	for _, pod := range pods {
		for _, container := range pod.Spec.Containers {
			if container.Name == "scanner" {
				found = true
				if container.SecurityContext == nil {
					t.Fatal("Scanner container has no security context")
				}
				if container.SecurityContext.Capabilities == nil {
					t.Fatal("Scanner container has no capabilities configuration")
				}

				// Verify privileged mode is false
				if container.SecurityContext.Privileged != nil && *container.SecurityContext.Privileged {
					t.Fatal("Expected scanner container to run in non-privileged mode")
				}

				// Verify all capabilities are dropped
				droppedCaps := container.SecurityContext.Capabilities.Drop
				if len(droppedCaps) != 1 || string(droppedCaps[0]) != "ALL" {
					t.Fatalf("Expected scanner container to drop ALL capabilities, got: %v", droppedCaps)
				}

				// Verify only CAP_SYS_CHROOT is added
				addedCaps := container.SecurityContext.Capabilities.Add
				if len(addedCaps) != 1 || string(addedCaps[0]) != "CAP_SYS_CHROOT" {
					t.Fatalf("Expected scanner container to only have CAP_SYS_CHROOT capability, got: %v", addedCaps)
				}
				break
			}
		}
		if found {
			break
		}
	}

	if !found {
		t.Fatal("Scanner container not found in any pod")
	}

	err = f.WaitForScanStatus(f.OperatorNamespace, scanName, compv1alpha1.PhaseDone)
	if err != nil {
		t.Fatal(err)
	}

	err = f.AssertScanIsCompliant(scanName, f.OperatorNamespace)
	if err != nil {
		t.Fatal(err)
	}

	aggrString := fmt.Sprintf("compliance_operator_compliance_scan_status_total{name=\"%s\",phase=\"AGGREGATING\",result=\"NOT-AVAILABLE\"}", scanName)
	metricsSet := map[string]int{
		fmt.Sprintf("compliance_operator_compliance_scan_status_total{name=\"%s\",phase=\"DONE\",result=\"COMPLIANT\"}", scanName):          1,
		fmt.Sprintf("compliance_operator_compliance_scan_status_total{name=\"%s\",phase=\"LAUNCHING\",result=\"NOT-AVAILABLE\"}", scanName): 1,
		fmt.Sprintf("compliance_operator_compliance_scan_status_total{name=\"%s\",phase=\"PENDING\",result=\"\"}", scanName):                1,
		fmt.Sprintf("compliance_operator_compliance_scan_status_total{name=\"%s\",phase=\"RUNNING\",result=\"NOT-AVAILABLE\"}", scanName):   1,
	}

	var metErr error
	// Aggregating may be variable, could be registered 1 to 3 times.
	for i := 1; i < 4; i++ {
		metricsSet[aggrString] = i
		err = framework.AssertEachMetric(f.OperatorNamespace, metricsSet)
		if err == nil {
			metErr = nil
			break
		}
		metErr = err
	}

	if metErr != nil {
		t.Fatalf("failed to assert metrics for scan %s: %s\n", scanName, metErr)
	}

	err = f.AssertScanHasValidPVCReference(scanName, f.OperatorNamespace)
	if err != nil {
		t.Fatalf("failed to assert PVC reference for scan %s: %s", scanName, err)
	}
}

func TestSingleScanTimestamps(t *testing.T) {
	t.Parallel()
	f := framework.Global

	scanName := framework.GetObjNameFromTest(t)
	testScan := &compv1alpha1.ComplianceScan{
		ObjectMeta: metav1.ObjectMeta{
			Name:      scanName,
			Namespace: f.OperatorNamespace,
		},
		Spec: compv1alpha1.ComplianceScanSpec{
			Profile:      "xccdf_org.ssgproject.content_profile_moderate",
			Content:      framework.RhcosContentFile,
			ContentImage: contentImagePath,
			Rule:         "xccdf_org.ssgproject.content_rule_no_netrc_files",
			ComplianceScanSettings: compv1alpha1.ComplianceScanSettings{
				Debug: true,
			},
		},
	}
	// use Context's create helper to create the object and add a cleanup function for the new object
	err := f.Client.Create(context.TODO(), testScan, nil)
	if err != nil {
		t.Fatalf("failed to create scan %s: %s", scanName, err)
	}
	defer f.Client.Delete(context.TODO(), testScan)

	err = f.WaitForScanStatus(f.OperatorNamespace, scanName, compv1alpha1.PhaseDone)
	if err != nil {
		t.Fatal(err)
	}

	// assertComplianceCheckResultTimestamps checks that the timestamps are set
	// and that they are set to the same value of startTimestamp of the scan
	err = f.AssertComplianceCheckResultTimestamps(scanName, f.OperatorNamespace)
	if err != nil {
		t.Fatal(err)
	}

	// rerun the scan
	err = f.ReRunScan(scanName, f.OperatorNamespace)
	if err != nil {
		t.Fatal(err)
	}
	err = f.WaitForScanStatus(f.OperatorNamespace, scanName, compv1alpha1.PhaseDone)
	if err != nil {
		t.Fatal(err)
	}

	// assertComplianceCheckResultTimestamps checks that the timestamps are set
	// and that they are set to the same value of startTimestamp of the scan
	err = f.AssertComplianceCheckResultTimestamps(scanName, f.OperatorNamespace)
	if err != nil {
		t.Fatal(err)
	}

}

func TestNonExistentDeprecatedProfile(t *testing.T) {
	t.Parallel()
	f := framework.Global

	scanName := framework.GetObjNameFromTest(t)
	testScan := &compv1alpha1.ComplianceScan{
		ObjectMeta: metav1.ObjectMeta{
			Name:      scanName,
			Namespace: f.OperatorNamespace,
		},
		Spec: compv1alpha1.ComplianceScanSpec{
			Profile:      "xccdf_org.ssgproject.content_profile_non_existing_profile",
			Content:      framework.OcpContentFile,
			ContentImage: contentImagePath,
			ComplianceScanSettings: compv1alpha1.ComplianceScanSettings{
				Debug: true,
			},
		},
	}
	// use Context's create helper to create the object and add a cleanup function for the new object
	err := f.Client.Create(context.TODO(), testScan, nil)
	if err != nil {
		t.Fatalf("failed to create scan %s: %s", scanName, err)
	}
	defer f.Client.Delete(context.TODO(), testScan)

	// The profile deprecation warning is sent out during Pending phase
	err = f.WaitForScanStatus(f.OperatorNamespace, scanName, compv1alpha1.PhaseDone)
	if err != nil {
		t.Fatal(err)
	}

	err = f.AssertScanIsInError(scanName, f.OperatorNamespace)
	if err != nil {
		t.Fatal(err)
	}

	if err = f.Client.Get(context.TODO(), types.NamespacedName{Name: scanName, Namespace: f.OperatorNamespace}, testScan); err != nil {
		t.Fatal(err)
	}
	if testScan.Status.ErrorMessage != "Could not check whether the Profile used by ComplianceScan is deprecated" {
		t.Fatal(errors.New("expected error message to be from failed profile deprecation check"))
	}
}

func TestScanTailoredProfileIsDeprecated(t *testing.T) {
	t.Parallel()
	f := framework.Global

	tpName := "test-tailored-profile-is-deprecated"
	tp := &compv1alpha1.TailoredProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name:      tpName,
			Namespace: f.OperatorNamespace,
			Annotations: map[string]string{
				compv1alpha1.ProfileStatusAnnotation: "deprecated",
			},
		},
		Spec: compv1alpha1.TailoredProfileSpec{
			Extends:     "ocp4-cis",
			Title:       "TestScanTailoredProfileIsDeprecated",
			Description: "TestScanTailoredProfileIsDeprecated",
			EnableRules: []compv1alpha1.RuleReferenceSpec{
				{
					Name:      "ocp4-cluster-version-operator-exists",
					Rationale: "Test tailored profile extends deprecated",
				},
			},
		},
	}
	err := f.Client.Create(context.TODO(), tp, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Client.Delete(context.TODO(), tp)

	suiteName := framework.GetObjNameFromTest(t)
	ssb := &compv1alpha1.ScanSettingBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      suiteName,
			Namespace: f.OperatorNamespace,
		},
		Profiles: []compv1alpha1.NamedObjectReference{
			{
				APIGroup: "compliance.openshift.io/v1alpha1",
				Kind:     "TailoredProfile",
				Name:     tpName,
			},
		},
		SettingsRef: &compv1alpha1.NamedObjectReference{
			APIGroup: "compliance.openshift.io/v1alpha1",
			Kind:     "ScanSetting",
			Name:     "default",
		},
	}
	err = f.Client.Create(context.TODO(), ssb, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Client.Delete(context.TODO(), ssb)

	// When using SSB with TailoredProfile, the scan has same name as the TP
	scanName := tpName
	if err = f.WaitForProfileDeprecatedWarning(t, scanName, tpName); err != nil {
		t.Fatal(err)
	}

	if err = f.WaitForScanStatus(f.OperatorNamespace, scanName, compv1alpha1.PhaseDone); err != nil {
		t.Fatal(err)
	}
}

func TestScanProducesRemediations(t *testing.T) {
	t.Parallel()
	f := framework.Global
	bindingName := framework.GetObjNameFromTest(t)
	tpName := framework.GetObjNameFromTest(t)

	// When using a profile directly, the profile name gets re-used
	// in the scan. By using a tailored profile we ensure that
	// the scan is unique and we get no clashes.
	tp := &compv1alpha1.TailoredProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name:      tpName,
			Namespace: f.OperatorNamespace,
		},
		Spec: compv1alpha1.TailoredProfileSpec{
			Title:       "TestScanProducesRemediations",
			Description: "TestScanProducesRemediations",
			Extends:     "ocp4-moderate",
		},
	}

	createTPErr := f.Client.Create(context.TODO(), tp, nil)
	if createTPErr != nil {
		t.Fatal(createTPErr)
	}
	defer f.Client.Delete(context.TODO(), tp)
	scanSettingBinding := compv1alpha1.ScanSettingBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      bindingName,
			Namespace: f.OperatorNamespace,
		},
		Profiles: []compv1alpha1.NamedObjectReference{
			{
				Name:     tpName,
				Kind:     "TailoredProfile",
				APIGroup: "compliance.openshift.io/v1alpha1",
			},
		},
		SettingsRef: &compv1alpha1.NamedObjectReference{
			Name:     "default",
			Kind:     "ScanSetting",
			APIGroup: "compliance.openshift.io/v1alpha1",
		},
	}
	// use Context's create helper to create the object and add a cleanup function for the new object
	err := f.Client.Create(context.TODO(), &scanSettingBinding, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Client.Delete(context.TODO(), &scanSettingBinding)
	if err := f.WaitForSuiteScansStatus(f.OperatorNamespace, bindingName, compv1alpha1.PhaseDone, compv1alpha1.ResultNonCompliant); err != nil {
		t.Fatal(err)
	}

	// Since the scan was not compliant, there should be some remediations and none
	// of them should be an error
	inNs := client.InNamespace(f.OperatorNamespace)
	withLabel := client.MatchingLabels{compv1alpha1.SuiteLabel: bindingName}
	fmt.Println(inNs, withLabel)
	remList := &compv1alpha1.ComplianceRemediationList{}
	err = f.Client.List(context.TODO(), remList, inNs, withLabel)
	if err != nil {
		t.Fatal(err)
	}

	if len(remList.Items) == 0 {
		t.Fatal("expected at least one remediation")
	}
	for _, rem := range remList.Items {
		if rem.Status.ApplicationState != compv1alpha1.RemediationNotApplied {
			t.Fatal("expected all remediations are unapplied when scan finishes")
		}
	}
}

func TestSingleScanWithStorageSucceeds(t *testing.T) {
	t.Parallel()
	f := framework.Global
	scanName := framework.GetObjNameFromTest(t)
	testScan := &compv1alpha1.ComplianceScan{
		ObjectMeta: metav1.ObjectMeta{
			Name:      scanName,
			Namespace: f.OperatorNamespace,
		},
		Spec: compv1alpha1.ComplianceScanSpec{
			Profile:      "xccdf_org.ssgproject.content_profile_moderate",
			Content:      framework.RhcosContentFile,
			ContentImage: contentImagePath,
			Rule:         "xccdf_org.ssgproject.content_rule_no_netrc_files",
			ComplianceScanSettings: compv1alpha1.ComplianceScanSettings{
				RawResultStorage: compv1alpha1.RawResultStorageSettings{
					Size: "2Gi",
				},
				Debug: true,
			},
		},
	}
	// use Context's create helper to create the object and add a cleanup function for the new object
	err := f.Client.Create(context.TODO(), testScan, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Client.Delete(context.TODO(), testScan)
	err = f.WaitForScanStatus(f.OperatorNamespace, scanName, compv1alpha1.PhaseDone)
	if err != nil {
		t.Fatal(err)
	}

	err = f.AssertScanIsCompliant(scanName, f.OperatorNamespace)
	if err != nil {
		t.Fatal(err)
	}
	err = f.AssertScanHasValidPVCReferenceWithSize(scanName, "2Gi", f.OperatorNamespace)
	if err != nil {
		t.Fatal(err)
	}
}

func TestScanWithUnexistentResourceFails(t *testing.T) {
	// This tests scan behavior when Kubernetes resource doesn't exist
	// The data stream, content image and profile all exist
	t.Parallel()
	f := framework.Global
	pbName := framework.GetObjNameFromTest(t)
	var unexistentImage = fmt.Sprintf("%s:%s", brokenContentImagePath, "unexistent_resource")
	origPb, err := f.CreateProfileBundle(pbName, unexistentImage, framework.UnexistentResourceContentFile)
	if err != nil {
		t.Fatalf("failed to create ProfileBundle: %s", err)
	}
	// This should get cleaned up at the end of the test
	defer f.Client.Delete(context.TODO(), origPb)
	if err = f.WaitForProfileBundleStatus(pbName, compv1alpha1.DataStreamValid); err != nil {
		t.Fatalf("failed waiting for the ProfileBundle to become available: %s", err)
	}

	scanName := framework.GetObjNameFromTest(t)
	testScan := &compv1alpha1.ComplianceScan{
		ObjectMeta: metav1.ObjectMeta{
			Name:      scanName,
			Namespace: f.OperatorNamespace,
		},
		Spec: compv1alpha1.ComplianceScanSpec{
			Profile:      "xccdf_org.ssgproject.content_profile_test",
			Content:      framework.UnexistentResourceContentFile,
			ContentImage: unexistentImage,
			Rule:         "xccdf_org.ssgproject.content_rule_api_server_unexistent_resource",
			ScanType:     compv1alpha1.ScanTypePlatform,
		},
	}
	// use Context's create helper to create the object and add a cleanup function for the new object
	err = f.Client.Create(context.TODO(), testScan, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Client.Delete(context.TODO(), testScan)
	err = f.WaitForScanStatus(f.OperatorNamespace, scanName, compv1alpha1.PhaseDone)
	if err != nil {
		t.Fatal(err)
	}

	err = f.AssertScanIsNonCompliant(scanName, f.OperatorNamespace)
	if err != nil {
		t.Fatal(err)
	}

	if err = f.ScanHasWarnings(scanName, f.OperatorNamespace); err != nil {
		t.Fatal(err)
	}
}

func TestScanStorageOutOfLimitRangeFails(t *testing.T) {
	t.Parallel()
	f := framework.Global
	// Create LimitRange
	lr := &corev1.LimitRange{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "pvc-limitrange",
			Namespace: f.OperatorNamespace,
		},
		Spec: corev1.LimitRangeSpec{
			Limits: []corev1.LimitRangeItem{
				{
					Type: corev1.LimitTypePersistentVolumeClaim,
					Max: corev1.ResourceList{
						corev1.ResourceStorage: resource.MustParse("5Gi"),
					},
				},
			},
		},
	}
	if err := f.Client.Create(context.TODO(), lr, nil); err != nil {
		t.Fatal(err)
	}
	defer f.Client.Delete(context.TODO(), lr)

	scanName := framework.GetObjNameFromTest(t)
	testScan := &compv1alpha1.ComplianceScan{
		ObjectMeta: metav1.ObjectMeta{
			Name:      scanName,
			Namespace: f.OperatorNamespace,
		},
		Spec: compv1alpha1.ComplianceScanSpec{
			Profile:      "xccdf_org.ssgproject.content_profile_moderate",
			Content:      framework.RhcosContentFile,
			ContentImage: contentImagePath,
			Rule:         "xccdf_org.ssgproject.content_rule_no_netrc_files",
			ComplianceScanSettings: compv1alpha1.ComplianceScanSettings{
				RawResultStorage: compv1alpha1.RawResultStorageSettings{
					Size: "6Gi",
				},
				Debug: true,
			},
		},
	}
	// use Context's create helper to create the object and add a cleanup function for the new object
	err := f.Client.Create(context.TODO(), testScan, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Client.Delete(context.TODO(), testScan)
	f.WaitForScanStatus(f.OperatorNamespace, scanName, compv1alpha1.PhaseDone)
	err = f.AssertScanIsInError(scanName, f.OperatorNamespace)
	if err != nil {
		t.Fatal(err)
	}

}

func TestSingleTailoredScanSucceeds(t *testing.T) {
	t.Parallel()
	f := framework.Global

	tpName := "test-tailoredprofile"
	tp := &compv1alpha1.TailoredProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name:      tpName,
			Namespace: f.OperatorNamespace,
			Annotations: map[string]string{
				compv1alpha1.ProductTypeAnnotation: "Node",
			},
		},
		Spec: compv1alpha1.TailoredProfileSpec{
			Title:       "TestSingleTailoredScanSucceeds",
			Description: "TestSingleTailoredScanSucceeds",
			EnableRules: []compv1alpha1.RuleReferenceSpec{
				{
					Name:      "rhcos4-no-netrc-files",
					Rationale: "Test for platform profile tailoring",
				},
			},
		},
	}
	err := f.Client.Create(context.TODO(), tp, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Client.Delete(context.TODO(), tp)

	err = f.WaitForTailoredProfileStatus(f.OperatorNamespace, tpName, compv1alpha1.TailoredProfileStateReady)
	if err != nil {
		t.Fatal(err)
	}

	suiteName := framework.GetObjNameFromTest(t)
	ssb := &compv1alpha1.ScanSettingBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      suiteName,
			Namespace: f.OperatorNamespace,
		},
		Profiles: []compv1alpha1.NamedObjectReference{
			{
				APIGroup: "compliance.openshift.io/v1alpha1",
				Kind:     "TailoredProfile",
				Name:     tpName,
			},
		},
		SettingsRef: &compv1alpha1.NamedObjectReference{
			APIGroup: "compliance.openshift.io/v1alpha1",
			Kind:     "ScanSetting",
			Name:     "default",
		},
	}
	err = f.Client.Create(context.TODO(), ssb, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Client.Delete(context.TODO(), ssb)

	// When using SSB with TailoredProfile, the scan has same name as the TP
	scanNameMaster := fmt.Sprintf("%s-master", tpName)
	scanNameWorker := fmt.Sprintf("%s-worker", tpName)
	if err = f.WaitForScanStatus(f.OperatorNamespace, scanNameMaster, compv1alpha1.PhaseDone); err != nil {
		t.Fatal(err)
	}
	if err = f.AssertScanIsCompliant(scanNameMaster, f.OperatorNamespace); err != nil {
		t.Fatal(err)
	}
	if err = f.WaitForScanStatus(f.OperatorNamespace, scanNameWorker, compv1alpha1.PhaseDone); err != nil {
		t.Fatal(err)
	}
	if err = f.AssertScanIsCompliant(scanNameWorker, f.OperatorNamespace); err != nil {
		t.Fatal(err)
	}
}

func TestSingleTailoredPlatformScanSucceeds(t *testing.T) {
	t.Parallel()
	f := framework.Global

	tpName := "test-tailoredplatformprofile"
	tp := &compv1alpha1.TailoredProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name:      tpName,
			Namespace: f.OperatorNamespace,
		},
		Spec: compv1alpha1.TailoredProfileSpec{
			Title:       "TestSingleTailoredPlatformScanSucceeds",
			Description: "TestSingleTailoredPlatformScanSucceeds",
			EnableRules: []compv1alpha1.RuleReferenceSpec{
				{
					Name:      "ocp4-cluster-version-operator-exists",
					Rationale: "Test for platform profile tailoring",
				},
			},
		},
	}
	err := f.Client.Create(context.TODO(), tp, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Client.Delete(context.TODO(), tp)

	err = f.WaitForTailoredProfileStatus(f.OperatorNamespace, tpName, compv1alpha1.TailoredProfileStateReady)
	if err != nil {
		t.Fatal(err)
	}

	suiteName := framework.GetObjNameFromTest(t)
	ssb := &compv1alpha1.ScanSettingBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      suiteName,
			Namespace: f.OperatorNamespace,
		},
		Profiles: []compv1alpha1.NamedObjectReference{
			{
				APIGroup: "compliance.openshift.io/v1alpha1",
				Kind:     "TailoredProfile",
				Name:     tpName,
			},
		},
		SettingsRef: &compv1alpha1.NamedObjectReference{
			APIGroup: "compliance.openshift.io/v1alpha1",
			Kind:     "ScanSetting",
			Name:     "default",
		},
	}
	err = f.Client.Create(context.TODO(), ssb, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Client.Delete(context.TODO(), ssb)

	// When using SSB with TailoredProfile, the scan has same name as the TP
	scanName := tpName
	err = f.WaitForScanStatus(f.OperatorNamespace, scanName, compv1alpha1.PhaseDone)
	if err != nil {
		t.Fatal(err)
	}
	err = f.AssertScanIsCompliant(scanName, f.OperatorNamespace)
	if err != nil {
		t.Fatal(err)
	}
}

func TestScanWithNodeSelectorFiltersCorrectly(t *testing.T) {
	t.Parallel()
	f := framework.Global
	selectWorkers := map[string]string{
		"node-role.kubernetes.io/worker": "",
	}
	testComplianceScan := &compv1alpha1.ComplianceScan{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-filtered-scan",
			Namespace: f.OperatorNamespace,
		},
		Spec: compv1alpha1.ComplianceScanSpec{
			Profile:      "xccdf_org.ssgproject.content_profile_moderate",
			Content:      framework.RhcosContentFile,
			ContentImage: contentImagePath,
			Rule:         "xccdf_org.ssgproject.content_rule_no_netrc_files",
			NodeSelector: selectWorkers,
			ComplianceScanSettings: compv1alpha1.ComplianceScanSettings{
				Debug: true,
			},
		},
	}
	// use Context's create helper to create the object and add a cleanup function for the new object
	err := f.Client.Create(context.TODO(), testComplianceScan, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Client.Delete(context.TODO(), testComplianceScan)
	err = f.WaitForScanStatus(f.OperatorNamespace, "test-filtered-scan", compv1alpha1.PhaseDone)
	if err != nil {
		t.Fatal(err)
	}

	nodes, err := f.GetNodesWithSelector(selectWorkers)
	if err != nil {
		t.Fatal(err)
	}
	configmaps, err := f.GetConfigMapsFromScan(testComplianceScan)
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes) != len(configmaps) {
		t.Fatalf("The number of reports doesn't match the number of selected nodes: %d reports / %d nodes", len(configmaps), len(nodes))
	}
	err = f.AssertScanIsCompliant("test-filtered-scan", f.OperatorNamespace)
	if err != nil {
		t.Fatal(err)
	}
}

func TestScanWithNodeSelectorNoMatches(t *testing.T) {
	t.Parallel()
	f := framework.Global
	scanName := framework.GetObjNameFromTest(t)
	selectNone := map[string]string{
		"node-role.kubernetes.io/no-matches": "",
	}
	testComplianceScan := &compv1alpha1.ComplianceScan{
		ObjectMeta: metav1.ObjectMeta{
			Name:      scanName,
			Namespace: f.OperatorNamespace,
		},
		Spec: compv1alpha1.ComplianceScanSpec{
			Profile:      "xccdf_org.ssgproject.content_profile_moderate",
			Content:      framework.RhcosContentFile,
			ContentImage: contentImagePath,
			Rule:         "xccdf_org.ssgproject.content_rule_no_netrc_files",
			NodeSelector: selectNone,
			ComplianceScanSettings: compv1alpha1.ComplianceScanSettings{
				Debug:             true,
				ShowNotApplicable: true,
			},
		},
	}
	// use Context's create helper to create the object and add a cleanup function for the new object
	err := f.Client.Create(context.TODO(), testComplianceScan, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Client.Delete(context.TODO(), testComplianceScan)
	err = f.WaitForScanStatus(f.OperatorNamespace, scanName, compv1alpha1.PhaseDone)
	if err != nil {
		t.Fatal(err)
	}
	err = f.AssertScanIsNotApplicable(scanName, f.OperatorNamespace)
	if err != nil {
		t.Fatal(err)
	}
}

func TestScanWithInvalidScanTypeFails(t *testing.T) {
	t.Parallel()
	f := framework.Global
	scanName := framework.GetObjNameFromTest(t)
	testScan := &compv1alpha1.ComplianceScan{
		ObjectMeta: metav1.ObjectMeta{
			Name:      scanName,
			Namespace: f.OperatorNamespace,
		},
		Spec: compv1alpha1.ComplianceScanSpec{
			Profile:      "xccdf_org.ssgproject.content_profile_moderate",
			Content:      "ssg-ocp4-non-existent.xml",
			ContentImage: contentImagePath,
			ScanType:     "BadScanType",
			ComplianceScanSettings: compv1alpha1.ComplianceScanSettings{
				Debug: true,
			},
		},
	}
	// use Context's create helper to create the object and add a cleanup function for the new object
	err := f.Client.Create(context.TODO(), testScan, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Client.Delete(context.TODO(), testScan)
	err = f.WaitForScanStatus(f.OperatorNamespace, scanName, compv1alpha1.PhaseDone)
	if err != nil {
		t.Fatal(err)
	}
	err = f.AssertScanIsInError(scanName, f.OperatorNamespace)
	if err != nil {
		t.Fatal(err)
	}
}

func TestScanWithInvalidContentFails(t *testing.T) {
	// This test logs a "Could not get Profile" error, but that is expected
	t.Parallel()
	f := framework.Global
	scanName := "test-scan-w-invalid-content"
	exampleComplianceScan := &compv1alpha1.ComplianceScan{
		ObjectMeta: metav1.ObjectMeta{
			Name:      scanName,
			Namespace: f.OperatorNamespace,
		},
		Spec: compv1alpha1.ComplianceScanSpec{
			Profile:      "xccdf_org.ssgproject.content_profile_moderate",
			Content:      "ssg-ocp4-non-existent.xml",
			ContentImage: contentImagePath,
			ComplianceScanSettings: compv1alpha1.ComplianceScanSettings{
				Debug: true,
			},
		},
	}
	// use Context's create helper to create the object and add a cleanup function for the new object
	err := f.Client.Create(context.TODO(), exampleComplianceScan, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Client.Delete(context.TODO(), exampleComplianceScan)
	err = f.WaitForScanStatus(f.OperatorNamespace, scanName, compv1alpha1.PhaseDone)
	if err != nil {
		t.Fatal(err)
	}
	err = f.AssertScanIsInError(scanName, f.OperatorNamespace)
	if err != nil {
		t.Fatal(err)
	}
}

func TestScanWithInvalidProfileFails(t *testing.T) {
	t.Parallel()
	f := framework.Global
	scanName := "test-scan-w-invalid-profile"
	exampleComplianceScan := &compv1alpha1.ComplianceScan{
		ObjectMeta: metav1.ObjectMeta{
			Name:      scanName,
			Namespace: f.OperatorNamespace,
		},
		Spec: compv1alpha1.ComplianceScanSpec{
			Profile:      "xccdf_org.ssgproject.content_profile_coreos-unexistent",
			Content:      framework.RhcosContentFile,
			ContentImage: contentImagePath,
			ComplianceScanSettings: compv1alpha1.ComplianceScanSettings{
				Debug: true,
			},
		},
	}
	// use Context's create helper to create the object and add a cleanup function for the new object
	err := f.Client.Create(context.TODO(), exampleComplianceScan, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Client.Delete(context.TODO(), exampleComplianceScan)
	err = f.WaitForScanStatus(f.OperatorNamespace, scanName, compv1alpha1.PhaseDone)
	if err != nil {
		t.Fatal(err)
	}
	err = f.AssertScanIsInError(scanName, f.OperatorNamespace)
	if err != nil {
		t.Fatal(err)
	}
}

func TestMalformedTailoredScanFails(t *testing.T) {
	t.Parallel()
	f := framework.Global
	cmName := "test-malformed-tailored-scan-fails-cm"
	tailoringCM := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      cmName,
			Namespace: f.OperatorNamespace,
		},
		// The tailored profile's namespace is wrong. It should be xccdf-1.2, but it was
		// declared as xccdf. So it should report an error
		Data: map[string]string{
			"tailoring.xml": `<?xml version="1.0" encoding="UTF-8"?>
<xccdf-1.2:Tailoring xmlns:xccdf="http://checklists.nist.gov/xccdf/1.2" id="xccdf_compliance.openshift.io_tailoring_test-tailoredprofile">
<xccdf-1.2:benchmark href="/content/ssg-rhcos4-ds.xml"></xccdf-1.2:benchmark>
<xccdf-1.2:version time="2020-04-28T07:04:13Z">1</xccdf-1.2:version>
<xccdf-1.2:Profile id="xccdf_compliance.openshift.io_profile_test-tailoredprofile">
<xccdf-1.2:title>Test Tailored Profile</xccdf-1.2:title>
<xccdf-1.2:description>Test Tailored Profile</xccdf-1.2:description>
<xccdf-1.2:select idref="xccdf_org.ssgproject.content_rule_no_netrc_files" selected="true"></xccdf-1.2:select>
</xccdf-1.2:Profile>
</xccdf-1.2:Tailoring>`,
		},
	}

	err := f.Client.Create(context.TODO(), tailoringCM, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Client.Delete(context.TODO(), tailoringCM)

	scanName := "test-malformed-tailored-scan-fails"
	exampleComplianceScan := &compv1alpha1.ComplianceScan{
		ObjectMeta: metav1.ObjectMeta{
			Name:      scanName,
			Namespace: f.OperatorNamespace,
		},
		Spec: compv1alpha1.ComplianceScanSpec{
			Profile:      "xccdf_compliance.openshift.io_profile_test-tailoredprofile",
			Content:      framework.RhcosContentFile,
			ContentImage: contentImagePath,
			Rule:         "xccdf_org.ssgproject.content_rule_no_netrc_files",
			ComplianceScanSettings: compv1alpha1.ComplianceScanSettings{
				Debug: true,
			},
			TailoringConfigMap: &compv1alpha1.TailoringConfigMapRef{
				Name: tailoringCM.Name,
			},
		},
	}
	// use Context's create helper to create the object and add a cleanup function for the new object
	err = f.Client.Create(context.TODO(), exampleComplianceScan, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Client.Delete(context.TODO(), exampleComplianceScan)
	err = f.WaitForScanStatus(f.OperatorNamespace, scanName, compv1alpha1.PhaseDone)
	if err != nil {
		t.Fatal(err)
	}
	err = f.AssertScanIsInError(scanName, f.OperatorNamespace)
	if err != nil {
		t.Fatal(err)
	}
}

func TestScanWithEmptyTailoringCMNameFails(t *testing.T) {
	t.Parallel()
	f := framework.Global
	scanName := "test-scan-w-empty-tailoring-cm"
	exampleComplianceScan := &compv1alpha1.ComplianceScan{
		ObjectMeta: metav1.ObjectMeta{
			Name:      scanName,
			Namespace: f.OperatorNamespace,
		},
		Spec: compv1alpha1.ComplianceScanSpec{
			Profile:      "xccdf_org.ssgproject.content_profile_moderate",
			Content:      framework.RhcosContentFile,
			ContentImage: contentImagePath,
			Rule:         "xccdf_org.ssgproject.content_rule_no_netrc_files",
			TailoringConfigMap: &compv1alpha1.TailoringConfigMapRef{
				Name: "",
			},
		},
	}
	// use Context's create helper to create the object and add a cleanup function for the new object
	err := f.Client.Create(context.TODO(), exampleComplianceScan, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Client.Delete(context.TODO(), exampleComplianceScan)
	err = f.WaitForScanStatus(f.OperatorNamespace, scanName, compv1alpha1.PhaseDone)
	if err != nil {
		t.Fatal(err)
	}

	err = f.AssertScanIsInError(scanName, f.OperatorNamespace)
	if err != nil {
		t.Fatal(err)
	}
}

func TestScanWithMissingTailoringCMFailsAndRecovers(t *testing.T) {
	t.Parallel()
	f := framework.Global
	scanName := "test-scan-w-missing-tailoring-cm"

	tpName := "test-tailoredprofile-missing-cm"
	tp := &compv1alpha1.TailoredProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name:      tpName,
			Namespace: f.OperatorNamespace,
		},
		Spec: compv1alpha1.TailoredProfileSpec{
			Title:       "TestScanWithMissingTailoringCMFailsAndRecovers",
			Description: "TestScanWithMissingTailoringCMFailsAndRecovers",
			EnableRules: []compv1alpha1.RuleReferenceSpec{
				{
					Name:      "rhcos4-no-netrc-files",
					Rationale: "Test for platform profile tailoring missing CM fails and recovers",
				},
			},
		},
	}
	createTPErr := f.Client.Create(context.TODO(), tp, nil)
	if createTPErr != nil {
		t.Fatal(createTPErr)
	}
	defer f.Client.Delete(context.TODO(), tp)

	exampleComplianceScan := &compv1alpha1.ComplianceScan{
		ObjectMeta: metav1.ObjectMeta{
			Name:      scanName,
			Namespace: f.OperatorNamespace,
		},
		Spec: compv1alpha1.ComplianceScanSpec{
			Profile:      "xccdf_compliance.openshift.io_profile_test-tailoredprofile-missing-cm",
			Content:      framework.RhcosContentFile,
			ContentImage: contentImagePath,
			Rule:         "xccdf_org.ssgproject.content_rule_no_netrc_files",
			ComplianceScanSettings: compv1alpha1.ComplianceScanSettings{
				Debug: true,
			},
			TailoringConfigMap: &compv1alpha1.TailoringConfigMapRef{
				Name: "missing-tailoring-file",
			},
		},
	}
	// use Context's create helper to create the object and add a cleanup function for the new object
	err := f.Client.Create(context.TODO(), exampleComplianceScan, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Client.Delete(context.TODO(), exampleComplianceScan)

	err = f.WaitForScanStatus(f.OperatorNamespace, scanName, compv1alpha1.PhaseLaunching)
	if err != nil {
		t.Fatal(err)
	}

	var resultErr error
	// The status might still be NOT-AVAILABLE... we can wait a bit
	// for the reconciliation to update it.
	_ = wait.PollImmediate(framework.RetryInterval, framework.Timeout, func() (bool, error) {
		if resultErr = f.AssertScanIsInError(scanName, f.OperatorNamespace); resultErr != nil {
			return false, nil
		}
		return true, nil
	})
	if resultErr != nil {
		t.Fatalf("failed waiting for the config map: %s", resultErr)
	}

	tailoringCM := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "missing-tailoring-file",
			Namespace: f.OperatorNamespace,
		},
		Data: map[string]string{
			"tailoring.xml": `<?xml version="1.0" encoding="UTF-8"?>
<xccdf-1.2:Tailoring xmlns:xccdf-1.2="http://checklists.nist.gov/xccdf/1.2" id="xccdf_compliance.openshift.io_tailoring_test-tailoredprofile-missing-cm">
<xccdf-1.2:benchmark href="/content/ssg-rhcos4-ds.xml"></xccdf-1.2:benchmark>
<xccdf-1.2:version time="2020-04-28T07:04:13Z">1</xccdf-1.2:version>
<xccdf-1.2:Profile id="xccdf_compliance.openshift.io_profile_test-tailoredprofile-missing-cm">
<xccdf-1.2:title>Test Tailored Profile</xccdf-1.2:title>
<xccdf-1.2:description>Test Tailored Profile</xccdf-1.2:description>
<xccdf-1.2:select idref="xccdf_org.ssgproject.content_rule_no_netrc_files" selected="true"></xccdf-1.2:select>
</xccdf-1.2:Profile>
</xccdf-1.2:Tailoring>`,
		},
	}
	err = f.Client.Create(context.TODO(), tailoringCM, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Client.Delete(context.TODO(), tailoringCM)

	err = f.WaitForScanStatus(f.OperatorNamespace, scanName, compv1alpha1.PhaseDone)
	if err != nil {
		t.Fatal(err)
	}
	err = f.AssertScanIsCompliant(scanName, f.OperatorNamespace)
	if err != nil {
		t.Fatal(err)
	}
}

func TestMissingPodInRunningState(t *testing.T) {
	t.Parallel()
	f := framework.Global
	scanName := "test-missing-pod-scan"
	exampleComplianceScan := &compv1alpha1.ComplianceScan{
		ObjectMeta: metav1.ObjectMeta{
			Name:      scanName,
			Namespace: f.OperatorNamespace,
		},
		Spec: compv1alpha1.ComplianceScanSpec{
			Profile:      "xccdf_org.ssgproject.content_profile_moderate",
			Content:      framework.RhcosContentFile,
			ContentImage: contentImagePath,
			Rule:         "xccdf_org.ssgproject.content_rule_no_netrc_files",
			ComplianceScanSettings: compv1alpha1.ComplianceScanSettings{
				Debug: true,
			},
		},
	}
	// use Context's create helper to create the object and add a cleanup function for the new object
	err := f.Client.Create(context.TODO(), exampleComplianceScan, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Client.Delete(context.TODO(), exampleComplianceScan)

	err = f.WaitForScanStatus(f.OperatorNamespace, scanName, compv1alpha1.PhaseRunning)
	if err != nil {
		t.Fatal(err)
	}
	pods, err := f.GetPodsForScan(scanName)
	if err != nil {
		t.Fatal(err)
	}
	if len(pods) < 1 {
		t.Fatal("No pods gotten from query for the scan")
	}
	podToDelete := pods[rand.Intn(len(pods))]
	// Delete pod ASAP
	zeroSeconds := int64(0)
	do := client.DeleteOptions{GracePeriodSeconds: &zeroSeconds}
	err = f.Client.Delete(context.TODO(), &podToDelete, &do)
	if err != nil {
		t.Fatal(err)
	}
	err = f.WaitForScanStatus(f.OperatorNamespace, scanName, compv1alpha1.PhaseDone)
	if err != nil {
		t.Fatal(err)
	}

	err = f.AssertScanIsCompliant(scanName, f.OperatorNamespace)
	if err != nil {
		t.Fatal(err)
	}
}

func TestApplyGenericRemediation(t *testing.T) {
	t.Parallel()
	f := framework.Global
	remName := "test-apply-generic-remediation"
	unstruct := &unstructured.Unstructured{}
	unstruct.SetUnstructuredContent(map[string]interface{}{
		"kind":       "ConfigMap",
		"apiVersion": "v1",
		"metadata": map[string]interface{}{
			"name":      "generic-rem-cm",
			"namespace": f.OperatorNamespace,
		},
		"data": map[string]interface{}{
			"key": "value",
		},
	})

	genericRem := &compv1alpha1.ComplianceRemediation{
		ObjectMeta: metav1.ObjectMeta{
			Name:      remName,
			Namespace: f.OperatorNamespace,
		},
		Spec: compv1alpha1.ComplianceRemediationSpec{
			ComplianceRemediationSpecMeta: compv1alpha1.ComplianceRemediationSpecMeta{
				Apply: true,
			},
			Current: compv1alpha1.ComplianceRemediationPayload{
				Object: unstruct,
			},
		},
	}
	// use Context's create helper to create the object and add a cleanup function for the new object
	err := f.Client.Create(context.TODO(), genericRem, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Client.Delete(context.TODO(), genericRem)
	err = f.WaitForRemediationState(remName, f.OperatorNamespace, compv1alpha1.RemediationApplied)
	if err != nil {
		t.Fatal(err)
	}

	cm := &corev1.ConfigMap{}
	cmName := "generic-rem-cm"
	err = f.WaitForObjectToExist(cmName, f.OperatorNamespace, cm)
	if err != nil {
		t.Fatal(err)
	}
	val, ok := cm.Data["key"]
	if !ok || val != "value" {
		t.Fatalf("ComplianceRemediation '%s' generated a malformed ConfigMap", remName)
	}

	// verify object is marked as created by the operator
	if !compv1alpha1.RemediationWasCreatedByOperator(cm) {
		t.Fatalf("ComplianceRemediation '%s' is missing controller annotation '%s'",
			remName, compv1alpha1.RemediationCreatedByOperatorAnnotation)
	}
}

func TestPatchGenericRemediation(t *testing.T) {
	t.Parallel()
	f := framework.Global
	remName := framework.GetObjNameFromTest(t)
	cmName := remName
	cmKey := types.NamespacedName{
		Name:      cmName,
		Namespace: f.OperatorNamespace,
	}
	existingCM := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      cmKey.Name,
			Namespace: cmKey.Namespace,
		},
		Data: map[string]string{
			"existingKey": "existingData",
		},
	}

	if err := f.Client.Create(context.TODO(), existingCM, nil); err != nil {
		t.Fatal(err)
	}
	defer f.Client.Delete(context.TODO(), existingCM)

	cm := &corev1.ConfigMap{}
	err := f.WaitForObjectToExist(cmKey.Name, f.OperatorNamespace, cm)
	if err != nil {
		t.Fatal(err)
	}

	unstruct := &unstructured.Unstructured{}
	unstruct.SetUnstructuredContent(map[string]interface{}{
		"kind":       "ConfigMap",
		"apiVersion": "v1",
		"metadata": map[string]interface{}{
			"name":      cmKey.Name,
			"namespace": cmKey.Namespace,
		},
		"data": map[string]interface{}{
			"newKey": "newData",
		},
	})

	genericRem := &compv1alpha1.ComplianceRemediation{
		ObjectMeta: metav1.ObjectMeta{
			Name:      remName,
			Namespace: f.OperatorNamespace,
		},
		Spec: compv1alpha1.ComplianceRemediationSpec{
			ComplianceRemediationSpecMeta: compv1alpha1.ComplianceRemediationSpecMeta{
				Apply: true,
			},
			Current: compv1alpha1.ComplianceRemediationPayload{
				Object: unstruct,
			},
		},
	}
	// use Context's create helper to create the object and add a cleanup function for the new object
	err = f.Client.Create(context.TODO(), genericRem, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Client.Delete(context.TODO(), genericRem)

	err = f.WaitForRemediationState(remName, f.OperatorNamespace, compv1alpha1.RemediationApplied)
	if err != nil {
		t.Fatal(err)
	}

	err = f.WaitForObjectToUpdate(cmKey.Name, f.OperatorNamespace, cm)
	if err != nil {
		t.Fatal(err)
	}

	// Old data should still be there
	val, ok := cm.Data["existingKey"]
	if !ok || val != "existingData" {
		t.Fatalf("ComplianceRemediation '%s' generated a malformed ConfigMap", remName)
	}

	// new data should be there too
	val, ok = cm.Data["newKey"]
	if !ok || val != "newData" {
		t.Fatalf("ComplianceRemediation '%s' generated a malformed ConfigMap", remName)
	}
}

func TestGenericRemediationFailsWithUnknownType(t *testing.T) {
	t.Parallel()
	f := framework.Global
	remName := "test-generic-remediation-fails-unknown"
	genericRem := &compv1alpha1.ComplianceRemediation{
		ObjectMeta: metav1.ObjectMeta{
			Name:      remName,
			Namespace: f.OperatorNamespace,
		},
		Spec: compv1alpha1.ComplianceRemediationSpec{
			ComplianceRemediationSpecMeta: compv1alpha1.ComplianceRemediationSpecMeta{
				Apply: true,
			},
			Current: compv1alpha1.ComplianceRemediationPayload{
				Object: &unstructured.Unstructured{
					Object: map[string]interface{}{
						"kind":       "OopsyDoodle",
						"apiVersion": "foo.bar/v1",
						"metadata": map[string]interface{}{
							"name":      "unknown-remediation",
							"namespace": f.OperatorNamespace,
						},
						"data": map[string]interface{}{
							"key": "value",
						},
					},
				},
			},
		},
	}
	// use Context's create helper to create the object and add a cleanup function for the new object
	err := f.Client.Create(context.TODO(), genericRem, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Client.Delete(context.TODO(), genericRem)
	err = f.WaitForRemediationState(remName, f.OperatorNamespace, compv1alpha1.RemediationError)
	if err != nil {
		t.Fatal(err)
	}
}

func TestSuiteWithInvalidScheduleShowsError(t *testing.T) {
	t.Parallel()
	f := framework.Global
	suiteName := "test-suite-with-invalid-schedule"
	testSuite := &compv1alpha1.ComplianceSuite{
		ObjectMeta: metav1.ObjectMeta{
			Name:      suiteName,
			Namespace: f.OperatorNamespace,
		},
		Spec: compv1alpha1.ComplianceSuiteSpec{
			ComplianceSuiteSettings: compv1alpha1.ComplianceSuiteSettings{
				AutoApplyRemediations: false,
				Schedule:              "This is WRONG",
			},
			Scans: []compv1alpha1.ComplianceScanSpecWrapper{
				{
					Name: fmt.Sprintf("%s-workers-scan", suiteName),
					ComplianceScanSpec: compv1alpha1.ComplianceScanSpec{
						ContentImage: contentImagePath,
						Profile:      "xccdf_org.ssgproject.content_profile_moderate",
						Content:      framework.RhcosContentFile,
						ComplianceScanSettings: compv1alpha1.ComplianceScanSettings{
							Debug: true,
						},
						NodeSelector: map[string]string{
							"node-role.kubernetes.io/worker": "",
						},
					},
				},
			},
		},
	}
	// use Context's create helper to create the object and add a cleanup function for the new object
	err := f.Client.Create(context.TODO(), testSuite, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Client.Delete(context.TODO(), testSuite)

	err = f.WaitForSuiteScansStatus(f.OperatorNamespace, suiteName, compv1alpha1.PhaseDone, compv1alpha1.ResultError)
	if err != nil {
		t.Fatal(err)
	}
	err = f.SuiteErrorMessageMatchesRegex(f.OperatorNamespace, suiteName, "Suite was invalid: .*")
	if err != nil {
		t.Fatal(err)
	}
}

func TestScheduledSuite(t *testing.T) {
	t.Parallel()
	f := framework.Global
	suiteName := "test-scheduled-suite"

	workerScanName := fmt.Sprintf("%s-workers-scan", suiteName)
	selectWorkers := map[string]string{
		"node-role.kubernetes.io/worker": "",
	}

	testSuite := &compv1alpha1.ComplianceSuite{
		ObjectMeta: metav1.ObjectMeta{
			Name:      suiteName,
			Namespace: f.OperatorNamespace,
		},
		Spec: compv1alpha1.ComplianceSuiteSpec{
			ComplianceSuiteSettings: compv1alpha1.ComplianceSuiteSettings{
				AutoApplyRemediations: false,
				Schedule:              "*/2 * * * *",
			},
			Scans: []compv1alpha1.ComplianceScanSpecWrapper{
				{
					Name: workerScanName,
					ComplianceScanSpec: compv1alpha1.ComplianceScanSpec{
						ContentImage: contentImagePath,
						Profile:      "xccdf_org.ssgproject.content_profile_moderate",
						Content:      framework.RhcosContentFile,
						Rule:         "xccdf_org.ssgproject.content_rule_no_netrc_files",
						NodeSelector: selectWorkers,
						ComplianceScanSettings: compv1alpha1.ComplianceScanSettings{
							RawResultStorage: compv1alpha1.RawResultStorageSettings{
								Rotation: 1,
							},
							Debug: true,
						},
					},
				},
			},
		},
	}

	err := f.Client.Create(context.TODO(), testSuite, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Client.Delete(context.TODO(), testSuite)

	// Ensure that all the scans in the suite have finished and are marked as Done
	err = f.WaitForSuiteScansStatus(f.OperatorNamespace, suiteName, compv1alpha1.PhaseDone, compv1alpha1.ResultCompliant)
	if err != nil {
		t.Fatal(err)
	}

	// Wait for one re-scan
	err = f.WaitForReScanStatus(f.OperatorNamespace, workerScanName, compv1alpha1.PhaseDone)
	if err != nil {
		t.Fatal(err)
	}

	// Wait for a second one to assert this is running scheduled as expected
	err = f.WaitForReScanStatus(f.OperatorNamespace, workerScanName, compv1alpha1.PhaseDone)
	if err != nil {
		t.Fatal(err)
	}

	// clean up
	// Get new reference of suite
	foundSuite := &compv1alpha1.ComplianceSuite{}
	key := types.NamespacedName{Name: testSuite.Name, Namespace: testSuite.Namespace}
	if err = f.Client.Get(context.TODO(), key, foundSuite); err != nil {
		t.Fatal(err)
	}

	// Remove cronjob so it doesn't keep running while other tests are running
	testSuiteCopy := foundSuite.DeepCopy()
	updatedSchedule := ""
	testSuiteCopy.Spec.Schedule = updatedSchedule
	if err = f.Client.Update(context.TODO(), testSuiteCopy); err != nil {
		t.Fatal(err)
	}

	rawResultClaimName, err := f.GetRawResultClaimNameFromScan(f.OperatorNamespace, workerScanName)
	if err != nil {
		t.Fatal(err)
	}

	rotationCheckerPod := framework.GetRotationCheckerWorkload(f.OperatorNamespace, rawResultClaimName)
	if err = f.Client.Create(context.TODO(), rotationCheckerPod, nil); err != nil {
		t.Fatal(err)
	}
	defer f.Client.Delete(context.TODO(), rotationCheckerPod)

	err = f.AssertResultStorageHasExpectedItemsAfterRotation(1, f.OperatorNamespace, rotationCheckerPod.Name)
	if err != nil {
		t.Fatal(err)
	}
}

func TestScheduledSuitePriorityClass(t *testing.T) {
	t.Parallel()
	f := framework.Global
	suiteName := "test-scheduled-suite-priority-class"
	workerScanName := fmt.Sprintf("%s-workers-scan", suiteName)
	selectWorkers := map[string]string{
		"node-role.kubernetes.io/worker": "",
	}

	priorityClass := &schedulingv1.PriorityClass{
		ObjectMeta: metav1.ObjectMeta{
			Name: "e2e-compliance-suite-high-priority",
		},
		Value: 100,
	}

	// Ensure that the priority class is created
	err := f.Client.Create(context.TODO(), priorityClass, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Client.Delete(context.TODO(), priorityClass)

	testSuite := &compv1alpha1.ComplianceSuite{
		ObjectMeta: metav1.ObjectMeta{
			Name:      suiteName,
			Namespace: f.OperatorNamespace,
		},
		Spec: compv1alpha1.ComplianceSuiteSpec{
			ComplianceSuiteSettings: compv1alpha1.ComplianceSuiteSettings{
				AutoApplyRemediations: false,
			},
			Scans: []compv1alpha1.ComplianceScanSpecWrapper{
				{
					Name: workerScanName,
					ComplianceScanSpec: compv1alpha1.ComplianceScanSpec{
						ContentImage: contentImagePath,
						Profile:      "xccdf_org.ssgproject.content_profile_moderate",
						Content:      framework.RhcosContentFile,
						Rule:         "xccdf_org.ssgproject.content_rule_no_netrc_files",
						NodeSelector: selectWorkers,
						ComplianceScanSettings: compv1alpha1.ComplianceScanSettings{
							PriorityClass: "e2e-compliance-suite-high-priority",
							RawResultStorage: compv1alpha1.RawResultStorageSettings{
								Rotation: 1,
							},
							Debug: true,
						},
					},
				},
			},
		},
	}

	err = f.Client.Create(context.TODO(), testSuite, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Client.Delete(context.TODO(), testSuite)

	podList := &corev1.PodList{}
	err = f.Client.List(context.TODO(), podList, client.InNamespace(f.OperatorNamespace), client.MatchingLabels(map[string]string{
		"workload": "scanner",
	}))
	if err != nil {
		t.Fatal(err)
	}
	// check if the scanning pod has properly been created and has priority class set
	for _, pod := range podList.Items {
		if strings.Contains(pod.Name, workerScanName) {
			if err := framework.WaitForPod(framework.CheckPodPriorityClass(f.KubeClient, pod.Name, f.OperatorNamespace, "e2e-compliance-suite-high-priority")); err != nil {
				t.Fatal(err)
			}
		}
	}

	// Ensure that all the scans in the suite have finished and are marked as Done
	err = f.WaitForSuiteScansStatus(f.OperatorNamespace, suiteName, compv1alpha1.PhaseDone, compv1alpha1.ResultCompliant)
	if err != nil {
		t.Fatal(err)
	}
}

func TestScheduledSuiteNoStorage(t *testing.T) {
	t.Parallel()
	f := framework.Global
	suiteName := "test-scheduled-suite-no-storage"
	workerScanName := fmt.Sprintf("%s-workers-scan", suiteName)
	selectWorkers := map[string]string{
		"node-role.kubernetes.io/worker": "",
	}

	testSuite := &compv1alpha1.ComplianceSuite{
		ObjectMeta: metav1.ObjectMeta{
			Name:      suiteName,
			Namespace: f.OperatorNamespace,
		},
		Spec: compv1alpha1.ComplianceSuiteSpec{
			ComplianceSuiteSettings: compv1alpha1.ComplianceSuiteSettings{
				AutoApplyRemediations: false,
			},
			Scans: []compv1alpha1.ComplianceScanSpecWrapper{
				{
					Name: workerScanName,
					ComplianceScanSpec: compv1alpha1.ComplianceScanSpec{
						ContentImage: contentImagePath,
						Profile:      "xccdf_org.ssgproject.content_profile_moderate",
						Content:      framework.RhcosContentFile,
						Rule:         "xccdf_org.ssgproject.content_rule_no_netrc_files",
						NodeSelector: selectWorkers,
						ComplianceScanSettings: compv1alpha1.ComplianceScanSettings{
							RawResultStorage: compv1alpha1.RawResultStorageSettings{
								Disabled: true,
							},
							Debug: true,
						},
					},
				},
			},
		},
	}

	err := f.Client.Create(context.TODO(), testSuite, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Client.Delete(context.TODO(), testSuite)

	pvcList := &corev1.PersistentVolumeClaimList{}
	err = f.Client.List(context.TODO(), pvcList, client.InNamespace(f.OperatorNamespace), client.MatchingLabels(map[string]string{
		compv1alpha1.ComplianceScanLabel: workerScanName,
	}))
	if err != nil {
		t.Fatal(err)
	}
	if len(pvcList.Items) > 0 {
		for _, pvc := range pvcList.Items {
			t.Fatalf("Found unexpected PVC %s", pvc.Name)
		}
		t.Fatal("Expected not to find PVC associated with the scan.")
	}

	// Ensure that all the scans in the suite have finished and are marked as Done
	err = f.WaitForSuiteScansStatus(f.OperatorNamespace, suiteName, compv1alpha1.PhaseDone, compv1alpha1.ResultCompliant)
	if err != nil {
		t.Fatal(err)
	}
}

func TestScheduledSuiteInvalidPriorityClass(t *testing.T) {
	t.Parallel()
	f := framework.Global
	suiteName := "test-scheduled-suite-invalid-priority-class"

	workerScanName := fmt.Sprintf("%s-workers-scan", suiteName)
	selectWorkers := map[string]string{
		"node-role.kubernetes.io/worker": "",
	}

	testSuite := &compv1alpha1.ComplianceSuite{
		ObjectMeta: metav1.ObjectMeta{
			Name:      suiteName,
			Namespace: f.OperatorNamespace,
		},
		Spec: compv1alpha1.ComplianceSuiteSpec{
			ComplianceSuiteSettings: compv1alpha1.ComplianceSuiteSettings{
				AutoApplyRemediations: false,
			},
			Scans: []compv1alpha1.ComplianceScanSpecWrapper{
				{
					Name: workerScanName,
					ComplianceScanSpec: compv1alpha1.ComplianceScanSpec{
						ContentImage: contentImagePath,
						Profile:      "xccdf_org.ssgproject.content_profile_moderate",
						Content:      framework.RhcosContentFile,
						Rule:         "xccdf_org.ssgproject.content_rule_no_netrc_files",
						NodeSelector: selectWorkers,
						ComplianceScanSettings: compv1alpha1.ComplianceScanSettings{
							PriorityClass: "priority-invalid",
							RawResultStorage: compv1alpha1.RawResultStorageSettings{
								Rotation: 1,
							},
							Debug: true,
						},
					},
				},
			},
		},
	}

	err := f.Client.Create(context.TODO(), testSuite, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Client.Delete(context.TODO(), testSuite)

	podList := &corev1.PodList{}
	err = f.Client.List(context.TODO(), podList, client.InNamespace(f.OperatorNamespace), client.MatchingLabels(map[string]string{
		"workload": "scanner",
	}))
	if err != nil {
		t.Fatal(err)
	}
	// check if the scanning pod has properly been created and has priority class set
	for _, pod := range podList.Items {
		if strings.Contains(pod.Name, workerScanName) {
			if err := framework.WaitForPod(framework.CheckPodPriorityClass(f.KubeClient, pod.Name, f.OperatorNamespace, "")); err != nil {
				t.Fatal(err)
			}
		}
	}
	// Ensure that all the scans in the suite have finished and are marked as Done
	err = f.WaitForSuiteScansStatus(f.OperatorNamespace, suiteName, compv1alpha1.PhaseDone, compv1alpha1.ResultCompliant)
	if err != nil {
		t.Fatal(err)
	}
}

func TestScheduledSuiteUpdate(t *testing.T) {
	t.Parallel()
	f := framework.Global
	suiteName := framework.GetObjNameFromTest(t)
	workerScanName := fmt.Sprintf("%s-workers-scan", suiteName)
	selectWorkers := map[string]string{
		"node-role.kubernetes.io/worker": "",
	}

	initialSchedule := "0 * * * *"
	testSuite := &compv1alpha1.ComplianceSuite{
		ObjectMeta: metav1.ObjectMeta{
			Name:      suiteName,
			Namespace: f.OperatorNamespace,
		},
		Spec: compv1alpha1.ComplianceSuiteSpec{
			ComplianceSuiteSettings: compv1alpha1.ComplianceSuiteSettings{
				AutoApplyRemediations: false,
				Schedule:              initialSchedule,
			},
			Scans: []compv1alpha1.ComplianceScanSpecWrapper{
				{
					Name: workerScanName,
					ComplianceScanSpec: compv1alpha1.ComplianceScanSpec{
						ContentImage: contentImagePath,
						Profile:      "xccdf_org.ssgproject.content_profile_moderate",
						Content:      framework.RhcosContentFile,
						Rule:         "xccdf_org.ssgproject.content_rule_no_netrc_files",
						NodeSelector: selectWorkers,
						ComplianceScanSettings: compv1alpha1.ComplianceScanSettings{
							Debug: true,
						},
					},
				},
			},
		},
	}

	err := f.Client.Create(context.TODO(), testSuite, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Client.Delete(context.TODO(), testSuite)

	// Ensure that all the scans in the suite have finished and are marked as Done
	err = f.WaitForSuiteScansStatus(f.OperatorNamespace, suiteName, compv1alpha1.PhaseDone, compv1alpha1.ResultCompliant)
	if err != nil {
		t.Fatal(err)
	}

	err = f.WaitForCronJobWithSchedule(f.OperatorNamespace, suiteName, initialSchedule)
	if err != nil {
		t.Fatal(err)
	}

	// Get new reference of suite
	foundSuite := &compv1alpha1.ComplianceSuite{}
	key := types.NamespacedName{Name: testSuite.Name, Namespace: testSuite.Namespace}
	if err = f.Client.Get(context.TODO(), key, foundSuite); err != nil {
		t.Fatal(err)
	}

	// Update schedule
	testSuiteCopy := foundSuite.DeepCopy()
	updatedSchedule := "*/2 * * * *"
	testSuiteCopy.Spec.Schedule = updatedSchedule
	if err = f.Client.Update(context.TODO(), testSuiteCopy); err != nil {
		t.Fatal(err)
	}

	if err = f.WaitForCronJobWithSchedule(f.OperatorNamespace, suiteName, updatedSchedule); err != nil {
		t.Fatal(err)
	}

	// Clean up
	// Get new reference of suite
	foundSuite = &compv1alpha1.ComplianceSuite{}
	if err = f.Client.Get(context.TODO(), key, foundSuite); err != nil {
		t.Fatal(err)
	}

	// Remove cronjob so it doesn't keep running while other tests are running
	testSuiteCopy = foundSuite.DeepCopy()
	updatedSchedule = ""
	testSuiteCopy.Spec.Schedule = updatedSchedule
	if err = f.Client.Update(context.TODO(), testSuiteCopy); err != nil {
		t.Fatal(err)
	}
}

func TestSuiteWithContentThatDoesNotMatch(t *testing.T) {
	t.Parallel()
	f := framework.Global

	pbName := framework.GetObjNameFromTest(t)
	baselineImage := fmt.Sprintf("%s:%s", brokenContentImagePath, "broken_os_detection")
	origPb, err := f.CreateProfileBundle(pbName, baselineImage, framework.RhcosContentFile)
	if err != nil {
		t.Fatalf("failed to create ProfileBundle: %s", err)
	}
	// This should get cleaned up at the end of the test
	defer f.Client.Delete(context.TODO(), origPb)
	if err = f.WaitForProfileBundleStatus(pbName, compv1alpha1.DataStreamValid); err != nil {
		t.Fatalf("failed waiting for the ProfileBundle to become available: %s", err)
	}

	suiteName := "test-suite-with-non-matching-content"
	testSuite := &compv1alpha1.ComplianceSuite{
		ObjectMeta: metav1.ObjectMeta{
			Name:      suiteName,
			Namespace: f.OperatorNamespace,
		},
		Spec: compv1alpha1.ComplianceSuiteSpec{
			ComplianceSuiteSettings: compv1alpha1.ComplianceSuiteSettings{
				AutoApplyRemediations: false,
			},
			Scans: []compv1alpha1.ComplianceScanSpecWrapper{
				{
					Name: fmt.Sprintf("%s-workers-scan", suiteName),
					ComplianceScanSpec: compv1alpha1.ComplianceScanSpec{
						ContentImage: baselineImage,
						Profile:      "xccdf_org.ssgproject.content_profile_moderate",
						Content:      "ssg-rhcos4-ds.xml",
						ComplianceScanSettings: compv1alpha1.ComplianceScanSettings{
							Debug:             true,
							ShowNotApplicable: true,
						},
						NodeSelector: map[string]string{
							"node-role.kubernetes.io/worker": "",
						},
					},
				},
			},
		},
	}
	// use Context's create helper to create the object and add a cleanup function for the new object
	err = f.Client.Create(context.TODO(), testSuite, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Client.Delete(context.TODO(), testSuite)

	err = f.WaitForSuiteScansStatus(f.OperatorNamespace, suiteName, compv1alpha1.PhaseDone, compv1alpha1.ResultNotApplicable)
	if err != nil {
		t.Fatal(err)
	}
	err = f.SuiteErrorMessageMatchesRegex(f.OperatorNamespace, suiteName, "The suite result is not applicable.*")
	if err != nil {
		t.Fatal(err)
	}
}

func TestScanSettingBinding(t *testing.T) {
	t.Parallel()
	f := framework.Global
	objName := framework.GetObjNameFromTest(t)
	const defaultCpuLimit = "100m"
	const testMemoryLimit = "432Mi"

	rhcosPb := &compv1alpha1.ProfileBundle{}
	err := f.Client.Get(context.TODO(), types.NamespacedName{Name: "rhcos4", Namespace: f.OperatorNamespace}, rhcosPb)
	if err != nil {
		t.Fatalf("unable to get rhcos4 profile bundle required for test: %s", err)
	}

	rhcos4e8profile := &compv1alpha1.Profile{}
	key := types.NamespacedName{Namespace: f.OperatorNamespace, Name: rhcosPb.Name + "-e8"}
	if err := f.Client.Get(context.TODO(), key, rhcos4e8profile); err != nil {
		t.Fatal(err)
	}

	scanSettingName := objName + "-setting"
	scanSetting := compv1alpha1.ScanSetting{
		ObjectMeta: metav1.ObjectMeta{
			Name:      scanSettingName,
			Namespace: f.OperatorNamespace,
		},
		ComplianceSuiteSettings: compv1alpha1.ComplianceSuiteSettings{
			AutoApplyRemediations: false,
		},
		ComplianceScanSettings: compv1alpha1.ComplianceScanSettings{
			Debug: true,
			ScanLimits: map[corev1.ResourceName]resource.Quantity{
				corev1.ResourceMemory: resource.MustParse(testMemoryLimit),
			},
		},
		Roles: []string{"master", "worker"},
	}

	if err := f.Client.Create(context.TODO(), &scanSetting, nil); err != nil {
		t.Fatal(err)
	}
	defer f.Client.Delete(context.TODO(), &scanSetting)

	scanSettingBindingName := "generated-suite"
	scanSettingBinding := compv1alpha1.ScanSettingBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      scanSettingBindingName,
			Namespace: f.OperatorNamespace,
		},
		Profiles: []compv1alpha1.NamedObjectReference{
			// TODO: test also OCP profile when it works completely
			{
				Name:     rhcos4e8profile.Name,
				Kind:     "Profile",
				APIGroup: "compliance.openshift.io/v1alpha1",
			},
		},
		SettingsRef: &compv1alpha1.NamedObjectReference{
			Name:     scanSetting.Name,
			Kind:     "ScanSetting",
			APIGroup: "compliance.openshift.io/v1alpha1",
		},
	}

	if err := f.Client.Create(context.TODO(), &scanSettingBinding, nil); err != nil {
		t.Fatal(err)
	}
	defer f.Client.Delete(context.TODO(), &scanSettingBinding)

	// Wait until the suite finishes, thus verifying the suite exists
	err = f.WaitForSuiteScansStatus(f.OperatorNamespace, scanSettingBindingName, compv1alpha1.PhaseDone, compv1alpha1.ResultNonCompliant)
	if err != nil {
		t.Fatal(err)
	}

	masterScanKey := types.NamespacedName{Namespace: f.OperatorNamespace, Name: rhcos4e8profile.Name + "-master"}
	masterScan := &compv1alpha1.ComplianceScan{}
	if err := f.Client.Get(context.TODO(), masterScanKey, masterScan); err != nil {
		t.Fatal(err)
	}

	if masterScan.Spec.Debug != true {
		log.Println("Expected that the settings set debug to true in master scan")
	}

	workerScanKey := types.NamespacedName{Namespace: f.OperatorNamespace, Name: rhcos4e8profile.Name + "-worker"}
	workerScan := &compv1alpha1.ComplianceScan{}
	if err := f.Client.Get(context.TODO(), workerScanKey, workerScan); err != nil {
		t.Fatal(err)
	}

	if workerScan.Spec.Debug != true {
		log.Println("Expected that the settings set debug to true in workers scan")
	}

	podList := &corev1.PodList{}
	if err := f.Client.List(context.TODO(), podList, client.InNamespace(f.OperatorNamespace), client.MatchingLabels(map[string]string{
		"workload": "scanner",
	})); err != nil {
		t.Fatal(err)
	}
	// check if the scanning pod has properly been created and has priority class set
	for _, pod := range podList.Items {
		if strings.Contains(pod.Name, workerScan.Name) {
			if err := framework.WaitForPod(framework.CheckPodLimit(f.KubeClient, pod.Name, f.OperatorNamespace, defaultCpuLimit, testMemoryLimit)); err != nil {
				t.Fatal(err)
			}
		}
	}

}

func TestScanSettingBindingTailoringManyEnablingRulePass(t *testing.T) {

	t.Parallel()
	f := framework.Global
	const (
		changeTypeRule      = "kubelet-anonymous-auth"
		unChangedTypeRule   = "api-server-insecure-port"
		moderateProfileName = "moderate"
		tpMixName           = "many-migrated-mix-tp"
		tpSingleName        = "migrated-single-tp"
		tpSingleNoPruneName = "migrated-single-no-prune-tp"
	)
	var (
		baselineImage = fmt.Sprintf("%s:%s", brokenContentImagePath, "kubelet_default")
		modifiedImage = fmt.Sprintf("%s:%s", brokenContentImagePath, "new_kubeletconfig")
	)

	prefixName := func(profName, ruleBaseName string) string { return profName + "-" + ruleBaseName }

	pbName := framework.GetObjNameFromTest(t)
	origPb, err := f.CreateProfileBundle(pbName, baselineImage, framework.OcpContentFile)
	if err != nil {
		t.Fatalf("failed to create ProfileBundle: %s", err)
	}
	// This should get cleaned up at the end of the test
	defer f.Client.Delete(context.TODO(), origPb)

	if err := f.WaitForProfileBundleStatus(pbName, compv1alpha1.DataStreamValid); err != nil {
		t.Fatalf("failed waiting for the ProfileBundle to become available: %s", err)
	}

	// Check that the rule exists in the original profile and it is a Platform rule
	changeTypeRuleName := prefixName(pbName, changeTypeRule)
	err, found := f.DoesRuleExist(origPb.Namespace, changeTypeRuleName)
	if err != nil {
		t.Fatal(err)
	} else if found != true {
		t.Fatalf("expected rule %s to exist in namespace %s", changeTypeRuleName, origPb.Namespace)
	}
	if err := f.AssertRuleIsPlatformType(changeTypeRuleName, f.OperatorNamespace); err != nil {
		t.Fatal(err)
	}

	// Check that the rule exists in the original profile and it is a Platform rule
	unChangedTypeRuleName := prefixName(pbName, unChangedTypeRule)
	err, found = f.DoesRuleExist(origPb.Namespace, unChangedTypeRuleName)
	if err != nil {
		t.Fatal(err)
	} else if found != true {
		t.Fatalf("expected rule %s to exist in namespace %s", unChangedTypeRuleName, origPb.Namespace)
	}
	if err := f.AssertRuleIsPlatformType(unChangedTypeRuleName, f.OperatorNamespace); err != nil {
		t.Fatal(err)
	}

	tpMix := &compv1alpha1.TailoredProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name:      tpMixName,
			Namespace: f.OperatorNamespace,
			Annotations: map[string]string{
				compv1alpha1.PruneOutdatedReferencesAnnotationKey: "true",
			},
		},
		Spec: compv1alpha1.TailoredProfileSpec{
			Title:       "TestForManyRules",
			Description: "TestForManyRules",
			EnableRules: []compv1alpha1.RuleReferenceSpec{
				{
					Name:      changeTypeRuleName,
					Rationale: "this rule should be removed from the profile",
				},
				{
					Name:      unChangedTypeRuleName,
					Rationale: "this rule should not be removed from the profile",
				},
			},
		},
	}

	tpSingle := &compv1alpha1.TailoredProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name:      tpSingleName,
			Namespace: f.OperatorNamespace,
			Annotations: map[string]string{
				compv1alpha1.PruneOutdatedReferencesAnnotationKey: "true",
			},
		},
		Spec: compv1alpha1.TailoredProfileSpec{
			Title:       "TestForManyRules",
			Description: "TestForManyRules",
			EnableRules: []compv1alpha1.RuleReferenceSpec{
				{
					Name:      changeTypeRuleName,
					Rationale: "this rule should be removed from the profile",
				},
			},
		},
	}

	tpMixNoPrune := &compv1alpha1.TailoredProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name:      tpSingleNoPruneName,
			Namespace: f.OperatorNamespace,
		},
		Spec: compv1alpha1.TailoredProfileSpec{
			Title:       "TestForNoPrune",
			Description: "TestForNoPrune",
			EnableRules: []compv1alpha1.RuleReferenceSpec{
				{
					Name:      changeTypeRuleName,
					Rationale: "this rule should not be removed from the profile",
				},
				{
					Name:      unChangedTypeRuleName,
					Rationale: "this rule should not be removed from the profile",
				},
			},
		},
	}

	createTPErr := f.Client.Create(context.TODO(), tpMix, nil)
	if createTPErr != nil {
		t.Fatal(createTPErr)
	}
	defer f.Client.Delete(context.TODO(), tpMix)
	// check the status of the TP to make sure it has no errors
	err = f.WaitForTailoredProfileStatus(f.OperatorNamespace, tpMixName, compv1alpha1.TailoredProfileStateReady)
	if err != nil {
		t.Fatal(err)
	}

	hasRule, err := f.EnableRuleExistInTailoredProfile(f.OperatorNamespace, tpMixName, changeTypeRuleName)
	if err != nil {
		t.Fatal(err)
	}
	if !hasRule {
		t.Fatalf("Expected the tailored profile to have rule: %s", changeTypeRuleName)
	}

	hasRule, err = f.EnableRuleExistInTailoredProfile(f.OperatorNamespace, tpMixName, unChangedTypeRuleName)
	if err != nil {
		t.Fatal(err)
	}
	if !hasRule {
		t.Fatalf("Expected the tailored profile to have rule: %s", unChangedTypeRuleName)
	}

	// tpSingle test
	createTPErr = f.Client.Create(context.TODO(), tpSingle, nil)
	if createTPErr != nil {
		t.Fatal(createTPErr)
	}
	defer f.Client.Delete(context.TODO(), tpSingle)
	// check the status of the TP to make sure it has no errors
	err = f.WaitForTailoredProfileStatus(f.OperatorNamespace, tpSingleName, compv1alpha1.TailoredProfileStateReady)
	if err != nil {
		t.Fatal(err)
	}

	hasRule, err = f.EnableRuleExistInTailoredProfile(f.OperatorNamespace, tpSingleName, changeTypeRuleName)
	if err != nil {
		t.Fatal(err)
	}
	if !hasRule {
		t.Fatalf("Expected the tailored profile to have rule: %s", changeTypeRuleName)
	}

	// tpMixNoPrune test
	createTPErr = f.Client.Create(context.TODO(), tpMixNoPrune, nil)
	if createTPErr != nil {
		t.Fatal(createTPErr)
	}
	defer f.Client.Delete(context.TODO(), tpMixNoPrune)
	// check the status of the TP to make sure it has no errors
	err = f.WaitForTailoredProfileStatus(f.OperatorNamespace, tpSingleNoPruneName, compv1alpha1.TailoredProfileStateReady)
	if err != nil {
		t.Fatal(err)
	}

	hasRule, err = f.EnableRuleExistInTailoredProfile(f.OperatorNamespace, tpSingleNoPruneName, changeTypeRuleName)
	if err != nil {
		t.Fatal(err)
	}

	if !hasRule {
		t.Fatalf("Expected the tailored profile to have rule: %s", changeTypeRuleName)
	}

	// update the image with a new hash
	modPb := origPb.DeepCopy()
	if err := f.Client.Get(context.TODO(), types.NamespacedName{Namespace: modPb.Namespace, Name: modPb.Name}, modPb); err != nil {
		t.Fatalf("failed to get ProfileBundle %s", modPb.Name)
	}

	modPb.Spec.ContentImage = modifiedImage
	if err := f.Client.Update(context.TODO(), modPb); err != nil {
		t.Fatalf("failed to update ProfileBundle %s: %s", modPb.Name, err)
	}

	// Wait for the update to happen, the PB will flip first to pending, then to valid
	if err := f.WaitForProfileBundleStatus(pbName, compv1alpha1.DataStreamValid); err != nil {
		t.Fatalf("failed to parse ProfileBundle %s: %s", pbName, err)
	}

	// Make sure the rules parsed correctly and one did indeed change from
	// a Platform to a Node rule. Note that this switch didn't happen
	// because of the test, but how the data stream was built.
	if err := f.AssertProfileBundleMustHaveParsedRules(pbName); err != nil {
		t.Fatal(err)
	}
	if err := f.AssertRuleIsPlatformType(unChangedTypeRuleName, f.OperatorNamespace); err != nil {
		t.Fatal(err)
	}
	if err := f.AssertRuleIsNodeType(changeTypeRuleName, f.OperatorNamespace); err != nil {
		t.Fatal(err)
	}

	// Assert the kubelet-anonymous-auth rule switched from Platform to Node type
	if err := f.AssertRuleCheckTypeChangedAnnotationKey(f.OperatorNamespace, changeTypeRuleName, "Platform"); err != nil {
		t.Fatal(err)
	}

	// check that the tp has been updated with the removed rule mixTP
	err = f.WaitForTailoredProfileStatus(f.OperatorNamespace, tpMixName, compv1alpha1.TailoredProfileStateReady)
	if err != nil {
		t.Fatal(err)
	}

	hasRule, err = f.EnableRuleExistInTailoredProfile(f.OperatorNamespace, tpMixName, changeTypeRuleName)
	if err != nil {
		t.Fatal(err)
	}
	if hasRule {
		t.Fatal("Expected the tailored profile to not have the rule")
	}

	hasRule, err = f.EnableRuleExistInTailoredProfile(f.OperatorNamespace, tpMixName, unChangedTypeRuleName)
	if err != nil {
		t.Fatal(err)
	}
	if !hasRule {
		t.Fatalf("Expected the tailored profile to have rule: %s", unChangedTypeRuleName)
	}

	// check that the tp has been updated with the removed rule singleTP
	err = f.WaitForTailoredProfileStatus(f.OperatorNamespace, tpSingleName, compv1alpha1.TailoredProfileStateError)
	if err != nil {
		t.Fatal(err)
	}

	hasRule, err = f.EnableRuleExistInTailoredProfile(f.OperatorNamespace, tpSingleName, changeTypeRuleName)
	if err != nil {
		t.Fatal(err)
	}
	if hasRule {
		t.Fatalf("Expected the tailored profile not to have rule: %s", changeTypeRuleName)
	}

	// check that the no prune tp still has the rule
	err = f.WaitForTailoredProfileStatus(f.OperatorNamespace, tpSingleNoPruneName, compv1alpha1.TailoredProfileStateReady)
	if err != nil {
		t.Fatal(err)
	}

	hasRule, err = f.EnableRuleExistInTailoredProfile(f.OperatorNamespace, tpSingleNoPruneName, changeTypeRuleName)
	if err != nil {
		t.Fatal(err)
	}
	if !hasRule {
		t.Fatalf("Expected the tailored profile to have rule: %s", changeTypeRuleName)
	}

	// check that we have a warning message in the tailored profile
	tpSingleNoPruneFetched := &compv1alpha1.TailoredProfile{}
	key := types.NamespacedName{Namespace: f.OperatorNamespace, Name: tpSingleNoPruneName}
	if err := f.Client.Get(context.Background(), key, tpSingleNoPruneFetched); err != nil {
		t.Fatal(err)
	}

	if len(tpSingleNoPruneFetched.Status.Warnings) == 0 {
		t.Fatalf("Expected the tailored profile to have a warning message but got none")
	}

	// check that the warning message is about the rule
	if !strings.Contains(tpSingleNoPruneFetched.Status.Warnings, changeTypeRule) {
		t.Fatalf("Expected the tailored profile to have a warning message about migrated rule: %s but got: %s", changeTypeRule, tpSingleNoPruneFetched.Status.Warnings)
	}

	// Annotate the TP to prune outdated references
	tpSingleNoPruneFetchedCopy := tpSingleNoPruneFetched.DeepCopy()
	tpSingleNoPruneFetchedCopy.Annotations[compv1alpha1.PruneOutdatedReferencesAnnotationKey] = "true"
	if err := f.Client.Update(context.Background(), tpSingleNoPruneFetchedCopy); err != nil {
		t.Fatal(err)
	}

	// check that the warning message is gone when we prune outdated references
	err = f.WaitForTailoredProfileStatus(f.OperatorNamespace, tpSingleNoPruneName, compv1alpha1.TailoredProfileStateReady)
	if err != nil {
		t.Fatal(err)
	}

	tpSingleNoPruneNoWarning := &compv1alpha1.TailoredProfile{}
	key = types.NamespacedName{Namespace: f.OperatorNamespace, Name: tpSingleNoPruneName}
	if err := f.Client.Get(context.Background(), key, tpSingleNoPruneFetched); err != nil {
		t.Fatal(err)
	}

	if len(tpSingleNoPruneNoWarning.Status.Warnings) != 0 {
		t.Fatalf("Expected the tailored profile to have no warning message but got: %s", tpSingleNoPruneFetched.Status.Warnings)
	}
	// check that the rule is being removed from the profile
	hasRule, err = f.EnableRuleExistInTailoredProfile(f.OperatorNamespace, tpSingleNoPruneName, changeTypeRuleName)
	if err != nil {
		t.Fatal(err)
	}

	if hasRule {
		t.Fatalf("Expected the tailored profile not to have rule: %s", changeTypeRuleName)
	}

}

func TestScanSettingBindingUsesDefaultScanSetting(t *testing.T) {
	t.Parallel()
	f := framework.Global
	objName := framework.GetObjNameFromTest(t)
	scanSettingBindingName := objName + "-binding"
	scanSettingBinding := compv1alpha1.ScanSettingBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      scanSettingBindingName,
			Namespace: f.OperatorNamespace,
		},
		Profiles: []compv1alpha1.NamedObjectReference{
			{
				Name:     "ocp4-cis",
				Kind:     "Profile",
				APIGroup: "compliance.openshift.io/v1alpha1",
			},
		},
	}
	if err := f.Client.Create(context.TODO(), &scanSettingBinding, nil); err != nil {
		t.Fatal(err)
	}
	defer f.Client.Delete(context.TODO(), &scanSettingBinding)

	// Wait until the suite finishes
	err := f.WaitForSuiteScansStatus(f.OperatorNamespace, scanSettingBindingName, compv1alpha1.PhaseDone, compv1alpha1.ResultNonCompliant)
	if err != nil {
		t.Fatal(err)
	}

	bindingKey := types.NamespacedName{Namespace: f.OperatorNamespace, Name: scanSettingBindingName}
	binding := &compv1alpha1.ScanSettingBinding{}
	if err := f.Client.Get(context.TODO(), bindingKey, binding); err != nil {
		t.Fatal(err)
	}

	// Make sure the binding used the `default` ScanSetting.
	if binding.SettingsRef.Name != "default" {
		t.Fatal("Expected the settings reference to use the default ScanSetting")
	}
}

func TestScanSettingBindingWatchesTailoredProfile(t *testing.T) {
	t.Parallel()
	f := framework.Global
	tpName := framework.GetObjNameFromTest(t)
	bindingName := framework.GetObjNameFromTest(t)

	tp := &compv1alpha1.TailoredProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name:      tpName,
			Namespace: f.OperatorNamespace,
		},
		Spec: compv1alpha1.TailoredProfileSpec{
			Title:       "TestScanSettingBindingWatchesTailoredProfile",
			Description: "TestScanSettingBindingWatchesTailoredProfile",
			DisableRules: []compv1alpha1.RuleReferenceSpec{
				{
					Name:      "no-such-rule",
					Rationale: "testing",
				},
			},
			Extends: "ocp4-cis",
		},
	}

	err := f.Client.Create(context.TODO(), tp, nil)
	if err != nil {
		t.Fatal("failed to create tailored profile")
	}
	defer f.Client.Delete(context.TODO(), tp)

	// make sure the TP is created with an error as expected
	err = wait.Poll(framework.RetryInterval, framework.Timeout, func() (bool, error) {
		tpGet := &compv1alpha1.TailoredProfile{}
		getErr := f.Client.Get(context.TODO(), types.NamespacedName{Name: tpName, Namespace: f.OperatorNamespace}, tpGet)
		if getErr != nil {
			// not gettable yet? retry
			return false, nil
		}

		if tpGet.Status.State != compv1alpha1.TailoredProfileStateError {
			return false, errors.New("expected the TP to be created with an error")
		}
		return true, nil
	})
	if err != nil {
		t.Fatal(err)
	}

	scanSettingBinding := compv1alpha1.ScanSettingBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      bindingName,
			Namespace: f.OperatorNamespace,
		},
		Profiles: []compv1alpha1.NamedObjectReference{
			{
				Name:     bindingName,
				Kind:     "TailoredProfile",
				APIGroup: "compliance.openshift.io/v1alpha1",
			},
		},
		SettingsRef: &compv1alpha1.NamedObjectReference{
			Name:     "default",
			Kind:     "ScanSetting",
			APIGroup: "compliance.openshift.io/v1alpha1",
		},
	}

	if err := f.Client.Create(context.TODO(), &scanSettingBinding, nil); err != nil {
		t.Fatal(err)
	}
	defer f.Client.Delete(context.TODO(), &scanSettingBinding)

	// Wait until the suite binding receives an error condition
	err = wait.Poll(framework.RetryInterval, framework.Timeout, func() (bool, error) {
		ssbGet := &compv1alpha1.ScanSettingBinding{}
		getErr := f.Client.Get(context.TODO(), types.NamespacedName{Name: bindingName, Namespace: f.OperatorNamespace}, ssbGet)
		if getErr != nil {
			// not gettable yet? retry
			return false, nil
		}

		readyCond := ssbGet.Status.Conditions.GetCondition("Ready")
		if readyCond == nil {
			return false, nil
		}
		if readyCond.Status != corev1.ConditionFalse && readyCond.Reason != "Invalid" {
			return false, fmt.Errorf("expected ready=false, reason=invalid, got %v", readyCond)
		}

		return true, nil
	})
	if err != nil {
		t.Fatal(err)
	}

	// Fix the TP
	tpGet := &compv1alpha1.TailoredProfile{}
	err = f.Client.Get(context.TODO(), types.NamespacedName{Name: tpName, Namespace: f.OperatorNamespace}, tpGet)
	if err != nil {
		t.Fatal(err)
	}

	tpUpdate := tpGet.DeepCopy()
	tpUpdate.Spec.DisableRules = []compv1alpha1.RuleReferenceSpec{
		{
			Name:      "ocp4-file-owner-scheduler-kubeconfig",
			Rationale: "testing",
		},
	}

	err = f.Client.Update(context.TODO(), tpUpdate)
	if err != nil {
		t.Fatal(err)
	}

	// Wait for the binding to transition to ready state
	// Wait until the suite binding receives an error condition
	err = wait.Poll(framework.RetryInterval, framework.Timeout, func() (bool, error) {
		ssbGet := &compv1alpha1.ScanSettingBinding{}
		getErr := f.Client.Get(context.TODO(), types.NamespacedName{Name: bindingName, Namespace: f.OperatorNamespace}, ssbGet)
		if getErr != nil {
			// not gettable yet? retry
			return false, nil
		}

		readyCond := ssbGet.Status.Conditions.GetCondition("Ready")
		if readyCond == nil {
			return false, nil
		}
		if readyCond.Status != corev1.ConditionTrue && readyCond.Reason != "Processed" {
			// don't return an error right away, let the poll just fail if it takes too long
			return false, nil
		}

		return true, nil
	})
	if err != nil {
		t.Fatal(err)
	}

}

func TestManualRulesTailoredProfile(t *testing.T) {
	t.Parallel()
	f := framework.Global
	var baselineImage = fmt.Sprintf("%s:%s", brokenContentImagePath, "kubeletconfig")
	const requiredRule = "kubelet-eviction-thresholds-set-soft-imagefs-available"
	pbName := framework.GetObjNameFromTest(t)
	prefixName := func(profName, ruleBaseName string) string { return profName + "-" + ruleBaseName }

	ocpPb, err := f.CreateProfileBundle(pbName, baselineImage, framework.OcpContentFile)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Client.Delete(context.TODO(), ocpPb)
	if err := f.WaitForProfileBundleStatus(pbName, compv1alpha1.DataStreamValid); err != nil {
		t.Fatal(err)
	}

	// Check that if the rule we are going to test is there
	requiredRuleName := prefixName(pbName, requiredRule)
	err, found := framework.Global.DoesRuleExist(f.OperatorNamespace, requiredRuleName)
	if err != nil {
		t.Fatal(err)
	} else if !found {
		t.Fatalf("Expected rule %s not found", requiredRuleName)
	}

	suiteName := "manual-rules-test-node"
	masterScanName := fmt.Sprintf("%s-master", suiteName)

	tp := &compv1alpha1.TailoredProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name:      suiteName,
			Namespace: f.OperatorNamespace,
			Annotations: map[string]string{
				compv1alpha1.DisableOutdatedReferenceValidation: "true",
			},
		},
		Spec: compv1alpha1.TailoredProfileSpec{
			Title:       "manual-rules-test",
			Description: "A test tailored profile to test manual-rules",
			ManualRules: []compv1alpha1.RuleReferenceSpec{
				{
					Name:      prefixName(pbName, requiredRule),
					Rationale: "To be tested",
				},
			},
		},
	}

	createTPErr := f.Client.Create(context.TODO(), tp, nil)
	if createTPErr != nil {
		t.Fatal(createTPErr)
	}
	defer f.Client.Delete(context.TODO(), tp)

	ssb := &compv1alpha1.ScanSettingBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      suiteName,
			Namespace: f.OperatorNamespace,
		},
		Profiles: []compv1alpha1.NamedObjectReference{
			{
				APIGroup: "compliance.openshift.io/v1alpha1",
				Kind:     "TailoredProfile",
				Name:     suiteName,
			},
		},
		SettingsRef: &compv1alpha1.NamedObjectReference{
			APIGroup: "compliance.openshift.io/v1alpha1",
			Kind:     "ScanSetting",
			Name:     "default",
		},
	}

	err = f.Client.Create(context.TODO(), ssb, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Client.Delete(context.TODO(), ssb)

	// Ensure that all the scans in the suite have finished and are marked as Done
	err = f.WaitForSuiteScansStatus(f.OperatorNamespace, suiteName, compv1alpha1.PhaseDone, compv1alpha1.ResultNonCompliant)
	if err != nil {
		t.Fatal(err)
	}

	// the check should be shown as manual
	checkResult := compv1alpha1.ComplianceCheckResult{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s-kubelet-eviction-thresholds-set-soft-imagefs-available", masterScanName),
			Namespace: f.OperatorNamespace,
		},
		ID:       "xccdf_org.ssgproject.content_rule_kubelet_eviction_thresholds_set_soft_imagefs_available",
		Status:   compv1alpha1.CheckResultManual,
		Severity: compv1alpha1.CheckResultSeverityMedium,
	}
	err = f.AssertHasCheck(suiteName, masterScanName, checkResult)
	if err != nil {
		t.Fatal(err)
	}

	inNs := client.InNamespace(f.OperatorNamespace)
	withLabel := client.MatchingLabels{"profile-bundle": pbName}

	remList := &compv1alpha1.ComplianceRemediationList{}
	err = f.Client.List(context.TODO(), remList, inNs, withLabel)
	if err != nil {
		t.Fatal(err)
	}

	if len(remList.Items) != 0 {
		t.Fatal("expected no remediation")
	}
}

func TestHideRule(t *testing.T) {
	t.Parallel()
	f := framework.Global
	var baselineImage = fmt.Sprintf("%s:%s", brokenContentImagePath, "hide_rule")
	const requiredRule = "version-detect"
	pbName := framework.GetObjNameFromTest(t)
	prefixName := func(profName, ruleBaseName string) string { return profName + "-" + ruleBaseName }

	ocpPb, err := f.CreateProfileBundle(pbName, baselineImage, framework.OcpContentFile)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Client.Delete(context.TODO(), ocpPb)
	if err := f.WaitForProfileBundleStatus(pbName, compv1alpha1.DataStreamValid); err != nil {
		t.Fatal(err)
	}

	// Check that if the rule we are going to test is there
	requiredRuleName := prefixName(pbName, requiredRule)
	err, found := f.DoesRuleExist(ocpPb.Namespace, requiredRuleName)
	if err != nil {
		t.Fatal(err)
	} else if !found {
		t.Fatalf("Expected rule %s not found", requiredRuleName)
	}

	suiteName := "hide-rules-test"
	scanName := "hide-rules-test"

	tp := &compv1alpha1.TailoredProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name:      suiteName,
			Namespace: f.OperatorNamespace,
		},
		Spec: compv1alpha1.TailoredProfileSpec{
			Title:       "hide-rules-test",
			Description: "A test tailored profile to test hide-rules",
			EnableRules: []compv1alpha1.RuleReferenceSpec{
				{
					Name:      prefixName(pbName, requiredRule),
					Rationale: "To be tested",
				},
			},
		},
	}

	createTPErr := f.Client.Create(context.TODO(), tp, nil)
	if createTPErr != nil {
		t.Fatal(createTPErr)
	}
	defer f.Client.Delete(context.TODO(), tp)

	ssb := &compv1alpha1.ScanSettingBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      suiteName,
			Namespace: f.OperatorNamespace,
		},
		Profiles: []compv1alpha1.NamedObjectReference{
			{
				APIGroup: "compliance.openshift.io/v1alpha1",
				Kind:     "TailoredProfile",
				Name:     suiteName,
			},
		},
		SettingsRef: &compv1alpha1.NamedObjectReference{
			APIGroup: "compliance.openshift.io/v1alpha1",
			Kind:     "ScanSetting",
			Name:     "default",
		},
	}

	err = f.Client.Create(context.TODO(), ssb, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Client.Delete(context.TODO(), ssb)

	// Ensure that all the scans in the suite have finished and are marked as Done
	err = f.WaitForSuiteScansStatus(f.OperatorNamespace, suiteName, compv1alpha1.PhaseDone, compv1alpha1.ResultNotApplicable)
	if err != nil {
		t.Fatal(err)
	}

	// the check should be shown as manual
	checkResult := compv1alpha1.ComplianceCheckResult{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s-version-detect", scanName),
			Namespace: f.OperatorNamespace,
		},
		ID:       "xccdf_org.ssgproject.content_rule_version_detect",
		Status:   compv1alpha1.CheckResultNoResult,
		Severity: compv1alpha1.CheckResultSeverityMedium,
	}
	err = f.AssertHasCheck(suiteName, scanName, checkResult)
	if err == nil {
		t.Fatalf("The check should not be found in the scan %s", scanName)
	}
}

func TestScheduledSuiteTimeoutFail(t *testing.T) {
	t.Parallel()
	f := framework.Global
	suiteName := "test-scheduled-suite-timeout-fail"

	workerScanName := fmt.Sprintf("%s-workers-scan", suiteName)
	selectWorkers := map[string]string{
		"node-role.kubernetes.io/worker": "",
	}

	testSuite := &compv1alpha1.ComplianceSuite{
		ObjectMeta: metav1.ObjectMeta{
			Name:      suiteName,
			Namespace: f.OperatorNamespace,
		},
		Spec: compv1alpha1.ComplianceSuiteSpec{
			ComplianceSuiteSettings: compv1alpha1.ComplianceSuiteSettings{
				AutoApplyRemediations: false,
			},
			Scans: []compv1alpha1.ComplianceScanSpecWrapper{
				{
					Name: workerScanName,
					ComplianceScanSpec: compv1alpha1.ComplianceScanSpec{
						ContentImage: contentImagePath,
						Profile:      "xccdf_org.ssgproject.content_profile_moderate",
						Content:      framework.RhcosContentFile,
						Rule:         "xccdf_org.ssgproject.content_rule_no_netrc_files",
						NodeSelector: selectWorkers,
						ComplianceScanSettings: compv1alpha1.ComplianceScanSettings{
							MaxRetryOnTimeout: 0,
							RawResultStorage: compv1alpha1.RawResultStorageSettings{
								Rotation: 1,
							},
							Timeout: "1s",
							Debug:   true,
						},
					},
				},
			},
		},
	}

	err := f.Client.Create(context.TODO(), testSuite, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Client.Delete(context.TODO(), testSuite)

	// Ensure that all the scans in the suite have finished and are marked as Done
	err = f.WaitForSuiteScansStatus(f.OperatorNamespace, suiteName, compv1alpha1.PhaseDone, compv1alpha1.ResultError)
	if err != nil {
		t.Fatal(err)
	}
	scan := &compv1alpha1.ComplianceScan{}
	err = f.Client.Get(context.TODO(), types.NamespacedName{Name: workerScanName, Namespace: f.OperatorNamespace}, scan)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := scan.Annotations[compv1alpha1.ComplianceScanTimeoutAnnotation]; !ok {
		t.Fatal("The scan should have the timeout annotation")
	}
}

func TestResultServerHTTPVersion(t *testing.T) {
	t.Parallel()
	f := framework.Global
	endpoints := []string{
		fmt.Sprintf("https://metrics.%s.svc:8585/metrics-co", f.OperatorNamespace),
		fmt.Sprintf("http://metrics.%s.svc:8383/metrics", f.OperatorNamespace),
	}

	expectedHTTPVersion := "HTTP/1.1"
	for _, endpoint := range endpoints {
		err := f.AssertMetricsEndpointUsesHTTPVersion(endpoint, expectedHTTPVersion)
		if err != nil {
			t.Fatal(err)
		}
	}
}

func TestRuleHasProfileAnnotation(t *testing.T) {
	t.Parallel()
	f := framework.Global
	const requiredRule = "ocp4-file-groupowner-worker-kubeconfig"
	const expectedRuleProfileAnnotation = "ocp4-pci-dss-node,ocp4-moderate-node,ocp4-stig-node,ocp4-nerc-cip-node,ocp4-cis-node,ocp4-high-node"
	err, found := f.DoesRuleExist(f.OperatorNamespace, requiredRule)
	if err != nil {
		t.Fatal(err)
	} else if !found {
		t.Fatalf("Expected rule %s not found", requiredRule)
	}

	// Check if requiredRule has the correct profile annotation
	rule := &compv1alpha1.Rule{}
	err = f.Client.Get(context.TODO(), types.NamespacedName{
		Name:      requiredRule,
		Namespace: f.OperatorNamespace,
	}, rule)
	if err != nil {
		t.Fatal(err)
	}
	expectedProfiles := strings.Split(expectedRuleProfileAnnotation, ",")
	for _, profileName := range expectedProfiles {
		if !f.AssertProfileInRuleAnnotation(rule, profileName) {
			t.Fatalf("expected to find profile %s in rule %s", profileName, rule.Name)
		}
	}
}

func TestScanCleansUpComplianceCheckResults(t *testing.T) {
	f := framework.Global
	t.Parallel()

	tpName := framework.GetObjNameFromTest(t)
	bindingName := tpName + "-binding"

	// create a tailored profile
	tp := &compv1alpha1.TailoredProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name:      tpName,
			Namespace: f.OperatorNamespace,
		},
		Spec: compv1alpha1.TailoredProfileSpec{
			Title:       tpName,
			Description: tpName,
			Extends:     "ocp4-cis",
		},
	}

	err := f.Client.Create(context.TODO(), tp, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Client.Delete(context.TODO(), tp)

	// run a scan
	ssb := compv1alpha1.ScanSettingBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      bindingName,
			Namespace: f.OperatorNamespace,
		},
		Profiles: []compv1alpha1.NamedObjectReference{
			{
				Name:     tpName,
				Kind:     "TailoredProfile",
				APIGroup: "compliance.openshift.io/v1alpha1",
			},
		},
		SettingsRef: &compv1alpha1.NamedObjectReference{
			Name:     "default",
			Kind:     "ScanSetting",
			APIGroup: "compliance.openshift.io/v1alpha1",
		},
	}
	err = f.Client.Create(context.TODO(), &ssb, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Client.Delete(context.TODO(), &ssb)

	if err := f.WaitForSuiteScansStatus(f.OperatorNamespace, bindingName, compv1alpha1.PhaseDone, compv1alpha1.ResultNonCompliant); err != nil {
		t.Fatal(err)
	}

	// verify a compliance check result exists
	checkName := tpName + "-audit-profile-set"
	checkResult := compv1alpha1.ComplianceCheckResult{
		ObjectMeta: metav1.ObjectMeta{
			Name:      checkName,
			Namespace: f.OperatorNamespace,
		},
		ID:       "xccdf_org.ssgproject.content_rule_audit_profile_set",
		Status:   compv1alpha1.CheckResultFail,
		Severity: compv1alpha1.CheckResultSeverityMedium,
	}
	err = f.AssertHasCheck(bindingName, tpName, checkResult)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.AssertRemediationExists(checkName, f.OperatorNamespace); err != nil {
		t.Fatal(err)
	}

	// update tailored profile to exclude the rule before we kick off another run
	tpGet := &compv1alpha1.TailoredProfile{}
	err = f.Client.Get(context.TODO(), types.NamespacedName{Name: tpName, Namespace: f.OperatorNamespace}, tpGet)
	if err != nil {
		t.Fatal(err)
	}

	tpUpdate := tpGet.DeepCopy()
	ruleName := "ocp4-audit-profile-set"
	tpUpdate.Spec.DisableRules = []compv1alpha1.RuleReferenceSpec{
		{
			Name:      ruleName,
			Rationale: "testing to ensure scan results are cleaned up",
		},
	}

	err = f.Client.Update(context.TODO(), tpUpdate)
	if err != nil {
		t.Fatal(err)
	}

	// rerun the scan
	err = f.ReRunScan(tpName, f.OperatorNamespace)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.WaitForSuiteScansStatus(f.OperatorNamespace, bindingName, compv1alpha1.PhaseDone, compv1alpha1.ResultNonCompliant); err != nil {
		t.Fatal(err)
	}

	// verify the compliance check result doesn't exist, which will also
	// mean the compliance remediation should also be gone
	if err = f.AssertScanDoesNotContainCheck(tpName, checkName, f.OperatorNamespace); err != nil {
		t.Fatal(err)
	}
	if err = f.AssertRemediationDoesNotExists(checkName, f.OperatorNamespace); err != nil {
		t.Fatal(err)
	}
}
