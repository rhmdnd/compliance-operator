package common

import (
	"context"
	"fmt"
	"time"

	// configv1 "github.com/openshift/api/config/v1"
	// "github.com/openshift/api/features"
	"github.com/openshift/library-go/pkg/operator/configobserver/featuregates"
	// metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/klog/v2"
)

func WaitForFeatureGatesReady(ctx context.Context, featureGateAccess featuregates.FeatureGateAccess) error {
	timeout := time.After(1 * time.Minute)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timeout:
			return fmt.Errorf("timed out waiting for FeatureGates to be ready")
		default:
			features, err := featureGateAccess.CurrentFeatureGates()
			if err == nil {
				enabled, disabled := GetEnabledDisabledFeatures(features)
				klog.Infof("FeatureGates initialized: enabled=%v, disabled=%v", enabled, disabled)
				return nil
			}
			klog.Infof("Waiting for FeatureGates to be ready...")
			time.Sleep(1 * time.Second)
		}
	}
}

// getEnabledDisabledFeatures extracts enabled and disabled features from the feature gate.
func GetEnabledDisabledFeatures(features featuregates.FeatureGate) ([]string, []string) {
	var enabled []string
	var disabled []string

	for _, feature := range features.KnownFeatures() {
		if features.Enabled(feature) {
			enabled = append(enabled, string(feature))
		} else {
			disabled = append(disabled, string(feature))
		}
	}

	return enabled, disabled
}

// IsBootImageControllerRequired checks that the currently enabled feature gates and
// the platform of the cluster requires a boot image controller. If any errors are
// encountered, it will log them and return false.
// Current valid feature gate and platform combinations:
// GCP -> FeatureGateManagedBootImages
// AWS -> FeatureGateManagedBootImagesAWS
func IsBootImageControllerRequired(ctx *ControllerContext) bool {
	// Feature gates FeatureGateManagedBootImagesAWS and FeatureGateManagedBootImages
	// have been removed from the newer OpenShift API. This function is not used by
	// compliance-operator. Returning false to maintain compatibility.
	// TODO: Update machine-config-operator to a compatible version.
	_ = ctx // Silence unused parameter warning
	return false
}
