package compliancescan

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/go-logr/logr"
	ocpapisecv1 "github.com/openshift/api/security/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	compv1alpha1 "github.com/ComplianceAsCode/compliance-operator/pkg/apis/compliance/v1alpha1"
	"github.com/ComplianceAsCode/compliance-operator/pkg/controller/common"
	"github.com/ComplianceAsCode/compliance-operator/pkg/utils"
)

const resultserverSA = "resultserver"

const (
	defaultPodFSGroup int64 = 2000
	defaultPodUid     int64 = 1000
)

// The result-server is a pod that listens for results from other pods and
// stores them in a PVC.
// It's comprised of the PVC for the scan, the pod and a service that fronts it
func (r *ReconcileComplianceScan) createResultServer(instance *compv1alpha1.ComplianceScan, logger logr.Logger) error {
	ctx := context.Background()
	resultServerLabels := getResultServerLabels(instance)

	logger.Info("Creating scan result server pod")
	podFSGroup, podFSGroupErr := r.getPodFSGroup(ctx)
	if podFSGroupErr != nil {
		return podFSGroupErr
	}
	podUid, podUidErr := r.getPodUid(ctx)
	if podUidErr != nil {
		return podUidErr
	}
	deployment := resultServer(instance, resultServerLabels, podFSGroup, podUid, logger)
	if priorityClassExist, why := utils.ValidatePriorityClassExist(deployment.Spec.Template.Spec.PriorityClassName, r.Client); !priorityClassExist {
		log.Info(why, "resultServer", deployment.Name)
		r.Recorder.Eventf(deployment, corev1.EventTypeWarning, "PriorityClass", why+" resultServer:"+deployment.Name)
		deployment.Spec.Template.Spec.PriorityClassName = ""
	}
	err := r.Client.Create(ctx, deployment)
	if err != nil && !errors.IsAlreadyExists(err) {
		logger.Error(err, "Cannot create deployment", "deployment", deployment)
		return err
	}
	logger.Info("ResultServer Deployment launched", "Deployment.Name", deployment.Name)

	service := resultServerService(instance, resultServerLabels)
	err = r.Client.Create(ctx, service)
	if err != nil && !errors.IsAlreadyExists(err) {
		logger.Error(err, "Cannot create service", "service", service)
		return err
	}
	logger.Info("ResultServer Service launched", "Service.Name", service.Name)
	return nil
}

func (r *ReconcileComplianceScan) scaleDownResultServer(instance *compv1alpha1.ComplianceScan, logger logr.Logger) error {
	ctx := context.TODO()
	key := types.NamespacedName{
		Name:      getResultServerName(instance),
		Namespace: common.GetComplianceOperatorNamespace(),
	}

	rslog := logger.WithValues(
		"Deployment.Name", key.Name,
		"Deployment.Namespace", key.Namespace)

	rslog.Info("Scaling down result server")

	found := &appsv1.Deployment{}
	err := r.Client.Get(ctx, key, found)
	if err != nil {
		if errors.IsNotFound(err) {
			rslog.Info("result server doesn't exist. " +
				"This is a non-issue since we were scaling down anyway")
			return nil
		}
		rslog.Error(err, "Error getting result server in preparation of scale-down")
		return err
	}

	// scale down
	var zeroRepls int32 = 0
	rs := found.DeepCopy()
	rs.Spec.Replicas = &zeroRepls
	rslog.Info("Updating result server for scale-down")
	return r.Client.Update(ctx, rs)
}

func (r *ReconcileComplianceScan) deleteResultServer(instance *compv1alpha1.ComplianceScan, logger logr.Logger) error {
	resultServerLabels := getResultServerLabels(instance)

	logger.Info("Deleting scan result server pod")

	deployment := resultServer(instance, resultServerLabels, 0, 0, logger)

	err := r.Client.Delete(context.TODO(), deployment)
	if err != nil && !errors.IsNotFound(err) {
		logger.Error(err, "Cannot delete deployment", "deployment", deployment)
		return err
	}
	logger.Info("ResultServer Deployment deleted", "Deployment.Name", deployment.Name)
	logger.Info("Deleting scan result server service")

	service := resultServerService(instance, resultServerLabels)
	err = r.Client.Delete(context.TODO(), service)
	if err != nil && !errors.IsNotFound(err) {
		logger.Error(err, "Cannot delete service", "service", service)
		return err
	}
	logger.Info("ResultServer Service deleted", "Service.Name", service.Name)
	return nil
}

func getResultServerLabels(instance *compv1alpha1.ComplianceScan) map[string]string {
	return map[string]string{
		compv1alpha1.ComplianceScanLabel: instance.Name,
		"workload":                       "resultserver",
	}
}

func (r *ReconcileComplianceScan) getPodFSGroup(ctx context.Context) (int64, error) {
	return r.getRangeFromNSorDefault(ctx, ocpapisecv1.SupplementalGroupsAnnotation, defaultPodFSGroup)
}

func (r *ReconcileComplianceScan) getPodUid(ctx context.Context) (int64, error) {
	return r.getRangeFromNSorDefault(ctx, ocpapisecv1.UIDRangeAnnotation, defaultPodUid)
}

func (r *ReconcileComplianceScan) getRangeFromNSorDefault(
	ctx context.Context,
	rangeTypeAnnotation string,
	defaultValue int64,
) (int64, error) {
	key := types.NamespacedName{
		Name: common.GetComplianceOperatorNamespace(),
	}
	ns := corev1.Namespace{}
	if geterr := r.Client.Get(ctx, key, &ns); geterr != nil {
		return 0, geterr
	}
	anns := ns.GetAnnotations()
	targetrange, found := anns[rangeTypeAnnotation]
	if !found {
		return defaultValue, nil
	}
	rangeInfo := strings.Split(targetrange, "/")[0]
	rangeinit, err := strconv.Atoi(rangeInfo)
	if err != nil {
		return 0, err
	}
	return int64(rangeinit), nil
}

// Serve up arf reports for a compliance scan with a web service protected by openshift auth (oauth-proxy sidecar).
// Needs corresponding Service (with service-serving cert).
// Need to aggregate reports into one service ? on subdirs?
func resultServer(scanInstance *compv1alpha1.ComplianceScan, labels map[string]string,
	podFSGroup, podUid int64, logger logr.Logger) *appsv1.Deployment {
	falseP := false
	trueP := true
	return &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      getResultServerName(scanInstance),
			Namespace: common.GetComplianceOperatorNamespace(),
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: &oneReplica,
			Selector: &metav1.LabelSelector{
				MatchLabels: labels,
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: labels,
					Annotations: map[string]string{
						"workload.openshift.io/management": `{"effect": "PreferredDuringScheduling"}`,
					},
				},
				Spec: corev1.PodSpec{
					NodeSelector:       scanInstance.Spec.RawResultStorage.NodeSelector,
					Tolerations:        scanInstance.Spec.RawResultStorage.Tolerations,
					ServiceAccountName: resultserverSA,
					PriorityClassName:  scanInstance.Spec.PriorityClass,
					SecurityContext: &corev1.PodSecurityContext{
						FSGroup:      &podFSGroup,
						RunAsNonRoot: &trueP,
						RunAsUser:    &podUid,
					},
					Containers: []corev1.Container{
						{
							Name:            "result-server",
							Image:           utils.GetComponentImage(utils.OPERATOR),
							ImagePullPolicy: corev1.PullAlways,
							Command: []string{
								"compliance-operator", "resultserver",
								"--path=/reports/",
								"--address=0.0.0.0",
								fmt.Sprintf("--port=%d", ResultServerPort),
								fmt.Sprintf("--scan-index=%d", scanInstance.Status.CurrentIndex),
								fmt.Sprintf("--rotation=%d", scanInstance.Spec.RawResultStorage.Rotation),
								"--tls-server-cert=/etc/pki/tls/tls.crt",
								"--tls-server-key=/etc/pki/tls/tls.key",
								"--tls-ca=/etc/pki/tls/ca.crt",
							},
							SecurityContext: &corev1.SecurityContext{
								AllowPrivilegeEscalation: &falseP,
								ReadOnlyRootFilesystem:   &trueP,
								Capabilities: &corev1.Capabilities{
									Drop: []corev1.Capability{"ALL"},
								},
							},
							VolumeMounts: []corev1.VolumeMount{
								{
									Name:      "arfreports",
									MountPath: "/reports",
								},
								{
									Name:      "tls",
									MountPath: "/etc/pki/tls",
									ReadOnly:  true,
								},
							},
						},
					},
					Volumes: []corev1.Volume{
						{
							Name: "arfreports",
							VolumeSource: corev1.VolumeSource{
								PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{
									ClaimName: getPVCForScanName(scanInstance.Name),
								},
							},
						},
						{
							Name: "tls",
							VolumeSource: corev1.VolumeSource{
								Secret: &corev1.SecretVolumeSource{
									SecretName: ServerCertPrefix + scanInstance.Name,
								},
							},
						},
					},
				},
			},
		},
	}
}

func resultServerService(scanInstance *compv1alpha1.ComplianceScan, labels map[string]string) *corev1.Service {
	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      getResultServerName(scanInstance),
			Namespace: common.GetComplianceOperatorNamespace(),
		},
		Spec: corev1.ServiceSpec{
			Selector: labels,
			Ports: []corev1.ServicePort{
				{
					Protocol: corev1.Protocol("TCP"),
					Port:     ResultServerPort,
				},
			},
		},
	}
}

func getResultServerName(instance *compv1alpha1.ComplianceScan) string {
	return instance.Name + "-rs"
}

func getResultServerURI(instance *compv1alpha1.ComplianceScan) string {
	return "https://" + getResultServerName(instance) + fmt.Sprintf(":%d/", ResultServerPort)
}

func getDisableRawResultUploadValue(instance *compv1alpha1.ComplianceScan) string {
	if instance.Spec.RawResultStorage.Disabled {
		return "true"
	} else {
		return "false"
	}
}

func getLogCollectorVolumeMounts(instance *compv1alpha1.ComplianceScan) []corev1.VolumeMount {
	if instance.Spec.RawResultStorage.Disabled {
		return []corev1.VolumeMount{
			{
				Name:      "report-dir",
				MountPath: "/reports",
				ReadOnly:  true,
			},
		}
	} else {
		return []corev1.VolumeMount{
			{
				Name:      "report-dir",
				MountPath: "/reports",
			},
			{
				Name:      "tls",
				MountPath: "/etc/pki/tls",
				ReadOnly:  true,
			},
		}
	}

}

func getPlatformScannerPodVolumes(instance *compv1alpha1.ComplianceScan) []corev1.Volume {
	mode := int32(0755)
	volumeList := []corev1.Volume{
		{
			Name: "report-dir",
			VolumeSource: corev1.VolumeSource{
				EmptyDir: &corev1.EmptyDirVolumeSource{},
			},
		},
		{
			Name: "content-dir",
			VolumeSource: corev1.VolumeSource{
				EmptyDir: &corev1.EmptyDirVolumeSource{},
			},
		},
		{
			Name: "tmp-dir",
			VolumeSource: corev1.VolumeSource{
				EmptyDir: &corev1.EmptyDirVolumeSource{},
			},
		},
		{
			Name: "fetch-results",
			VolumeSource: corev1.VolumeSource{
				EmptyDir: &corev1.EmptyDirVolumeSource{},
			},
		},
		{
			Name: scriptCmForScan(instance),
			VolumeSource: corev1.VolumeSource{
				ConfigMap: &corev1.ConfigMapVolumeSource{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: scriptCmForScan(instance),
					},
					DefaultMode: &mode,
				},
			},
		},
	}
	if instance.Spec.RawResultStorage.Disabled {
		return volumeList
	} else {
		volumeList = append(volumeList, corev1.Volume{
			Name: "tls",
			VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{
					SecretName: ClientCertPrefix + instance.Name,
				},
			},
		},
		)
		return volumeList
	}
}

func getNodeScannerPodVolumes(instance *compv1alpha1.ComplianceScan, node *corev1.Node) []corev1.Volume {
	mode := int32(0744)
	kubeMode := int32(0600)
	volumesList := []corev1.Volume{
		{
			Name: "host",
			VolumeSource: corev1.VolumeSource{
				HostPath: &corev1.HostPathVolumeSource{
					Path: "/",
					Type: &hostPathDir,
				},
			},
		},
		{
			Name: "report-dir",
			VolumeSource: corev1.VolumeSource{
				EmptyDir: &corev1.EmptyDirVolumeSource{},
			},
		},
		{
			Name: "content-dir",
			VolumeSource: corev1.VolumeSource{
				EmptyDir: &corev1.EmptyDirVolumeSource{},
			},
		},
		{
			Name: "tmp-dir",
			VolumeSource: corev1.VolumeSource{
				EmptyDir: &corev1.EmptyDirVolumeSource{},
			},
		},
		{
			Name: scriptCmForScan(instance),
			VolumeSource: corev1.VolumeSource{
				ConfigMap: &corev1.ConfigMapVolumeSource{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: scriptCmForScan(instance),
					},
					DefaultMode: &mode,
				},
			},
		},
		{
			Name: "kubeletconfig",
			VolumeSource: corev1.VolumeSource{
				ConfigMap: &corev1.ConfigMapVolumeSource{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: getKubeletCMNameForScan(instance, node),
					},
					DefaultMode: &kubeMode,
				},
			},
		},
	}
	if instance.Spec.RawResultStorage.Disabled {
		return volumesList
	} else {
		volumesList = append(volumesList, corev1.Volume{
			Name: "tls",
			VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{
					SecretName: ClientCertPrefix + instance.Name,
				},
			},
		},
		)
		return volumesList
	}
}
