package compliancescan

import (
	"context"
	"fmt"
	"os"
	"path"
	"strings"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	compv1alpha1 "github.com/ComplianceAsCode/compliance-operator/pkg/apis/compliance/v1alpha1"
	"github.com/ComplianceAsCode/compliance-operator/pkg/controller/common"
	"github.com/ComplianceAsCode/compliance-operator/pkg/utils"
)

const (
	resultscollectorSA      = "resultscollector"
	apiResourceCollectorSA  = "api-resource-collector"
	tailoringCMVolumeName   = "tailoring"
	tailoringNotFoundPrefix = "Tailoring ConfigMap not found: "
)

func (r *ReconcileComplianceScan) launchScanPod(instance *compv1alpha1.ComplianceScan, pod *corev1.Pod, logger logr.Logger) error {
	podLogger := logger.WithValues("Pod.Name", pod.Name)
	if instance.Spec.TailoringConfigMap != nil {
		if err := r.reconcileTailoring(instance, pod, logger); err != nil {
			return err
		}
	}

	// ..and launch it..
	err := r.Client.Create(context.TODO(), pod)
	if errors.IsAlreadyExists(err) {
		podLogger.Info("Pod already exists. This is fine.")
	} else if err != nil {
		podLogger.Error(err, "Failed to launch a pod")
		return err
	} else {
		podLogger.Info("Launched a pod")
	}
	return nil
}

func scanLimits(scanInstance *compv1alpha1.ComplianceScan, defaultMem, defaultCpu string) *corev1.ResourceList {
	limits := corev1.ResourceList{
		corev1.ResourceMemory: resource.MustParse(defaultMem),
		corev1.ResourceCPU:    resource.MustParse(defaultCpu),
	}

	if scanInstance.Spec.ScanLimits != nil {
		for resource := range limits {
			customLimit, ok := scanInstance.Spec.ScanLimits[resource]
			if ok {
				limits[resource] = customLimit
			}
		}
	}

	return &limits
}

func newScanPodForNode(scanInstance *compv1alpha1.ComplianceScan, node *corev1.Node, logger logr.Logger) *corev1.Pod {

	podName := getPodForNodeName(scanInstance.Name, node.Name)
	cmName := getConfigMapForNodeName(scanInstance.Name, node.Name)
	podLabels := map[string]string{
		compv1alpha1.ComplianceScanLabel: scanInstance.Name,
		"targetNode":                     node.Name,
		"workload":                       "scanner",
	}
	falseP := false
	trueP := true
	hostToContainer := corev1.MountPropagationHostToContainer

	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      podName,
			Namespace: common.GetComplianceOperatorNamespace(),
			Labels:    podLabels,
			Annotations: map[string]string{
				"openshift.io/scc": "privileged",
			},
		},
		Spec: corev1.PodSpec{
			ServiceAccountName: resultscollectorSA,
			PriorityClassName:  scanInstance.Spec.PriorityClass,
			InitContainers: []corev1.Container{
				{
					Name:  "content-container",
					Image: getInitContainerImage(&scanInstance.Spec, logger),
					Command: []string{
						"sh",
						"-c",
						fmt.Sprintf("cp %s /content | /bin/true", path.Join("/", scanInstance.Spec.Content)),
					},
					ImagePullPolicy: corev1.PullAlways,
					SecurityContext: &corev1.SecurityContext{
						AllowPrivilegeEscalation: &falseP,
						ReadOnlyRootFilesystem:   &trueP,
						Capabilities: &corev1.Capabilities{
							Drop: []corev1.Capability{"ALL"},
						},
					},
					Resources: corev1.ResourceRequirements{
						Requests: corev1.ResourceList{
							corev1.ResourceMemory: resource.MustParse("10Mi"),
							corev1.ResourceCPU:    resource.MustParse("10m"),
						},
						Limits: corev1.ResourceList{
							corev1.ResourceMemory: resource.MustParse("50Mi"),
							corev1.ResourceCPU:    resource.MustParse("50m"),
						},
					},
					VolumeMounts: []corev1.VolumeMount{
						{
							Name:      "content-dir",
							MountPath: "/content",
						},
					},
				},
				{
					Name:  "runtime-kubeletconfig-helper",
					Image: utils.GetComponentImage(utils.OPERATOR),
					Command: []string{
						"sh",
						"-c",
						fmt.Sprintf("mkdir -p %s && ln -s %s %s | /bin/true", KubeletConfigLinkFolder, KubeletConfigMapPath, KubeletConfigLinkPath),
					},
					ImagePullPolicy: corev1.PullAlways,
					SecurityContext: &corev1.SecurityContext{
						Privileged:             &trueVal,
						ReadOnlyRootFilesystem: &trueP,
					},
					Resources: corev1.ResourceRequirements{
						Requests: corev1.ResourceList{
							corev1.ResourceMemory: resource.MustParse("20Mi"),
							corev1.ResourceCPU:    resource.MustParse("10m"),
						},
						Limits: corev1.ResourceList{
							corev1.ResourceMemory: resource.MustParse("50Mi"),
							corev1.ResourceCPU:    resource.MustParse("50m"),
						},
					},
					VolumeMounts: []corev1.VolumeMount{
						{
							Name:      "host",
							MountPath: "/host",
						},
						{
							Name:      "kubeletconfig",
							ReadOnly:  true,
							MountPath: KubeletConfigMapPath,
						},
					},
				},
			},
			Containers: []corev1.Container{
				{
					Name:  "log-collector",
					Image: utils.GetComponentImage(utils.OPERATOR),
					Command: []string{
						"compliance-operator", "resultscollector",
						"--arf-file=/reports/report-arf.xml",
						"--results-file=/reports/report.xml",
						"--exit-code-file=/reports/exit_code",
						"--oscap-output-file=/reports/cmd_output",
						"--config-map-name=" + cmName,
						"--node-name=" + node.Name,
						"--owner=" + scanInstance.Name,
						"--namespace=" + scanInstance.Namespace,
						"--resultserveruri=" + getResultServerURI(scanInstance),
						"--tls-client-cert=/etc/pki/tls/tls.crt",
						"--tls-client-key=/etc/pki/tls/tls.key",
						"--tls-ca=/etc/pki/tls/ca.crt",
						"--disable-raw-upload=" + getDisableRawResultUploadValue(scanInstance),
					},
					ImagePullPolicy: corev1.PullAlways,
					SecurityContext: &corev1.SecurityContext{
						AllowPrivilegeEscalation: &falseP,
						ReadOnlyRootFilesystem:   &trueP,
						Capabilities: &corev1.Capabilities{
							Drop: []corev1.Capability{"ALL"},
						},
					},
					Resources: corev1.ResourceRequirements{
						Requests: corev1.ResourceList{
							corev1.ResourceMemory: resource.MustParse("20Mi"),
							corev1.ResourceCPU:    resource.MustParse("10m"),
						},
						Limits: corev1.ResourceList{
							corev1.ResourceMemory: resource.MustParse("100Mi"),
							corev1.ResourceCPU:    resource.MustParse("100m"),
						},
					},
					VolumeMounts: getLogCollectorVolumeMounts(scanInstance),
				},
				{
					Name:    OpenSCAPScanContainerName,
					Image:   utils.GetComponentImage(utils.OPENSCAP),
					Command: []string{OpenScapScriptPath},
					SecurityContext: &corev1.SecurityContext{
						Privileged:               &falseP,
						AllowPrivilegeEscalation: &falseP,
						ReadOnlyRootFilesystem:   &trueP,
						Capabilities: &corev1.Capabilities{
							Drop: []corev1.Capability{"ALL"},
							Add:  []corev1.Capability{"CAP_SYS_CHROOT"},
						},
						// TODO(jaosorior): Figure out if the default
						// seccomp profile is sufficient here.
					},
					Resources: corev1.ResourceRequirements{
						Requests: corev1.ResourceList{
							corev1.ResourceMemory: resource.MustParse("50Mi"),
							corev1.ResourceCPU:    resource.MustParse("10m"),
						},
						// NOTE: when changing the default limits, remember to also change the
						// doc text in the CRD.
						Limits: *scanLimits(scanInstance, "500Mi", "100m"),
					},
					VolumeMounts: []corev1.VolumeMount{
						{
							Name:             "host",
							MountPath:        "/host",
							MountPropagation: &hostToContainer,
							ReadOnly:         true,
						},
						{
							Name:      "report-dir",
							MountPath: "/reports",
						},
						{
							Name:      "content-dir",
							MountPath: "/content",
							ReadOnly:  true,
						},
						{
							Name:      "tmp-dir",
							MountPath: "/tmp",
						},
						{
							Name:      scriptCmForScan(scanInstance),
							MountPath: "/scripts",
							ReadOnly:  true,
						},
						{
							Name:      "kubeletconfig",
							MountPath: KubeletConfigMapPath,
							ReadOnly:  true,
						},
					},
					Env: []corev1.EnvVar{
						{
							Name:  "OVERRIDE_TARGET",
							Value: node.Labels[corev1.LabelHostname],
						},
						{
							Name:  "OSCAP_EVALUATION_TARGET",
							Value: node.Name,
						},
					},
					EnvFrom: []corev1.EnvFromSource{
						{
							ConfigMapRef: &corev1.ConfigMapEnvSource{
								LocalObjectReference: corev1.LocalObjectReference{
									Name: envCmForScan(scanInstance),
								},
							},
						},
					},
				},
			},
			Tolerations: scanInstance.Spec.ScanTolerations,
			NodeSelector: map[string]string{
				corev1.LabelHostname: node.Labels[corev1.LabelHostname],
			},
			HostNetwork:   true,
			DNSPolicy:     "ClusterFirstWithHostNet",
			RestartPolicy: corev1.RestartPolicyOnFailure,
			Volumes:       getNodeScannerPodVolumes(scanInstance, node),
		},
	}
}

func (r *ReconcileComplianceScan) newPlatformScanPod(scanInstance *compv1alpha1.ComplianceScan, logger logr.Logger) *corev1.Pod {
	podName := getPodForNodeName(scanInstance.Name, PlatformScanName)
	cmName := getConfigMapForNodeName(scanInstance.Name, PlatformScanName)
	podLabels := map[string]string{
		compv1alpha1.ComplianceScanLabel: scanInstance.Name,
		"workload":                       "scanner",
	}
	collectorCmd := []string{
		"compliance-operator", "api-resource-collector",
		"--content=/content/" + scanInstance.Spec.Content,
		"--resultdir=" + PlatformScanDataRoot,
		"--profile=" + scanInstance.Spec.Profile,
		"--warnings-output-file=/reports/warning_output",
		"--platform=" + os.Getenv("PLATFORM"),
	}
	if scanInstance.Spec.TailoringConfigMap != nil {
		// NOTE(jaosorior): Adding the tailoring volume is handled in the
		// addTailoringVolume function
		tailoringArg := fmt.Sprintf("--tailoring=%s/tailoring.xml", OpenScapTailoringDir)
		collectorCmd = append(collectorCmd, tailoringArg)
	}

	falseP := false
	trueP := true

	if scanInstance.Spec.Debug {
		collectorCmd = append(collectorCmd, "--debug")
	}

	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      podName,
			Namespace: common.GetComplianceOperatorNamespace(),
			Labels:    podLabels,
			Annotations: map[string]string{
				"workload.openshift.io/management": `{"effect": "PreferredDuringScheduling"}`,
			},
		},
		Spec: corev1.PodSpec{
			ServiceAccountName: apiResourceCollectorSA,
			SecurityContext: &corev1.PodSecurityContext{
				RunAsNonRoot: &trueP,
			},
			PriorityClassName: scanInstance.Spec.PriorityClass,
			InitContainers: []corev1.Container{
				{
					Name:  "content-container",
					Image: getInitContainerImage(&scanInstance.Spec, logger),
					Command: []string{
						"sh",
						"-c",
						fmt.Sprintf("cp %s /content | /bin/true", path.Join("/", scanInstance.Spec.Content)),
					},
					ImagePullPolicy: corev1.PullAlways,
					SecurityContext: &corev1.SecurityContext{
						AllowPrivilegeEscalation: &falseP,
						ReadOnlyRootFilesystem:   &trueP,
						Capabilities: &corev1.Capabilities{
							Drop: []corev1.Capability{"ALL"},
						},
					},
					Resources: corev1.ResourceRequirements{
						Requests: corev1.ResourceList{
							corev1.ResourceMemory: resource.MustParse("10Mi"),
							corev1.ResourceCPU:    resource.MustParse("10m"),
						},
						Limits: corev1.ResourceList{
							corev1.ResourceMemory: resource.MustParse("50Mi"),
							corev1.ResourceCPU:    resource.MustParse("50m"),
						},
					},
					VolumeMounts: []corev1.VolumeMount{
						{
							Name:      "content-dir",
							MountPath: "/content",
						},
					},
				},
				{
					Name:            PlatformScanResourceCollectorName,
					Image:           utils.GetComponentImage(utils.OPERATOR),
					Command:         collectorCmd,
					ImagePullPolicy: corev1.PullAlways,
					SecurityContext: &corev1.SecurityContext{
						AllowPrivilegeEscalation: &falseP,
						ReadOnlyRootFilesystem:   &trueP,
						Capabilities: &corev1.Capabilities{
							Drop: []corev1.Capability{"ALL"},
						},
					},
					Resources: corev1.ResourceRequirements{
						Requests: corev1.ResourceList{
							corev1.ResourceMemory: resource.MustParse("20Mi"),
							corev1.ResourceCPU:    resource.MustParse("10m"),
						},
						// NOTE: when changing the default limits, remember to also change the
						// doc text in the CRD.
						Limits: *scanLimits(scanInstance, "202Mi", "100m"),
					},
					VolumeMounts: []corev1.VolumeMount{
						{
							Name:      "content-dir",
							MountPath: "/content",
							ReadOnly:  true,
						},
						{
							Name:      "fetch-results",
							MountPath: PlatformScanDataRoot,
						},
						{
							Name:      "report-dir",
							MountPath: "/reports",
						},
					},
					Env: []corev1.EnvVar{
						{
							Name: "POD_NAMESPACE",
							ValueFrom: &corev1.EnvVarSource{
								FieldRef: &corev1.ObjectFieldSelector{
									FieldPath: "metadata.namespace",
								},
							},
						},
						{
							Name: "POD_NAME",
							ValueFrom: &corev1.EnvVarSource{
								FieldRef: &corev1.ObjectFieldSelector{
									FieldPath: "metadata.name",
								},
							},
						},
					},
				},
			},
			Containers: []corev1.Container{
				{
					Name:  "log-collector",
					Image: utils.GetComponentImage(utils.OPERATOR),
					Command: []string{
						"compliance-operator", "resultscollector",
						"--arf-file=/reports/report-arf.xml",
						"--results-file=/reports/report.xml",
						"--exit-code-file=/reports/exit_code",
						"--oscap-output-file=/reports/cmd_output",
						"--warnings-output-file=/reports/warning_output",
						"--config-map-name=" + cmName,
						"--owner=" + scanInstance.Name,
						"--namespace=" + scanInstance.Namespace,
						"--resultserveruri=" + getResultServerURI(scanInstance),
						"--tls-client-cert=/etc/pki/tls/tls.crt",
						"--tls-client-key=/etc/pki/tls/tls.key",
						"--tls-ca=/etc/pki/tls/ca.crt",
						"--disable-raw-upload=" + getDisableRawResultUploadValue(scanInstance),
					},
					ImagePullPolicy: corev1.PullAlways,
					SecurityContext: &corev1.SecurityContext{
						AllowPrivilegeEscalation: &falseP,
						ReadOnlyRootFilesystem:   &trueP,
						Capabilities: &corev1.Capabilities{
							Drop: []corev1.Capability{"ALL"},
						},
					},
					Resources: corev1.ResourceRequirements{
						Requests: corev1.ResourceList{
							corev1.ResourceMemory: resource.MustParse("20Mi"),
							corev1.ResourceCPU:    resource.MustParse("10m"),
						},
						Limits: corev1.ResourceList{
							corev1.ResourceMemory: resource.MustParse("100Mi"),
							corev1.ResourceCPU:    resource.MustParse("100m"),
						},
					},
					VolumeMounts: getLogCollectorVolumeMounts(scanInstance),
				},
				{
					Name:    OpenSCAPScanContainerName,
					Image:   utils.GetComponentImage(utils.OPENSCAP),
					Command: []string{OpenScapScriptPath},
					SecurityContext: &corev1.SecurityContext{
						AllowPrivilegeEscalation: &falseP,
						ReadOnlyRootFilesystem:   &trueP,
						Capabilities: &corev1.Capabilities{
							Drop: []corev1.Capability{"ALL"},
						},
					},
					Resources: corev1.ResourceRequirements{
						Requests: corev1.ResourceList{
							corev1.ResourceMemory: resource.MustParse("50Mi"),
							corev1.ResourceCPU:    resource.MustParse("10m"),
						},
						// NOTE: when changing the default limits, remember to also change the
						// doc text in the CRD.
						Limits: *scanLimits(scanInstance, "500Mi", "100m"),
					},
					VolumeMounts: []corev1.VolumeMount{
						{
							Name:      "report-dir",
							MountPath: "/reports",
						},
						{
							Name:      "content-dir",
							MountPath: "/content",
							ReadOnly:  true,
						},
						{
							Name:      "tmp-dir",
							MountPath: "/tmp",
						},
						{
							Name:      "fetch-results",
							MountPath: PlatformScanDataRoot,
						},
						{
							Name:      scriptCmForScan(scanInstance),
							MountPath: "/scripts",
							ReadOnly:  true,
						},
					},
					EnvFrom: []corev1.EnvFromSource{
						{
							ConfigMapRef: &corev1.ConfigMapEnvSource{
								LocalObjectReference: corev1.LocalObjectReference{
									Name: envCmForPlatformScan(scanInstance),
								},
							},
						},
					},
				},
			},
			NodeSelector:  r.schedulingInfo.Selector,
			Tolerations:   r.schedulingInfo.Tolerations,
			RestartPolicy: corev1.RestartPolicyOnFailure,
			Volumes:       getPlatformScannerPodVolumes(scanInstance),
		},
	}
}

func (r *ReconcileComplianceScan) deleteScanPods(instance *compv1alpha1.ComplianceScan, nodes []corev1.Node, logger logr.Logger) error {
	// On each eligible node..
	for idx := range nodes {
		node := &nodes[idx]
		logger.Info("Deleting a pod on node", "node", node.Name)
		pod := newScanPodForNode(instance, node, logger)

		// Delete it.
		err := r.Client.Delete(context.TODO(), pod)
		if errors.IsNotFound(err) {
			logger.Info("Pod is already gone. This is fine.", "Pod.Name", pod.Name)
		} else if err != nil {
			log.Error(err, "Failed to delete a pod", "Pod.Name", pod.Name)
			return err
		} else {
			logger.Info("deleted pod", "Pod.Name", pod.Name)
		}
	}

	return nil
}

func (r *ReconcileComplianceScan) reconcileTailoring(instance *compv1alpha1.ComplianceScan, pod *corev1.Pod, logger logr.Logger) error {
	if instance.Spec.TailoringConfigMap.Name == "" {
		return common.NewNonRetriableCtrlError("tailoring config map name can't be empty")
	}
	name := instance.Spec.TailoringConfigMap.Name
	ns := instance.Namespace

	tailoringCMName := getReplicatedTailoringCMName(instance.Name)
	tailoringCMNamespace := common.GetComplianceOperatorNamespace()
	if err := r.reconcileReplicatedTailoringConfigMap(instance, name, ns, tailoringCMName, tailoringCMNamespace, instance.Name, logger); err != nil {
		return err
	}

	if err := r.addTailoringVolume(tailoringCMName, pod); err != nil {
		return err
	}
	return nil
}

func (r *ReconcileComplianceScan) addTailoringVolume(name string, pod *corev1.Pod) error {
	mode := int32(0644)

	pod.Spec.Volumes = append(pod.Spec.Volumes, corev1.Volume{
		Name: tailoringCMVolumeName,
		VolumeSource: corev1.VolumeSource{
			ConfigMap: &corev1.ConfigMapVolumeSource{
				LocalObjectReference: corev1.LocalObjectReference{
					Name: name,
				},
				DefaultMode: &mode,
			},
		},
	})

	// The index is used to get the references instead of copies
	for i := range pod.Spec.InitContainers {
		container := &pod.Spec.InitContainers[i]
		if container.Name == PlatformScanResourceCollectorName {
			container.VolumeMounts = append(container.VolumeMounts, corev1.VolumeMount{
				Name:      tailoringCMVolumeName,
				MountPath: OpenScapTailoringDir,
				ReadOnly:  true,
			})
		}
	}

	for i := range pod.Spec.Containers {
		container := &pod.Spec.Containers[i]
		if container.Name == OpenSCAPScanContainerName {
			container.VolumeMounts = append(container.VolumeMounts, corev1.VolumeMount{
				Name:      tailoringCMVolumeName,
				MountPath: OpenScapTailoringDir,
				ReadOnly:  true,
			})
		}
	}

	return nil
}

func (r *ReconcileComplianceScan) deletePlatformScanPod(instance *compv1alpha1.ComplianceScan, logger logr.Logger) error {
	logger.Info("Deleting the platform scan pod for instance", "instance", instance.Name)
	pod := r.newPlatformScanPod(instance, logger)

	err := r.Client.Delete(context.TODO(), pod)
	if errors.IsNotFound(err) {
		logger.Info("Pod is already gone. This is fine.", "pod", pod)
	} else if err != nil {
		log.Error(err, "Failed to delete a pod", "pod", pod)
		return err
	} else {
		logger.Info("deleted pod", "pod", pod)
	}

	return nil
}

// Creates a private configmap that'll only be used by this operator.
func (r *ReconcileComplianceScan) reconcileReplicatedTailoringConfigMap(scan *compv1alpha1.ComplianceScan, origName, origNs, privName, privNs, scanName string, logger logr.Logger) error {
	logger.Info("Reconciling Tailoring ConfigMap", "ConfigMap.Name", origName, "ConfigMap.Namespace", origNs)

	origCM := &corev1.ConfigMap{}
	origKey := types.NamespacedName{Name: origName, Namespace: origNs}
	err := r.Client.Get(context.TODO(), origKey, origCM)
	// Tailoring ConfigMap not found
	if err != nil && errors.IsNotFound(err) {
		// We previously had dealt with this issue, just requeue
		if strings.HasPrefix(scan.Status.ErrorMessage, tailoringNotFoundPrefix) {
			return common.NewRetriableCtrlErrorWithCustomHandler(func() (reconcile.Result, error) {
				// A ConfigMap not being found might be a temporary issue
				if r.Recorder != nil {
					r.Recorder.Eventf(
						scan, corev1.EventTypeWarning, "TailoringError",
						"Tailoring ConfigMap '%s' not found", origKey,
					)
				}

				return reconcile.Result{RequeueAfter: requeueAfterDefault, Requeue: true}, nil
			}, "Tailoring ConfigMap not found")
		}
		// A ConfigMap not being found might be a temporary issue (update and let the reconcile loop requeue)
		return common.NewRetriableCtrlErrorWithCustomHandler(func() (reconcile.Result, error) {
			if r.Recorder != nil {
				r.Recorder.Eventf(
					scan, corev1.EventTypeWarning, "TailoringError",
					"Tailoring ConfigMap '%s' not found", origKey,
				)
			}

			log.Info("Updating scan status due to missing Tailoring ConfigMap")
			scanCopy := scan.DeepCopy()
			scanCopy.Status.ErrorMessage = tailoringNotFoundPrefix + err.Error()
			scanCopy.Status.Result = compv1alpha1.ResultError
			if updateerr := r.Client.Status().Update(context.TODO(), scanCopy); updateerr != nil {
				log.Error(updateerr, "Failed to update a scan")
				return reconcile.Result{}, updateerr
			}
			return reconcile.Result{RequeueAfter: requeueAfterDefault, Requeue: true}, nil
		}, "Tailoring ConfigMap not found")
	} else if err != nil {
		log.Error(err, "Failed to get spec tailoring ConfigMap", "ConfigMap.Name", origName, "ConfigMap.Namespace", origNs)
		return err
	} else if scan.Status.Result == compv1alpha1.ResultError {
		// We had an error caused by a previously not found configmap. Let's remove it
		if strings.HasPrefix(scan.Status.ErrorMessage, tailoringNotFoundPrefix) {
			return common.NewRetriableCtrlErrorWithCustomHandler(func() (reconcile.Result, error) {
				log.Info("Updating scan status since Tailoring ConfigMap was now found")
				scanCopy := scan.DeepCopy()
				scanCopy.Status.ErrorMessage = ""
				scanCopy.Status.Result = compv1alpha1.ResultNotAvailable
				if updateerr := r.Client.Status().Update(context.TODO(), scanCopy); updateerr != nil {
					log.Error(updateerr, "Failed to update a scan")
					return reconcile.Result{}, updateerr
				}
				return reconcile.Result{RequeueAfter: requeueAfterDefault, Requeue: true}, nil
			}, "Tailoring ConfigMap previously not found, was now found")
		}
	}

	origData, ok := origCM.Data["tailoring.xml"]
	if !ok {
		return common.NewNonRetriableCtrlError("Tailoring ConfigMap missing `tailoring.xml` key")
	}
	if origData == "" {
		return common.NewNonRetriableCtrlError("Tailoring ConfigMap's key `tailoring.xml` is empty")
	}

	privCM := &corev1.ConfigMap{}
	privKey := types.NamespacedName{Name: privName, Namespace: privNs}
	err = r.Client.Get(context.TODO(), privKey, privCM)
	if err != nil && errors.IsNotFound(err) {
		newCM := &corev1.ConfigMap{}
		newCM.SetName(privName)
		newCM.SetNamespace(privNs)
		if newCM.Labels == nil {
			newCM.Labels = make(map[string]string)
		}
		newCM.Labels[compv1alpha1.ComplianceScanLabel] = scanName
		newCM.Labels[compv1alpha1.ScriptLabel] = ""
		if newCM.Data == nil {
			newCM.Data = make(map[string]string)
		}
		newCM.Data["tailoring.xml"] = origData
		logger.Info("Creating private Tailoring ConfigMap", "ConfigMap.Name", privName, "ConfigMap.Namespace", privNs)
		err = r.Client.Create(context.TODO(), newCM)
		// Ignore error if CM already exists
		if err != nil && !errors.IsAlreadyExists(err) {
			return nil
		}
		return err
	} else if err != nil {
		log.Error(err, "Failed to get private tailoring ConfigMap", "ConfigMap.Name", privName, "ConfigMap.Namespace", privNs)
		return err
	}
	privData, _ := privCM.Data["tailoring.xml"]

	// privCM needs update
	if privData != origData {
		updatedCM := privCM.DeepCopy()
		if updatedCM.Data == nil {
			updatedCM.Data = make(map[string]string)
		}
		if updatedCM.Labels == nil {
			updatedCM.Labels = make(map[string]string)
		}
		updatedCM.Labels[compv1alpha1.ComplianceScanLabel] = scanName
		updatedCM.Labels[compv1alpha1.ScriptLabel] = ""
		updatedCM.Data["tailoring.xml"] = origData
		logger.Info("Updating private Tailoring ConfigMap", "ConfigMap.Name", privName, "ConfigMap.Namespace", privNs)
		return r.Client.Update(context.TODO(), updatedCM)
	}
	logger.Info("Private Tailoring ConfigMap is up-to-date", "ConfigMap.Name", privName, "ConfigMap.Namespace", privNs)
	return nil
}

func checkScanUnknownError(cm *corev1.ConfigMap) error {
	exitcode, ok := cm.Data["exit-code"]
	if !ok {
		return fmt.Errorf("the ConfigMap '%s' was missing 'exit-code'", cm.Name)
	}

	if exitcode != common.OpenSCAPExitCodeCompliant && exitcode != common.OpenSCAPExitCodeNonCompliant && exitcode != common.PodUnschedulableExitCode {
		errorMsg, ok := cm.Data["error-msg"]
		if ok {
			return fmt.Errorf(errorMsg)
		}
		return fmt.Errorf("the ConfigMap '%s' was missing 'error-msg' despite exitcode %s", cm.Name, exitcode)
	}

	return nil
}

func scanResultReady(cm *corev1.ConfigMap) bool {
	if cm.Annotations == nil {
		return false
	}

	_, ok := cm.Annotations[compv1alpha1.CmScanResultAnnotation]
	if !ok {
		return false
	}

	return true
}

func getScanResult(cm *corev1.ConfigMap) (compv1alpha1.ComplianceScanStatusResult, error) {
	strResult, ok := cm.Annotations[compv1alpha1.CmScanResultAnnotation]
	if !ok {
		return compv1alpha1.ResultError, fmt.Errorf("the ConfigMap '%s' annotation was missing the result key", cm.Name)
	}

	switch strResult {
	case string(compv1alpha1.ResultCompliant):
		return compv1alpha1.ResultCompliant, nil
	case string(compv1alpha1.ResultNonCompliant):
		return compv1alpha1.ResultNonCompliant, nil
	case string(compv1alpha1.ResultNotApplicable):
		return compv1alpha1.ResultNotApplicable, nil
	default:
		break
	}

	errMsg, ok := cm.Annotations[compv1alpha1.CmScanResultErrMsg]
	if !ok {
		errMsg = fmt.Sprintf("Undefined error in ConfigMap %s", cm.Name)
	}
	return compv1alpha1.ResultError, fmt.Errorf(errMsg)
}

func getReplicatedTailoringCMName(instanceName string) string {
	return utils.DNSLengthName("tp-", "tp-%s", instanceName)
}
