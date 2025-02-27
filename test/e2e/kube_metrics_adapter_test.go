package e2e

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	rgclient "github.com/szuecs/routegroup-client"
	rgv1 "github.com/szuecs/routegroup-client/apis/zalando.org/v1"
	appsv1 "k8s.io/api/apps/v1"
	autoscaling "k8s.io/api/autoscaling/v2"
	corev1 "k8s.io/api/core/v1"
	netv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/kubernetes/test/e2e/framework"
	"k8s.io/kubernetes/test/e2e/framework/ingress"
	admissionapi "k8s.io/pod-security-admission/api"
)

// Test Scale down with custom metrics from an app's /metrics endpoint
// 1. Create a deployment with an hpa and more pods than needed. Then "deploy" it
// 2. Set the metrics "queue_count" of the app at startup
// 3. Observe if the HPA downscales
var _ = describe("[HPA] Horizontal pod autoscaling (scale resource: Custom Metrics from kube-metrics-adapter)", func() {
	f := framework.NewDefaultFramework("zalando-kube-metrics-adapter")
	f.NamespacePodSecurityEnforceLevel = admissionapi.LevelBaseline
	var cs kubernetes.Interface
	var rgcs rgclient.Interface
	var jig *ingress.TestJig

	const (
		DeploymentName = "sample-custom-metrics-autoscaling-e2e"
	)

	BeforeEach(func() {
		jig = ingress.NewIngressTestJig(f.ClientSet)
		cs = f.ClientSet

		// setup RouteGroup clientset
		config, err := framework.LoadConfig()
		framework.ExpectNoError(err)
		config.QPS = f.Options.ClientQPS
		config.Burst = f.Options.ClientBurst
		if f.Options.GroupVersion != nil {
			config.GroupVersion = f.Options.GroupVersion
		}
		rgcs, err = rgclient.NewClientset(config)
		framework.ExpectNoError(err)
	})

	It("should scale down with Custom Metric of type Pod from kube-metrics-adapter [CustomMetricsAutoscaling] [Zalando]", func() {
		initialReplicas := 2
		scaledReplicas := 1
		metricValue := int64(10)
		metricName := "queue-count"
		metricTarget := metricValue * 2

		tc := CustomMetricTestCase{
			framework:       f,
			kubeClient:      cs,
			initialReplicas: initialReplicas,
			scaledReplicas:  scaledReplicas,
			deployment:      simplePodMetricDeployment(DeploymentName, int32(initialReplicas), metricName, metricValue),
			hpa:             simplePodMetricHPA(DeploymentName, metricName, metricTarget),
		}
		tc.Run()

	})

	It("should scale down with Custom Metric of type Object from Skipper (networking.k8s.io) [Ingress] [CustomMetricsAutoscaling] [Zalando]", func() {
		hostName := fmt.Sprintf("%s-%d.%s", DeploymentName, time.Now().UTC().Unix(), E2EHostedZone())

		initialReplicas := 2
		scaledReplicas := 1
		metricValue := 10
		metricTarget := int64(metricValue) * 2
		labels := map[string]string{
			"application": DeploymentName,
		}
		port := 80
		targetPort := 8000
		targetUrl := hostName + "/metrics"
		ingress := createIngress(DeploymentName, hostName, f.Namespace.Name, "/", netv1.PathTypePrefix, labels, nil, port)
		tc := CustomMetricTestCase{
			framework:       f,
			kubeClient:      cs,
			jig:             jig,
			initialReplicas: initialReplicas,
			scaledReplicas:  scaledReplicas,
			deployment:      simplePodDeployment(DeploymentName, int32(initialReplicas)),
			ingress:         ingress,
			hpa:             rpsBasedHPA(DeploymentName, ingress.Name, "networking.k8s.io/v1", "Ingress", metricTarget),
			service:         createServiceTypeClusterIP(DeploymentName, labels, 80, targetPort),
			auxDeployments: []*appsv1.Deployment{
				createVegetaDeployment(targetUrl, metricValue),
			},
		}
		tc.Run()
	})

	It("should scale down with Custom Metric of type Object from Skipper [RouteGroup] [CustomMetricsAutoscaling] [Zalando]", func() {
		hostName := fmt.Sprintf("%s-%d.%s", DeploymentName, time.Now().UTC().Unix(), E2EHostedZone())

		initialReplicas := 2
		scaledReplicas := 1
		metricValue := 10
		metricTarget := int64(metricValue) * 2
		labels := map[string]string{
			"application": DeploymentName,
		}
		port := 80
		targetPort := 8000
		targetUrl := hostName + "/metrics"
		routegroup := createRouteGroup(DeploymentName, hostName, f.Namespace.Name, labels, nil, port)
		tc := CustomMetricTestCase{
			framework:       f,
			kubeClient:      cs,
			rgClient:        rgcs,
			jig:             jig,
			initialReplicas: initialReplicas,
			scaledReplicas:  scaledReplicas,
			deployment:      simplePodDeployment(DeploymentName, int32(initialReplicas)),
			routegroup:      routegroup,
			hpa:             rpsBasedHPA(DeploymentName, routegroup.Name, "zalando.org/v1", "RouteGroup", metricTarget),
			service:         createServiceTypeClusterIP(DeploymentName, labels, 80, targetPort),
			auxDeployments: []*appsv1.Deployment{
				createVegetaDeployment(targetUrl, metricValue),
			},
		}
		tc.Run()
	})

	It("should scale with external metric based on hostname RPS [CustomMetricsAutoscaling] [Zalando]", func() {
		hostName := fmt.Sprintf("%s-%d.%s", DeploymentName, time.Now().UTC().Unix(), E2EHostedZone())

		initialReplicas := 2
		scaledReplicas := 1
		metricValue := 10
		metricTarget := int64(metricValue) * 2
		labels := map[string]string{
			"application": DeploymentName,
		}
		port := 80
		targetPort := 8000
		targetUrl := hostName + "/metrics"
		routegroup := createRouteGroup(DeploymentName, hostName, f.Namespace.Name, labels, nil, port)
		tc := CustomMetricTestCase{
			framework:       f,
			kubeClient:      cs,
			rgClient:        rgcs,
			jig:             jig,
			initialReplicas: initialReplicas,
			scaledReplicas:  scaledReplicas,
			deployment:      simplePodDeployment(DeploymentName, int32(initialReplicas)),
			routegroup:      routegroup,
			hpa:             externalRPSHPA(DeploymentName, hostName, "100", metricTarget),
			service:         createServiceTypeClusterIP(DeploymentName, labels, 80, targetPort),
			auxDeployments: []*appsv1.Deployment{
				createVegetaDeployment(targetUrl, metricValue),
			},
		}
		tc.Run()
	})
})

type CustomMetricTestCase struct {
	framework       *framework.Framework
	hpa             *autoscaling.HorizontalPodAutoscaler
	kubeClient      kubernetes.Interface
	rgClient        rgclient.Interface
	jig             *ingress.TestJig
	deployment      *appsv1.Deployment
	initialReplicas int
	scaledReplicas  int
	ingress         *netv1.Ingress
	routegroup      *rgv1.RouteGroup
	service         *corev1.Service
	auxDeployments  []*appsv1.Deployment
}

func (tc *CustomMetricTestCase) Run() {
	By("By creating a deployment with an HPA and custom metrics Configured")
	ns := tc.framework.Namespace.Name

	// Create a MetricsExporter deployment
	_, err := tc.kubeClient.AppsV1().Deployments(ns).Create(context.TODO(), tc.deployment, metav1.CreateOptions{})
	framework.ExpectNoError(err)
	// Wait for the deployment to run
	waitForReplicas(tc.deployment.ObjectMeta.Name, tc.framework.Namespace.ObjectMeta.Name, tc.kubeClient, 15*time.Minute, tc.initialReplicas)

	for _, deployment := range tc.auxDeployments {
		_, err := tc.kubeClient.AppsV1().Deployments(ns).Create(context.TODO(), deployment, metav1.CreateOptions{})
		framework.ExpectNoError(err)
		// Wait for the deployment to run
		waitForReplicas(deployment.ObjectMeta.Name, tc.framework.Namespace.ObjectMeta.Name, tc.kubeClient, 15*time.Minute, int(*(deployment.Spec.Replicas)))
	}

	// Check if an Ingress needs to be created
	if tc.ingress != nil {
		// Create a Service for the Ingress
		_, err = tc.kubeClient.CoreV1().Services(ns).Create(context.TODO(), tc.service, metav1.CreateOptions{})
		framework.ExpectNoError(err)

		// Create an Ingress since RPS based scaling relies on it
		ingressCreate, err := tc.kubeClient.NetworkingV1().Ingresses(ns).Create(context.TODO(), tc.ingress, metav1.CreateOptions{})
		framework.ExpectNoError(err)

		_, err = tc.jig.WaitForIngressAddress(context.TODO(), tc.kubeClient, ns, ingressCreate.Name, 10*time.Minute)
		framework.ExpectNoError(err)

	}

	// check if a RouteGroup needs to be created
	if tc.routegroup != nil {
		// Create a Service for the RouteGroup
		_, err = tc.kubeClient.CoreV1().Services(ns).Create(context.TODO(), tc.service, metav1.CreateOptions{})
		framework.ExpectNoError(err)

		// Create a RouteGroup since RPS based scaling relies on it
		rgCreate, err := tc.rgClient.ZalandoV1().RouteGroups(ns).Create(context.TODO(), tc.routegroup, metav1.CreateOptions{})
		framework.ExpectNoError(err)

		_, err = waitForRouteGroup(tc.rgClient, rgCreate.Name, rgCreate.Namespace, 10*time.Minute)
		framework.ExpectNoError(err)
	}

	// Autoscale the deployment
	_, err = tc.kubeClient.AutoscalingV2().HorizontalPodAutoscalers(ns).Create(context.TODO(), tc.hpa, metav1.CreateOptions{})
	framework.ExpectNoError(err)

	waitForReplicas(tc.deployment.ObjectMeta.Name, tc.framework.Namespace.ObjectMeta.Name, tc.kubeClient, 15*time.Minute, tc.scaledReplicas)
}

func cleanDeploymentToScale(f *framework.Framework, kubeClient kubernetes.Interface, deployment *appsv1.Deployment) {
	if deployment != nil {
		// Can't do much if there's an error while deleting the deployment, or can we?
		_ = kubeClient.AppsV1().Deployments(f.Namespace.Name).Delete(context.TODO(), deployment.ObjectMeta.Name, metav1.DeleteOptions{})
	}
}

// CustomMetricContainerSpec allows to specify a config for simplePodMetricDeployment
// with multiple containers exporting different metrics.
type CustomMetricContainerSpec struct {
	Name        string
	MetricName  string
	MetricValue int64
}

// simplePodMetricDeployment is a Deployment of simple application that exports a metric of
// fixed value to kube-metrics-adapter in a loop.
func simplePodMetricDeployment(name string, replicas int32, metricName string, metricValue int64) *appsv1.Deployment {
	return podMetricDeployment(name, replicas,
		[]CustomMetricContainerSpec{
			{
				Name:        "metrics-exporter-e2e",
				MetricName:  metricName,
				MetricValue: metricValue,
			},
		})
}

// simplePodDeployment is a Deployment of an application that exposes an HTTP endpoint
func simplePodDeployment(name string, replicas int32) *appsv1.Deployment {
	podSpec := corev1.PodSpec{Containers: []corev1.Container{}}
	podSpec.Containers = append(podSpec.Containers, podContainerSpec(name))

	return &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
			Labels: map[string]string{
				"application": name,
			},
		},
		Spec: appsv1.DeploymentSpec{
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{"application": name},
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{
						"application": name,
					},
				},
				Spec: podSpec,
			},
			Replicas: &replicas,
		},
	}
}

// podMetricDeployment is a Deployment of an application that can expose
// an arbitrary amount of metrics of fixed value to kube-metrics-adapter in a loop. Each metric
// is exposed by a different container in one pod.
// The metric names and values are configured via the containers parameter.
func podMetricDeployment(name string, replicas int32, containers []CustomMetricContainerSpec) *appsv1.Deployment {
	podSpec := corev1.PodSpec{Containers: []corev1.Container{}}
	for _, containerSpec := range containers {
		podSpec.Containers = append(podSpec.Containers, podMetricContainerSpec(containerSpec))
	}

	return &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
			Labels: map[string]string{
				"application": name,
			},
		},
		Spec: appsv1.DeploymentSpec{
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{"application": name},
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{
						"application": name,
					},
				},
				Spec: podSpec,
			},
			Replicas: &replicas,
		},
	}
}

func podContainerSpec(name string) corev1.Container {
	return corev1.Container{
		Name:  name,
		Image: "container-registry.zalando.net/teapot/sample-custom-metrics-autoscaling:main-5",
		Ports: []corev1.ContainerPort{{ContainerPort: 8000, Protocol: "TCP"}},
		Resources: corev1.ResourceRequirements{
			Limits: map[corev1.ResourceName]resource.Quantity{
				corev1.ResourceMemory: resource.MustParse("300Mi"),
			},
			Requests: map[corev1.ResourceName]resource.Quantity{
				corev1.ResourceCPU:    resource.MustParse("10m"),
				corev1.ResourceMemory: resource.MustParse("300Mi"),
			},
		},
	}
}

func podMetricContainerSpec(container CustomMetricContainerSpec) corev1.Container {
	return corev1.Container{
		Name:  container.Name,
		Image: "container-registry.zalando.net/teapot/sample-custom-metrics-autoscaling:main-5",
		Ports: []corev1.ContainerPort{{ContainerPort: 8000, Protocol: "TCP"}},
		Resources: corev1.ResourceRequirements{
			Limits: map[corev1.ResourceName]resource.Quantity{
				corev1.ResourceMemory: resource.MustParse("300Mi"),
			},
			Requests: map[corev1.ResourceName]resource.Quantity{
				corev1.ResourceCPU:    resource.MustParse("10m"),
				corev1.ResourceMemory: resource.MustParse("300Mi"),
			},
		},
		Args: []string{
			"-fake-queue-length", strconv.FormatInt(container.MetricValue, 10),
		},
	}
}

func simplePodMetricHPA(deploymentName string, metricName string, metricTarget int64) *autoscaling.HorizontalPodAutoscaler {
	return podMetricHPA(deploymentName, map[string]int64{metricName: metricTarget})
}

func podMetricHPA(deploymentName string, metricTargets map[string]int64) *autoscaling.HorizontalPodAutoscaler {
	var minReplicas int32 = 1
	metrics := []autoscaling.MetricSpec{}
	metricName := ""
	for metric, target := range metricTargets {
		metrics = append(metrics, autoscaling.MetricSpec{
			Type: autoscaling.PodsMetricSourceType,
			Pods: &autoscaling.PodsMetricSource{
				Metric: autoscaling.MetricIdentifier{
					Name: metric,
				},
				Target: autoscaling.MetricTarget{
					Type:         autoscaling.AverageValueMetricType,
					AverageValue: resource.NewQuantity(target, resource.DecimalSI),
				},
			},
		})
		metricName = metric
	}
	return &autoscaling.HorizontalPodAutoscaler{
		ObjectMeta: metav1.ObjectMeta{
			Name: "custom-metrics-pods-hpa",
			Annotations: map[string]string{
				strings.Join([]string{"metric-config.pods", metricName, "json-path/json-key"}, "."): "$.queue.length",
				strings.Join([]string{"metric-config.pods", metricName, "json-path/path"}, "."):     "/metrics",
				strings.Join([]string{"metric-config.pods", metricName, "json-path/port"}, "."):     "8000",
			},
			Labels: map[string]string{
				"application": deploymentName,
			},
		},
		Spec: autoscaling.HorizontalPodAutoscalerSpec{
			Metrics:     metrics,
			MaxReplicas: 3,
			MinReplicas: &minReplicas,
			ScaleTargetRef: autoscaling.CrossVersionObjectReference{
				APIVersion: "apps/v1",
				Kind:       "Deployment",
				Name:       deploymentName,
			},
		},
	}
}

func externalRPSHPA(deploymentName, host, weight string, target int64) *autoscaling.HorizontalPodAutoscaler {
	return externalHPA(
		deploymentName,
		map[string]int64{"foo": target},
		map[string]string{
			"metric-config.external.foo.requests-per-second/hostnames": host,
			"metric-config.external.foo.requests-per-second/weight":    weight,
		},
	)
}

func externalHPA(deploymentName string, metricNameTargets map[string]int64, annotations map[string]string) *autoscaling.HorizontalPodAutoscaler {
	var minReplicas int32 = 1
	metrics := []autoscaling.MetricSpec{}
	for metricName, target := range metricNameTargets {
		metrics = append(metrics, autoscaling.MetricSpec{
			Type: autoscaling.ExternalMetricSourceType,
			External: &autoscaling.ExternalMetricSource{
				Metric: autoscaling.MetricIdentifier{
					Name: metricName,
					Selector: &metav1.LabelSelector{
						MatchLabels: map[string]string{"type": "requests-per-second"},
					},
				},
				Target: autoscaling.MetricTarget{
					Type:         autoscaling.AverageValueMetricType,
					AverageValue: resource.NewQuantity(target, resource.DecimalSI),
				},
			},
		})
	}

	return &autoscaling.HorizontalPodAutoscaler{
		ObjectMeta: metav1.ObjectMeta{
			Name: "custom-metrics-pods-hpa",
			Labels: map[string]string{
				"application": deploymentName,
			},
			Annotations: annotations,
		},
		Spec: autoscaling.HorizontalPodAutoscalerSpec{
			Metrics:     metrics,
			MaxReplicas: 3,
			MinReplicas: &minReplicas,
			ScaleTargetRef: autoscaling.CrossVersionObjectReference{
				APIVersion: "apps/v1",
				Kind:       "Deployment",
				Name:       deploymentName,
			},
		},
	}
}

func rpsBasedHPA(deploymentName, name, apiVersion, kind string, metricTarget int64) *autoscaling.HorizontalPodAutoscaler {
	return podHPA(deploymentName, name, apiVersion, kind, map[string]int64{"requests-per-second": metricTarget})
}

func podHPA(deploymentName, name, apiVersion, kind string, metricTargets map[string]int64) *autoscaling.HorizontalPodAutoscaler {
	var minReplicas int32 = 1
	metrics := []autoscaling.MetricSpec{}
	for metric, target := range metricTargets {
		metrics = append(metrics, autoscaling.MetricSpec{
			Type: autoscaling.ObjectMetricSourceType,
			Object: &autoscaling.ObjectMetricSource{
				DescribedObject: autoscaling.CrossVersionObjectReference{
					APIVersion: apiVersion,
					Kind:       kind,
					Name:       name,
				},
				Metric: autoscaling.MetricIdentifier{
					Name: metric,
				},
				Target: autoscaling.MetricTarget{
					Type:         autoscaling.AverageValueMetricType,
					AverageValue: resource.NewQuantity(target, resource.DecimalSI),
				},
			},
		})
	}

	return &autoscaling.HorizontalPodAutoscaler{
		ObjectMeta: metav1.ObjectMeta{
			Name: "custom-metrics-pods-hpa",
			Labels: map[string]string{
				"application": deploymentName,
			},
		},
		Spec: autoscaling.HorizontalPodAutoscalerSpec{
			Metrics:     metrics,
			MaxReplicas: 3,
			MinReplicas: &minReplicas,
			ScaleTargetRef: autoscaling.CrossVersionObjectReference{
				APIVersion: "apps/v1",
				Kind:       "Deployment",
				Name:       deploymentName,
			},
		},
	}
}
