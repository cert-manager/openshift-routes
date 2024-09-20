/*
Copyright 2022 The cert-manager Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package app

import (
	"context"
	"fmt"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"
	"net/http"
	"os"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"strings"
	"time"

	cmscheme "github.com/cert-manager/cert-manager/pkg/client/clientset/versioned/scheme"
	routescheme "github.com/openshift/client-go/route/clientset/versioned/scheme"
	"github.com/spf13/cobra"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	clientcorev1 "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/metrics/server"

	"github.com/cert-manager/openshift-routes/internal/cmd/app/options"
	"github.com/cert-manager/openshift-routes/internal/controller"
)

func Command() *cobra.Command {
	opts := options.New()
	cmd := &cobra.Command{
		Use:   "cert-manager-openshift-routes",
		Short: "cert-manager support for openshift routes",
		Long:  "cert-manager support for openshift routes",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := opts.Complete(); err != nil {
				return err
			}

			cl, err := kubernetes.NewForConfig(opts.RestConfig)
			if err != nil {
				return fmt.Errorf("error creating kubernetes client: %w", err)
			}

			// Check if v1 Openshift Routes exist in the API server
			apiServerHasRoutes := false
			routeResources, err := cl.Discovery().ServerResourcesForGroupVersion("route.openshift.io/v1")
			if err != nil {
				return fmt.Errorf("couldn't check if route.openshift.io/v1 exists in the kubernetes API: %w", err)
			}
			for _, r := range routeResources.APIResources {
				if r.Kind == "Route" {
					apiServerHasRoutes = true
					break
				}
			}
			if !apiServerHasRoutes {
				return fmt.Errorf("connected to the Kubernetes API, but the Openshift Route v1 CRD does not appear to be installed")
			}

			// Check if v1 cert-manager CertificateRequests exist in the API server
			apiServerHasCertificateRequests := false
			cmResources, err := cl.Discovery().ServerResourcesForGroupVersion("cert-manager.io/v1")
			if err != nil {
				return fmt.Errorf("couldn't check if cert-manager.io/v1 exists in the kubernetes API: %w", err)
			}
			for _, r := range cmResources.APIResources {
				if r.Kind == "CertificateRequest" {
					apiServerHasCertificateRequests = true
					break
				}
			}
			if !apiServerHasCertificateRequests {
				return fmt.Errorf("connected to the Kubernetes API, but the cert-manager v1 CRDs do not appear to be installed")
			}

			logger := opts.Logr.WithName("controller-manager")
			eventBroadcaster := record.NewBroadcaster()
			eventBroadcaster.StartLogging(func(format string, args ...interface{}) {
				logger.V(3).Info(fmt.Sprintf(format, args...))
			})
			eventBroadcaster.StartRecordingToSink(&clientcorev1.EventSinkImpl{Interface: cl.CoreV1().Events("")})

			combinedScheme := runtime.NewScheme()
			if err := cmscheme.AddToScheme(combinedScheme); err != nil {
				return err
			}
			if err := routescheme.AddToScheme(combinedScheme); err != nil {
				return err
			}

			opts.EventRecorder = eventBroadcaster.NewRecorder(combinedScheme, corev1.EventSource{Component: "cert-manager-openshift-routes"})

			watchNamespace, err := getWatchNamespace()
			if err != nil {
				return fmt.Errorf("unable to get WATCH_NAMESPACE,the manager will watch and manage resources in all namespaces, err: %w", err)
			}

			// Add support for MultiNamespace set in WATCH_NAMESPACE (e.g ns1,ns2)
			cacheConfig := map[string]cache.Config{}
			if strings.Contains(watchNamespace, ",") {
				logger.V(3).Info("manager set up with multiple namespaces", "namespaces", watchNamespace)
				for _, ns := range strings.Split(watchNamespace, ",") {
					cacheConfig[ns] = cache.Config{
						LabelSelector: labels.Everything(),
						FieldSelector: fields.Everything(),
					}
				}
			}

			mgr, err := ctrl.NewManager(opts.RestConfig, ctrl.Options{
				Scheme: combinedScheme,
				Logger: logger,
				Cache: cache.Options{
					DefaultNamespaces: cacheConfig,
				},
				LeaderElection:                opts.EnableLeaderElection,
				LeaderElectionID:              "cert-manager-openshift-routes",
				LeaderElectionNamespace:       opts.LeaderElectionNamespace,
				LeaderElectionResourceLock:    "leases",
				LeaderElectionReleaseOnCancel: true,
				ReadinessEndpointName:         opts.ReadyzPath,
				HealthProbeBindAddress:        fmt.Sprintf("[::]:%d", opts.ReadyzPort),
				Metrics: server.Options{
					BindAddress: fmt.Sprintf("[::]:%d", opts.MetricsPort),
				},
			})
			if err != nil {
				return fmt.Errorf("could not create controller manager: %w", err)
			}
			mgr.AddReadyzCheck("informers_synced", func(req *http.Request) error {
				// haven't got much time to wait in a readiness check
				ctx, cancel := context.WithTimeout(req.Context(), 2*time.Second)
				defer cancel()
				if mgr.GetCache().WaitForCacheSync(ctx) {
					return nil
				}
				return fmt.Errorf("informers not synced")
			})
			if err := controller.AddToManager(mgr, opts); err != nil {
				return fmt.Errorf("could not add route controller to manager: %w", err)
			}
			opts.Logr.V(5).Info("starting controller")
			return mgr.Start(ctrl.SetupSignalHandler())
		},
	}
	opts.Prepare(cmd)
	return cmd
}

// getWatchNamespace returns the Namespace the operator should be watching for changes
func getWatchNamespace() (string, error) {
	// WatchNamespaceEnvVar is the constant for env variable WATCH_NAMESPACE
	// which specifies the Namespace to watch.
	// An empty value means the operator is running with cluster scope.
	var watchNamespaceEnvVar = "WATCH_NAMESPACE"

	ns, found := os.LookupEnv(watchNamespaceEnvVar)
	if !found {
		return "", fmt.Errorf("%s must be set", watchNamespaceEnvVar)
	}
	return ns, nil
}
