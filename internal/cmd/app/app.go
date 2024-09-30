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
	"net/http"
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
	"github.com/cert-manager/openshift-routes/internal/crcontroller"
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

			// Check if v1 cert-manager Certificates / CertificateRequests exist in the API server
			apiServerHasCertificates := false
			apiServerHasCertificateRequests := false

			cmResources, err := cl.Discovery().ServerResourcesForGroupVersion("cert-manager.io/v1")
			if err != nil {
				return fmt.Errorf("couldn't check if cert-manager.io/v1 exists in the kubernetes API: %w", err)
			}

			for _, r := range cmResources.APIResources {
				if apiServerHasCertificates && apiServerHasCertificateRequests {
					break
				}

				if r.Kind == "Certificate" {
					apiServerHasCertificates = true
					continue
				}

				if r.Kind == "CertificateRequest" {
					apiServerHasCertificateRequests = true
					continue
				}
			}

			if !apiServerHasCertificates || !apiServerHasCertificateRequests {
				return fmt.Errorf("connected to the Kubernetes API, but the cert-manager v1 CRDs do not appear to be installed: has Certificates=%v, has CertificateRequests=%v", apiServerHasCertificates, apiServerHasCertificateRequests)
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

			mgr, err := ctrl.NewManager(opts.RestConfig, ctrl.Options{
				Scheme:                        combinedScheme,
				Logger:                        logger,
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

			switch opts.IssuanceMode {
			case options.CertificateIssuanceMode:
				err := controller.AddToManager(mgr, opts)
				if err != nil {
					return fmt.Errorf("could not add certificate-based route controller to manager: %w", err)
				}

				opts.Logr.V(5).Info("starting certificate-based controller")

			case options.CertificateRequestIssuanceMode:
				err := crcontroller.AddToManager(mgr, opts)
				if err != nil {
					return fmt.Errorf("could not add certificate request-based route controller to manager: %w", err)
				}

				opts.Logr.V(5).Info("starting certificate request-based controller")

			default:
				return fmt.Errorf("invalid issuance mode %q", opts.IssuanceMode)
			}

			return mgr.Start(ctrl.SetupSignalHandler())
		},
	}

	opts.Prepare(cmd)
	return cmd
}
