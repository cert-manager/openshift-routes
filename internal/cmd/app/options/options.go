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

package options

import (
	"flag"
	"fmt"
	"strings"

	"github.com/go-logr/logr"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/record"
	cliflag "k8s.io/component-base/cli/flag"
	"k8s.io/klog/v2"
	"k8s.io/klog/v2/klogr"
)

const (
	CertificateIssuanceMode        = "certificate"
	CertificateRequestIssuanceMode = "certificaterequest"

	defaultIssuanceMode = CertificateIssuanceMode
)

// Options is the main configuration struct for cert-manager-openshift-routes
type Options struct {
	EventRecorder record.EventRecorder

	// ReadyzPort is the port to serve the readiness check on
	ReadyzPort int
	// ReadyzPath is the path to serve the readiness check on
	ReadyzPath string

	// MetricsPort is the port to serve prometheus metrics on
	MetricsPort int

	// EnableLeaderElection determines whether to use leader election
	EnableLeaderElection bool

	// LeaderElectionNamespace is the namespace to create Leader Election Resources
	LeaderElectionNamespace string

	// Logr is the shared base logr.Logger
	Logr logr.Logger

	// RestConfig is the Kubernetes config
	RestConfig *rest.Config

	// IssuanceMode switches between using Certificates and CertificateRequests
	// to issue certs for routes
	IssuanceMode string

	logLevel        string
	kubeConfigFlags *genericclioptions.ConfigFlags
}

func New() *Options {
	return new(Options)
}

func (o *Options) Prepare(cmd *cobra.Command) *Options {
	o.addFlags(cmd)
	return o
}

func (o *Options) Complete() error {
	klog.InitFlags(nil)
	log := klogr.New()
	if err := flag.Set("v", o.logLevel); err != nil {
		return err
	}
	o.Logr = log.WithName("cert-manager-openshift-routes")

	var err error
	o.RestConfig, err = o.kubeConfigFlags.ToRESTConfig()
	if err != nil {
		return fmt.Errorf("failed to build kubernetes rest config: %s", err)
	}

	originalIssuanceMode := o.IssuanceMode

	if o.IssuanceMode == "" {
		o.IssuanceMode = defaultIssuanceMode
	}

	o.IssuanceMode = strings.ToLower(o.IssuanceMode)
	o.IssuanceMode = strings.TrimSuffix(o.IssuanceMode, "s")

	if o.IssuanceMode != CertificateIssuanceMode && o.IssuanceMode != CertificateRequestIssuanceMode {
		return fmt.Errorf("invalid issuance mode %q; must be either '%s' or '%s'", originalIssuanceMode, CertificateIssuanceMode, CertificateRequestIssuanceMode)
	}

	return nil
}

func (o *Options) addFlags(cmd *cobra.Command) {
	var nfs cliflag.NamedFlagSets

	o.addAppFlags(nfs.FlagSet("App"))
	o.kubeConfigFlags = genericclioptions.NewConfigFlags(true)
	o.kubeConfigFlags.AddFlags(nfs.FlagSet("Kubernetes"))

	usageFmt := "Usage:\n  %s\n"
	cmd.SetUsageFunc(func(cmd *cobra.Command) error {
		fmt.Fprintf(cmd.OutOrStderr(), usageFmt, cmd.UseLine())
		cliflag.PrintSections(cmd.OutOrStderr(), nfs, 0)
		return nil
	})

	cmd.SetHelpFunc(func(cmd *cobra.Command, args []string) {
		fmt.Fprintf(cmd.OutOrStdout(), "%s\n\n"+usageFmt, cmd.Long, cmd.UseLine())
		cliflag.PrintSections(cmd.OutOrStdout(), nfs, 0)
	})

	fs := cmd.Flags()
	for _, f := range nfs.FlagSets {
		fs.AddFlagSet(f)
	}
}

func (o *Options) addAppFlags(fs *pflag.FlagSet) {
	fs.StringVarP(&o.logLevel,
		"log-level", "v", "1",
		"Log level (1-5).")

	fs.IntVar(&o.ReadyzPort,
		"readiness-probe-port", 6060,
		"Port to expose the readiness probe.")

	fs.StringVar(&o.ReadyzPath,
		"readiness-probe-path", "/readyz",
		"HTTP path to expose the readiness probe server.")

	fs.IntVar(&o.MetricsPort,
		"metrics-port", 9402,
		"Port to expose Prometheus metrics on 0.0.0.0 on path '/metrics'.")

	fs.BoolVar(&o.EnableLeaderElection,
		"enable-leader-election", true,
		"Whether to enable leader election on the controller.")

	fs.StringVar(&o.LeaderElectionNamespace,
		"leader-election-namespace", "cert-manager",
		"Namespace to create leader election resources in.")

	fs.StringVar(&o.IssuanceMode, "issuance-mode", defaultIssuanceMode,
		fmt.Sprintf("How certificates should be requested. Either '%s' or '%s'", CertificateIssuanceMode, CertificateRequestIssuanceMode))
}
