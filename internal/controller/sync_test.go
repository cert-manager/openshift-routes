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

package controller

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"sort"
	"strconv"
	"testing"
	"time"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	utilpki "github.com/cert-manager/cert-manager/pkg/util/pki"
	routev1 "github.com/openshift/api/route/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/record"
)

func TestRoute_hasValidCertificate(t *testing.T) {
	// set up some cert/key pairs for tests cases
	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	ecdsaKeyPEM, err := utilpki.EncodePKCS8PrivateKey(ecdsaKey)
	require.NoError(t, err)
	anotherEcdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	anotherEcdsaKeyPEM, err := utilpki.EncodePKCS8PrivateKey(anotherEcdsaKey)
	require.NoError(t, err)
	certTemplate := &x509.Certificate{
		SignatureAlgorithm:    x509.ECDSAWithSHA256,
		PublicKeyAlgorithm:    x509.ECDSA,
		Version:               0,
		SerialNumber:          big.NewInt(12345678),
		Issuer:                pkix.Name{CommonName: "test-cert"},
		Subject:               pkix.Name{CommonName: "test-cert"},
		NotBefore:             time.Now().Add(-time.Hour * 24 * 30),
		NotAfter:              time.Now().Add(time.Hour * 24 * 61),
		KeyUsage:              x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        false,
		DNSNames:              []string{"some-host.some-domain.tld"},
	}
	validEcdsaCert, err := x509.CreateCertificate(rand.Reader, certTemplate, certTemplate, ecdsaKey.Public(), ecdsaKey)
	require.NoError(t, err)
	validEcdsaCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: validEcdsaCert})
	certTemplate.NotAfter = time.Now().Add(time.Hour * 24)
	expiringSoonEcdsaCert, err := x509.CreateCertificate(rand.Reader, certTemplate, certTemplate, ecdsaKey.Public(), ecdsaKey)
	require.NoError(t, err)
	expiringSoonEcdsaCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: expiringSoonEcdsaCert})

	tests := []struct {
		name         string
		route        *routev1.Route
		want         bool
		wantedEvents []string
	}{
		{
			name: "valid and up-to-date ecdsa cert is OK",
			route: generateRouteStatus(&routev1.Route{
				ObjectMeta: metav1.ObjectMeta{
					Name:              "some-route",
					Namespace:         "some-namespace",
					CreationTimestamp: metav1.Time{Time: time.Now().Add(-time.Hour * 24 * 30)},
					Annotations:       map[string]string{cmapi.IssuerNameAnnotationKey: "some-issuer"},
				},
				Spec: routev1.RouteSpec{
					Host: "some-host.some-domain.tld",
					TLS: &routev1.TLSConfig{
						Termination:                   routev1.TLSTerminationEdge,
						Certificate:                   string(validEcdsaCertPEM),
						Key:                           string(ecdsaKeyPEM),
						CACertificate:                 string(validEcdsaCertPEM),
						InsecureEdgeTerminationPolicy: routev1.InsecureEdgeTerminationPolicyRedirect,
					},
				},
			},
				true),
			want:         true,
			wantedEvents: nil,
		},
		{
			name: "route with renew-before annotation overrides the default 2/3 lifetime behaviour",
			route: generateRouteStatus(&routev1.Route{
				ObjectMeta: metav1.ObjectMeta{
					Name:              "some-route",
					Namespace:         "some-namespace",
					CreationTimestamp: metav1.Time{Time: time.Now().Add(-time.Hour * 24 * 30)},
					Annotations: map[string]string{
						cmapi.IssuerNameAnnotationKey:  "some-issuer",
						cmapi.RenewBeforeAnnotationKey: "1680h",
					},
				},
				Spec: routev1.RouteSpec{
					Host: "some-host.some-domain.tld",
					TLS: &routev1.TLSConfig{
						Termination:                   routev1.TLSTerminationEdge,
						Certificate:                   string(validEcdsaCertPEM),
						Key:                           string(ecdsaKeyPEM),
						CACertificate:                 string(validEcdsaCertPEM),
						InsecureEdgeTerminationPolicy: routev1.InsecureEdgeTerminationPolicyRedirect,
					},
				},
			},
				true),
			want:         false,
			wantedEvents: []string{"Normal Issuing Issuing cert as the renew-before period has been reached"},
		},
		{
			name: "expiring soon ecdsa cert triggers a renewal",
			route: generateRouteStatus(&routev1.Route{
				ObjectMeta: metav1.ObjectMeta{
					Name:              "some-route",
					Namespace:         "some-namespace",
					CreationTimestamp: metav1.Time{Time: time.Now().Add(-time.Hour * 24 * 30)},
					Annotations:       map[string]string{cmapi.IssuerNameAnnotationKey: "some-issuer"},
				},
				Spec: routev1.RouteSpec{
					Host: "some-host.some-domain.tld",
					TLS: &routev1.TLSConfig{
						Termination:                   routev1.TLSTerminationEdge,
						Certificate:                   string(expiringSoonEcdsaCertPEM),
						Key:                           string(ecdsaKeyPEM),
						CACertificate:                 string(expiringSoonEcdsaCertPEM),
						InsecureEdgeTerminationPolicy: routev1.InsecureEdgeTerminationPolicyRedirect,
					},
				},
			},
				true),
			want:         false,
			wantedEvents: []string{"Normal Issuing Issuing cert as the existing cert is more than 2/3 through its validity period"},
		},
		{
			name: "cert not matching key triggers a renewal",
			route: generateRouteStatus(&routev1.Route{
				ObjectMeta: metav1.ObjectMeta{
					Name:              "some-route",
					Namespace:         "some-namespace",
					CreationTimestamp: metav1.Time{Time: time.Now().Add(-time.Hour * 24 * 30)},
					Annotations:       map[string]string{cmapi.IssuerNameAnnotationKey: "some-issuer"},
				},
				Spec: routev1.RouteSpec{
					Host: "some-host.some-domain.tld",
					TLS: &routev1.TLSConfig{
						Termination:                   routev1.TLSTerminationEdge,
						Certificate:                   string(validEcdsaCertPEM),
						Key:                           string(anotherEcdsaKeyPEM),
						CACertificate:                 string(validEcdsaCertPEM),
						InsecureEdgeTerminationPolicy: routev1.InsecureEdgeTerminationPolicyRedirect,
					},
				},
			},
				true),
			want:         false,
			wantedEvents: []string{"Normal Issuing Issuing cert as the public key does not match the certificate"},
		},
		{
			name: "junk data in key triggers a renewal",
			route: generateRouteStatus(&routev1.Route{
				ObjectMeta: metav1.ObjectMeta{
					Name:              "some-route",
					Namespace:         "some-namespace",
					CreationTimestamp: metav1.Time{Time: time.Now().Add(-time.Hour * 24 * 30)},
					Annotations:       map[string]string{cmapi.IssuerNameAnnotationKey: "some-issuer"},
				},
				Spec: routev1.RouteSpec{
					Host: "some-host.some-domain.tld",
					TLS: &routev1.TLSConfig{
						Termination: routev1.TLSTerminationEdge,
						Certificate: string(validEcdsaCertPEM),
						Key: `-----BEGIN PRIVATE KEY-----
SOME GARBAGE
-----END PRIVATE KEY-----`,
						CACertificate:                 string(validEcdsaCertPEM),
						InsecureEdgeTerminationPolicy: routev1.InsecureEdgeTerminationPolicyRedirect,
					},
				},
			},
				true),
			want:         false,
			wantedEvents: []string{"Normal Issuing Issuing cert as the existing key is invalid: error decoding private key PEM block: no PEM data was found in given input"},
		},
		{
			name: "missing private key triggers a renewal",
			route: generateRouteStatus(&routev1.Route{
				ObjectMeta: metav1.ObjectMeta{
					Name:              "some-route",
					Namespace:         "some-namespace",
					CreationTimestamp: metav1.Time{Time: time.Now().Add(-time.Hour * 24 * 30)},
					Annotations:       map[string]string{cmapi.IssuerNameAnnotationKey: "some-issuer"},
				},
				Spec: routev1.RouteSpec{
					Host: "some-host.some-domain.tld",
					TLS: &routev1.TLSConfig{
						Termination:                   routev1.TLSTerminationEdge,
						Certificate:                   string(validEcdsaCertPEM),
						CACertificate:                 string(validEcdsaCertPEM),
						InsecureEdgeTerminationPolicy: routev1.InsecureEdgeTerminationPolicyRedirect,
					},
				},
			},
				true),
			want:         false,
			wantedEvents: []string{"Normal Issuing Issuing cert as no private key exists"},
		},
		{
			name: "junk data in cert triggers a renewal",
			route: generateRouteStatus(&routev1.Route{
				ObjectMeta: metav1.ObjectMeta{
					Name:              "some-route",
					Namespace:         "some-namespace",
					CreationTimestamp: metav1.Time{Time: time.Now().Add(-time.Hour * 24 * 30)},
					Annotations:       map[string]string{cmapi.IssuerNameAnnotationKey: "some-issuer"},
				},
				Spec: routev1.RouteSpec{
					Host: "some-host.some-domain.tld",
					TLS: &routev1.TLSConfig{
						Termination: routev1.TLSTerminationEdge,
						Certificate: `-----BEGIN CERTIFICATE-----
SOME GARBAGE
-----END CERTIFICATE-----`,
						CACertificate:                 string(validEcdsaCertPEM),
						InsecureEdgeTerminationPolicy: routev1.InsecureEdgeTerminationPolicyRedirect,
					},
				},
				Status: routev1.RouteStatus{
					Ingress: []routev1.RouteIngress{
						{
							Host: "some-host.some-domain.tld",
						},
					},
				},
			},
				true),
			want:         false,
			wantedEvents: []string{"Normal Issuing Issuing cert as the existing cert is invalid: error decoding certificate PEM block: no valid certificates found"},
		},
		{
			name: "missing cert triggers a renewal",
			route: generateRouteStatus(&routev1.Route{
				ObjectMeta: metav1.ObjectMeta{
					Name:              "some-route",
					Namespace:         "some-namespace",
					CreationTimestamp: metav1.Time{Time: time.Now().Add(-time.Hour * 24 * 30)},
					Annotations:       map[string]string{cmapi.IssuerNameAnnotationKey: "some-issuer"},
				},
				Spec: routev1.RouteSpec{
					Host: "some-host.some-domain.tld",
					TLS: &routev1.TLSConfig{
						Termination:                   routev1.TLSTerminationEdge,
						CACertificate:                 string(validEcdsaCertPEM),
						InsecureEdgeTerminationPolicy: routev1.InsecureEdgeTerminationPolicyRedirect,
					},
				},
			},
				true),
			want:         false,
			wantedEvents: []string{"Normal Issuing Issuing cert as no certificate exists"},
		},
		{
			name: "missing tls config triggers a renewal",
			route: generateRouteStatus(&routev1.Route{
				ObjectMeta: metav1.ObjectMeta{
					Name:              "some-route",
					Namespace:         "some-namespace",
					CreationTimestamp: metav1.Time{Time: time.Now().Add(-time.Hour * 24 * 30)},
					Annotations:       map[string]string{cmapi.IssuerNameAnnotationKey: "some-issuer"},
				},
				Spec: routev1.RouteSpec{
					Host: "some-host.some-domain.tld",
				},
			},
				true),
			want:         false,
			wantedEvents: []string{"Normal Issuing Issuing cert as no TLS is configured"},
		},
		{
			name: "route with changed hostname",
			route: generateRouteStatus(&routev1.Route{
				ObjectMeta: metav1.ObjectMeta{
					Name:              "some-route",
					Namespace:         "some-namespace",
					CreationTimestamp: metav1.Time{Time: time.Now().Add(-time.Hour * 24 * 30)},
					Annotations:       map[string]string{cmapi.IssuerNameAnnotationKey: "some-issuer"},
				},
				Spec: routev1.RouteSpec{
					Host: "some-other-host.some-domain.tld",
					TLS: &routev1.TLSConfig{
						Termination:                   routev1.TLSTerminationEdge,
						Certificate:                   string(validEcdsaCertPEM),
						Key:                           string(ecdsaKeyPEM),
						CACertificate:                 string(validEcdsaCertPEM),
						InsecureEdgeTerminationPolicy: routev1.InsecureEdgeTerminationPolicyRedirect,
					},
				},
			},
				true),
			want: false,
			wantedEvents: []string{
				"Normal Issuing Issuing cert as the hostname does not match the certificate",
			},
		},
		{
			name: "route with subdomain",
			route: generateRouteStatus(&routev1.Route{
				ObjectMeta: metav1.ObjectMeta{
					Name:              "some-uninitialized-route",
					Namespace:         "some-namespace",
					CreationTimestamp: metav1.Time{Time: time.Now().Add(-time.Hour * 24 * 30)},
					Annotations:       map[string]string{cmapi.IssuerNameAnnotationKey: "some-issuer"},
				},
				Spec: routev1.RouteSpec{
					Subdomain: "sub-domain",
				},
			},
				true),
			want: false,
			wantedEvents: []string{
				"Normal Issuing Issuing cert as no TLS is configured",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			recorder := record.NewFakeRecorder(100)
			r := &RouteController{
				eventRecorder: recorder,
			}
			assert.Equal(t, tt.want, r.hasValidCertificate(tt.route), "hasValidCertificate() return value")
			close(recorder.Events)
			var gotEvents []string
			for e := range recorder.Events {
				gotEvents = append(gotEvents, e)
			}
			sort.Strings(tt.wantedEvents)
			sort.Strings(gotEvents)
			assert.Equal(t, tt.wantedEvents, gotEvents, "hasValidCertificate() events")
		})
	}
}

// Trivial logic that re-implements OpenShift's IngressController behavior. For context,
// the OpenShift IngressController code that deals with this is visible at:
// https://github.com/openshift/router/blob/72114ea/pkg/router/controller/status.go
func generateRouteStatus(route *routev1.Route, admitted bool) *routev1.Route {
	var host string
	if route.Spec.Host != "" {
		host = route.Spec.Host
	}
	if route.Spec.Subdomain != "" {
		host = route.Spec.Subdomain + ".cert-manager.io" // suffix depends on IC config
	}

	var admittedStatus = corev1.ConditionTrue
	if admitted == false {
		admittedStatus = corev1.ConditionFalse
	}

	route.Status = routev1.RouteStatus{
		Ingress: []routev1.RouteIngress{
			{
				Host: host,
				Conditions: []routev1.RouteIngressCondition{
					{
						Type:   "Admitted",
						Status: admittedStatus,
					},
				},
			},
		},
	}
	return route
}

func TestRoute_buildNextCertificate(t *testing.T) {
	domain := "some-host.some-domain.tld"
	domainSlice := []string{domain}

	routeName := "some-route"
	certName := routeName + "-cert"
	secretName := routeName + "-tls"

	// see util_test.go for details
	reallyLongRouteName := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	reallyLongCertName := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-03aaf5-cert"
	reallyLongSecretName := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-03aaf5-tls"

	tests := []struct {
		name       string
		route      *routev1.Route
		want       *cmapi.Certificate
		wantErr    error
		wantEvents []string
	}{
		{
			name: "Basic test with duration and hostname",
			route: generateRouteStatus(&routev1.Route{
				ObjectMeta: metav1.ObjectMeta{
					Name:      routeName,
					Namespace: "some-namespace",
					Annotations: map[string]string{
						cmapi.IssuerNameAnnotationKey: "self-signed-issuer",
						cmapi.DurationAnnotationKey:   "42m",
					},
				},
				Spec: routev1.RouteSpec{
					Host: domain,
				},
				Status: routev1.RouteStatus{
					Ingress: []routev1.RouteIngress{
						{
							Host: domain,
							Conditions: []routev1.RouteIngressCondition{
								{
									Type:   "Admitted",
									Status: "True",
								},
							},
						},
					},
				},
			},
				true),
			want: &cmapi.Certificate{
				ObjectMeta: metav1.ObjectMeta{
					Name:      certName,
					Namespace: "some-namespace",
				},
				Spec: cmapi.CertificateSpec{
					Duration:   &metav1.Duration{Duration: 42 * time.Minute},
					DNSNames:   domainSlice,
					IsCA:       false,
					Usages:     []cmapi.KeyUsage{cmapi.UsageServerAuth, cmapi.UsageDigitalSignature, cmapi.UsageKeyEncipherment},
					SecretName: secretName,
				},
			},
			wantErr: nil,
		},

		{
			name: "Basic test with long route name",
			route: generateRouteStatus(&routev1.Route{
				ObjectMeta: metav1.ObjectMeta{
					Name:      reallyLongRouteName,
					Namespace: "some-namespace",
					Annotations: map[string]string{
						cmapi.IssuerNameAnnotationKey: "self-signed-issuer",
					},
				},
				Spec: routev1.RouteSpec{
					Host: domain,
				},
				Status: routev1.RouteStatus{
					Ingress: []routev1.RouteIngress{
						{
							Host: domain,
							Conditions: []routev1.RouteIngressCondition{
								{
									Type:   "Admitted",
									Status: "True",
								},
							},
						},
					},
				},
			},
				true),
			want: &cmapi.Certificate{
				ObjectMeta: metav1.ObjectMeta{
					Name:      reallyLongCertName,
					Namespace: "some-namespace",
				},
				Spec: cmapi.CertificateSpec{
					Duration:   &metav1.Duration{Duration: DefaultCertificateDuration},
					DNSNames:   domainSlice,
					IsCA:       false,
					Usages:     []cmapi.KeyUsage{cmapi.UsageServerAuth, cmapi.UsageDigitalSignature, cmapi.UsageKeyEncipherment},
					SecretName: reallyLongSecretName,
				},
			},
			wantErr: nil,
		},

		{
			name: "Basic test with issuer name + kind",
			route: generateRouteStatus(&routev1.Route{
				ObjectMeta: metav1.ObjectMeta{
					Name:      routeName,
					Namespace: "some-namespace",
					Annotations: map[string]string{
						cmapi.IssuerNameAnnotationKey: "self-signed-issuer",
						cmapi.IssuerKindAnnotationKey: "SomeIssuer",
					},
				},
				Spec: routev1.RouteSpec{
					Host: domain,
				},
				Status: routev1.RouteStatus{
					Ingress: []routev1.RouteIngress{
						{
							Host: domain,
							Conditions: []routev1.RouteIngressCondition{
								{
									Type:   "Admitted",
									Status: "True",
								},
							},
						},
					},
				},
			},
				true),
			want: &cmapi.Certificate{
				ObjectMeta: metav1.ObjectMeta{
					Name:      certName,
					Namespace: "some-namespace",
				},
				Spec: cmapi.CertificateSpec{
					Duration:   &metav1.Duration{Duration: DefaultCertificateDuration},
					DNSNames:   domainSlice,
					IsCA:       false,
					Usages:     []cmapi.KeyUsage{cmapi.UsageServerAuth, cmapi.UsageDigitalSignature, cmapi.UsageKeyEncipherment},
					SecretName: secretName,

					IssuerRef: cmmeta.ObjectReference{
						Name: "self-signed-issuer",
						Kind: "SomeIssuer",
					},
				},
			},
			wantErr: nil,
		},

		{
			name: "Basic test with issuer name, kind + group",
			route: generateRouteStatus(&routev1.Route{
				ObjectMeta: metav1.ObjectMeta{
					Name:      routeName,
					Namespace: "some-namespace",
					Annotations: map[string]string{
						cmapi.IssuerNameAnnotationKey:  "self-signed-issuer",
						cmapi.IssuerKindAnnotationKey:  "SomeIssuer",
						cmapi.IssuerGroupAnnotationKey: "group.example.com",
					},
				},
				Spec: routev1.RouteSpec{
					Host: domain,
				},
				Status: routev1.RouteStatus{
					Ingress: []routev1.RouteIngress{
						{
							Host: domain,
							Conditions: []routev1.RouteIngressCondition{
								{
									Type:   "Admitted",
									Status: "True",
								},
							},
						},
					},
				},
			},
				true),
			want: &cmapi.Certificate{
				ObjectMeta: metav1.ObjectMeta{
					Name:      certName,
					Namespace: "some-namespace",
				},
				Spec: cmapi.CertificateSpec{
					Duration:   &metav1.Duration{Duration: DefaultCertificateDuration},
					DNSNames:   domainSlice,
					IsCA:       false,
					Usages:     []cmapi.KeyUsage{cmapi.UsageServerAuth, cmapi.UsageDigitalSignature, cmapi.UsageKeyEncipherment},
					SecretName: secretName,

					IssuerRef: cmmeta.ObjectReference{
						Name:  "self-signed-issuer",
						Kind:  "SomeIssuer",
						Group: "group.example.com",
					},
				},
			},
			wantErr: nil,
		},

		{
			name: "Basic test with alternate ingress issuer name annotation",
			route: generateRouteStatus(&routev1.Route{
				ObjectMeta: metav1.ObjectMeta{
					Name:      routeName,
					Namespace: "some-namespace",
					Annotations: map[string]string{
						cmapi.IngressIssuerNameAnnotationKey: "self-signed-issuer",
						cmapi.IssuerKindAnnotationKey:        "Issuer",
						cmapi.IssuerGroupAnnotationKey:       "external-issuer.io",
					},
				},
				Spec: routev1.RouteSpec{
					Host: domain,
				},
				Status: routev1.RouteStatus{
					Ingress: []routev1.RouteIngress{
						{
							Host: domain,
							Conditions: []routev1.RouteIngressCondition{
								{
									Type:   "Admitted",
									Status: "True",
								},
							},
						},
					},
				},
			},
				true),
			want: &cmapi.Certificate{
				ObjectMeta: metav1.ObjectMeta{
					Name:      certName,
					Namespace: "some-namespace",
				},
				Spec: cmapi.CertificateSpec{
					Duration:   &metav1.Duration{Duration: DefaultCertificateDuration},
					DNSNames:   domainSlice,
					IsCA:       false,
					Usages:     []cmapi.KeyUsage{cmapi.UsageServerAuth, cmapi.UsageDigitalSignature, cmapi.UsageKeyEncipherment},
					SecretName: secretName,

					IssuerRef: cmmeta.ObjectReference{
						Name:  "self-signed-issuer",
						Kind:  "Issuer",
						Group: "external-issuer.io",
					},
				},
			},
			wantErr: nil,
		},

		{
			name: "With subdomain and multiple ICs",
			route: &routev1.Route{
				ObjectMeta: metav1.ObjectMeta{
					Name:      routeName,
					Namespace: "some-namespace",
					Annotations: map[string]string{
						cmapi.IssuerNameAnnotationKey: "self-signed-issuer",
					},
				},
				Spec: routev1.RouteSpec{
					Subdomain: "some-sub-domain",
				},
				Status: routev1.RouteStatus{
					Ingress: []routev1.RouteIngress{
						{
							Host: "some-sub-domain.some-domain.tld", // suffix depends on IC config
							Conditions: []routev1.RouteIngressCondition{
								{
									Type:   "Admitted",
									Status: "True",
								},
							},
						},
						{
							Host: "some-sub-domain.some-other-ic.example.com",
							Conditions: []routev1.RouteIngressCondition{
								{
									Type:   "Admitted",
									Status: "True",
								},
							},
						},
						{
							Host: "some-sub-domain.not-admitted.example.com",
							Conditions: []routev1.RouteIngressCondition{
								{
									Type:   "Admitted",
									Status: "False",
								},
							},
						},
					},
				},
			},
			want: &cmapi.Certificate{
				ObjectMeta: metav1.ObjectMeta{
					Name:      certName,
					Namespace: "some-namespace",
				},
				Spec: cmapi.CertificateSpec{
					Duration:   &metav1.Duration{Duration: DefaultCertificateDuration},
					Usages:     []cmapi.KeyUsage{cmapi.UsageServerAuth, cmapi.UsageDigitalSignature, cmapi.UsageKeyEncipherment},
					IsCA:       false,
					SecretName: secretName,

					DNSNames: []string{
						"some-sub-domain.some-domain.tld",
						"some-sub-domain.some-other-ic.example.com",
					},
				},
			},
			wantErr: nil,
		},

		{
			name: "With ECDSA private key algorithm annotation",
			route: generateRouteStatus(&routev1.Route{
				ObjectMeta: metav1.ObjectMeta{
					Name:      routeName,
					Namespace: "some-namespace",
					Annotations: map[string]string{
						cmapi.IssuerNameAnnotationKey:          "self-signed-issuer",
						cmapi.PrivateKeyAlgorithmAnnotationKey: string(cmapi.ECDSAKeyAlgorithm),
					},
				},
				Spec: routev1.RouteSpec{
					Host: domain,
				},
				Status: routev1.RouteStatus{
					Ingress: []routev1.RouteIngress{
						{
							Host: domain,
							Conditions: []routev1.RouteIngressCondition{
								{
									Type:   "Admitted",
									Status: "True",
								},
							},
						},
					},
				},
			},
				true),
			want: &cmapi.Certificate{
				ObjectMeta: metav1.ObjectMeta{
					Name:      certName,
					Namespace: "some-namespace",
				},
				Spec: cmapi.CertificateSpec{
					Usages:     []cmapi.KeyUsage{cmapi.UsageServerAuth, cmapi.UsageDigitalSignature, cmapi.UsageKeyEncipherment},
					Duration:   &metav1.Duration{Duration: DefaultCertificateDuration},
					IsCA:       false,
					DNSNames:   domainSlice,
					SecretName: secretName,

					PrivateKey: &cmapi.CertificatePrivateKey{
						Algorithm: cmapi.ECDSAKeyAlgorithm,
					},
				},
			},
			wantErr: nil,
		},

		{
			name: "With ECDSA P-384 private key algorithm and size annotation",
			route: generateRouteStatus(&routev1.Route{
				ObjectMeta: metav1.ObjectMeta{
					Name:      routeName,
					Namespace: "some-namespace",
					Annotations: map[string]string{
						cmapi.IssuerNameAnnotationKey:          "self-signed-issuer",
						cmapi.PrivateKeyAlgorithmAnnotationKey: string(cmapi.ECDSAKeyAlgorithm),
						cmapi.PrivateKeySizeAnnotationKey:      strconv.Itoa(384),
					},
				},
				Spec: routev1.RouteSpec{
					Host: domain,
				},
				Status: routev1.RouteStatus{
					Ingress: []routev1.RouteIngress{
						{
							Host: domain,
							Conditions: []routev1.RouteIngressCondition{
								{
									Type:   "Admitted",
									Status: "True",
								},
							},
						},
					},
				},
			},
				true),
			want: &cmapi.Certificate{
				ObjectMeta: metav1.ObjectMeta{
					Name:      certName,
					Namespace: "some-namespace",
				},
				Spec: cmapi.CertificateSpec{
					Usages:     []cmapi.KeyUsage{cmapi.UsageServerAuth, cmapi.UsageDigitalSignature, cmapi.UsageKeyEncipherment},
					Duration:   &metav1.Duration{Duration: DefaultCertificateDuration},
					IsCA:       false,
					DNSNames:   domainSlice,
					SecretName: secretName,

					PrivateKey: &cmapi.CertificatePrivateKey{
						Algorithm: cmapi.ECDSAKeyAlgorithm,
						Size:      384,
					},
				},
			},
			wantErr: nil,
		},

		{
			name: "With ECDSA P-521 private key algorithm and size annotation",
			route: generateRouteStatus(&routev1.Route{
				ObjectMeta: metav1.ObjectMeta{
					Name:      routeName,
					Namespace: "some-namespace",
					Annotations: map[string]string{
						cmapi.IssuerNameAnnotationKey:          "self-signed-issuer",
						cmapi.PrivateKeyAlgorithmAnnotationKey: string(cmapi.ECDSAKeyAlgorithm),
						cmapi.PrivateKeySizeAnnotationKey:      strconv.Itoa(521),
					},
				},
				Spec: routev1.RouteSpec{
					Host: domain,
				},
				Status: routev1.RouteStatus{
					Ingress: []routev1.RouteIngress{
						{
							Host: domain,
							Conditions: []routev1.RouteIngressCondition{
								{
									Type:   "Admitted",
									Status: "True",
								},
							},
						},
					},
				},
			},
				true),
			want: &cmapi.Certificate{
				ObjectMeta: metav1.ObjectMeta{
					Name:      certName,
					Namespace: "some-namespace",
				},
				Spec: cmapi.CertificateSpec{
					Usages:     []cmapi.KeyUsage{cmapi.UsageServerAuth, cmapi.UsageDigitalSignature, cmapi.UsageKeyEncipherment},
					Duration:   &metav1.Duration{Duration: DefaultCertificateDuration},
					IsCA:       false,
					DNSNames:   domainSlice,
					SecretName: secretName,

					PrivateKey: &cmapi.CertificatePrivateKey{
						Algorithm: cmapi.ECDSAKeyAlgorithm,
						Size:      521,
					},
				},
			},
			wantErr: nil,
		},

		{
			name: "With RSA private key algorithm annotation",
			route: generateRouteStatus(&routev1.Route{
				ObjectMeta: metav1.ObjectMeta{
					Name:      routeName,
					Namespace: "some-namespace",
					Annotations: map[string]string{
						cmapi.IssuerNameAnnotationKey:          "self-signed-issuer",
						cmapi.PrivateKeyAlgorithmAnnotationKey: string(cmapi.RSAKeyAlgorithm),
					},
				},
				Spec: routev1.RouteSpec{
					Host: domain,
				},
				Status: routev1.RouteStatus{
					Ingress: []routev1.RouteIngress{
						{
							Host: domain,
							Conditions: []routev1.RouteIngressCondition{
								{
									Type:   "Admitted",
									Status: "True",
								},
							},
						},
					},
				},
			},
				true),
			want: &cmapi.Certificate{
				ObjectMeta: metav1.ObjectMeta{
					Name:      certName,
					Namespace: "some-namespace",
				},
				Spec: cmapi.CertificateSpec{
					Usages:     []cmapi.KeyUsage{cmapi.UsageServerAuth, cmapi.UsageDigitalSignature, cmapi.UsageKeyEncipherment},
					Duration:   &metav1.Duration{Duration: DefaultCertificateDuration},
					IsCA:       false,
					DNSNames:   domainSlice,
					SecretName: secretName,

					PrivateKey: &cmapi.CertificatePrivateKey{
						Algorithm: cmapi.RSAKeyAlgorithm,
					},
				},
			},
			wantErr: nil,
		},

		{
			name: "With RSA 3072 private key algorithm and size annotation",
			route: generateRouteStatus(&routev1.Route{
				ObjectMeta: metav1.ObjectMeta{
					Name:      routeName,
					Namespace: "some-namespace",
					Annotations: map[string]string{
						cmapi.IssuerNameAnnotationKey:          "self-signed-issuer",
						cmapi.PrivateKeyAlgorithmAnnotationKey: string(cmapi.RSAKeyAlgorithm),
						cmapi.PrivateKeySizeAnnotationKey:      strconv.Itoa(3072),
					},
				},
				Spec: routev1.RouteSpec{
					Host: domain,
				},
				Status: routev1.RouteStatus{
					Ingress: []routev1.RouteIngress{
						{
							Host: domain,
							Conditions: []routev1.RouteIngressCondition{
								{
									Type:   "Admitted",
									Status: "True",
								},
							},
						},
					},
				},
			},
				true),
			want: &cmapi.Certificate{
				ObjectMeta: metav1.ObjectMeta{
					Name:      certName,
					Namespace: "some-namespace",
				},
				Spec: cmapi.CertificateSpec{
					Usages:     []cmapi.KeyUsage{cmapi.UsageServerAuth, cmapi.UsageDigitalSignature, cmapi.UsageKeyEncipherment},
					Duration:   &metav1.Duration{Duration: DefaultCertificateDuration},
					IsCA:       false,
					DNSNames:   domainSlice,
					SecretName: secretName,

					PrivateKey: &cmapi.CertificatePrivateKey{
						Algorithm: cmapi.RSAKeyAlgorithm,
						Size:      3072,
					},
				},
			},
			wantErr: nil,
		},

		{
			name: "With Ed25519 private key algorithm and size annotation",
			route: generateRouteStatus(&routev1.Route{
				ObjectMeta: metav1.ObjectMeta{
					Name:      routeName,
					Namespace: "some-namespace",
					Annotations: map[string]string{
						cmapi.IssuerNameAnnotationKey:          "self-signed-issuer",
						cmapi.PrivateKeyAlgorithmAnnotationKey: string(cmapi.Ed25519KeyAlgorithm),
					},
				},
				Spec: routev1.RouteSpec{
					Host: domain,
				},
				Status: routev1.RouteStatus{
					Ingress: []routev1.RouteIngress{
						{
							Host: domain,
							Conditions: []routev1.RouteIngressCondition{
								{
									Type:   "Admitted",
									Status: "True",
								},
							},
						},
					},
				},
			},
				true),
			want: &cmapi.Certificate{
				ObjectMeta: metav1.ObjectMeta{
					Name:      certName,
					Namespace: "some-namespace",
				},
				Spec: cmapi.CertificateSpec{
					Usages:     []cmapi.KeyUsage{cmapi.UsageServerAuth, cmapi.UsageDigitalSignature, cmapi.UsageKeyEncipherment},
					Duration:   &metav1.Duration{Duration: DefaultCertificateDuration},
					IsCA:       false,
					DNSNames:   domainSlice,
					SecretName: secretName,

					PrivateKey: &cmapi.CertificatePrivateKey{
						Algorithm: cmapi.Ed25519KeyAlgorithm,
					},
				},
			},
			wantErr: nil,
		},

		{
			name: "With subject annotations",
			route: &routev1.Route{
				ObjectMeta: metav1.ObjectMeta{
					Name:      routeName,
					Namespace: "some-namespace",
					Annotations: map[string]string{
						cmapi.IssuerNameAnnotationKey: "self-signed-issuer",

						cmapi.SubjectOrganizationsAnnotationKey:       "Company 1,Company 2",
						cmapi.SubjectOrganizationalUnitsAnnotationKey: "Tech Division,Other Division",
						cmapi.SubjectCountriesAnnotationKey:           "Country 1,Country 2",
						cmapi.SubjectProvincesAnnotationKey:           "Province 1,Province 2",
						cmapi.SubjectStreetAddressesAnnotationKey:     "123 Example St,456 Example Ave",
						cmapi.SubjectLocalitiesAnnotationKey:          "City 1,City 2",
						cmapi.SubjectPostalCodesAnnotationKey:         "123ABC,456DEF",
						cmapi.SubjectSerialNumberAnnotationKey:        "10978342379280287615",
					},
				},
				Spec: routev1.RouteSpec{
					Host: domain,
				},
				Status: routev1.RouteStatus{
					Ingress: []routev1.RouteIngress{
						{
							Host: domain,
							Conditions: []routev1.RouteIngressCondition{
								{
									Type:   "Admitted",
									Status: "True",
								},
							},
						},
					},
				},
			},
			want: &cmapi.Certificate{
				ObjectMeta: metav1.ObjectMeta{
					Name:      certName,
					Namespace: "some-namespace",
				},
				Spec: cmapi.CertificateSpec{
					Duration:   &metav1.Duration{Duration: DefaultCertificateDuration},
					Usages:     []cmapi.KeyUsage{cmapi.UsageServerAuth, cmapi.UsageDigitalSignature, cmapi.UsageKeyEncipherment},
					IsCA:       false,
					DNSNames:   domainSlice,
					SecretName: secretName,

					Subject: &cmapi.X509Subject{
						Organizations:       []string{"Company 1", "Company 2"},
						OrganizationalUnits: []string{"Tech Division", "Other Division"},
						Countries:           []string{"Country 1", "Country 2"},
						Provinces:           []string{"Province 1", "Province 2"},
						StreetAddresses:     []string{"123 Example St", "456 Example Ave"},
						Localities:          []string{"City 1", "City 2"},
						PostalCodes:         []string{"123ABC", "456DEF"},
						SerialNumber:        "10978342379280287615",
					},
				},
			},
			wantErr: nil,
		},

		{
			name: "With custom URI SAN",
			route: generateRouteStatus(&routev1.Route{
				ObjectMeta: metav1.ObjectMeta{
					Name:      routeName,
					Namespace: "some-namespace",
					Annotations: map[string]string{
						cmapi.IssuerNameAnnotationKey: "self-signed-issuer",
						cmapi.URISANAnnotationKey:     "spiffe://example.com/myuri",
					},
				},
				Spec: routev1.RouteSpec{
					Host: domain,
				},
				Status: routev1.RouteStatus{
					Ingress: []routev1.RouteIngress{
						{
							Host: domain,
							Conditions: []routev1.RouteIngressCondition{
								{
									Type:   "Admitted",
									Status: "True",
								},
							},
						},
					},
				},
			},
				true),
			want: &cmapi.Certificate{
				ObjectMeta: metav1.ObjectMeta{
					Name:      certName,
					Namespace: "some-namespace",
				},
				Spec: cmapi.CertificateSpec{
					Duration:   &metav1.Duration{Duration: DefaultCertificateDuration},
					DNSNames:   domainSlice,
					IsCA:       false,
					Usages:     []cmapi.KeyUsage{cmapi.UsageServerAuth, cmapi.UsageDigitalSignature, cmapi.UsageKeyEncipherment},
					SecretName: secretName,

					URIs: []string{"spiffe://example.com/myuri"},
				},
			},
			wantErr: nil,
		},

		{
			name: "With extra DNS names",
			route: generateRouteStatus(&routev1.Route{
				ObjectMeta: metav1.ObjectMeta{
					Name:      routeName,
					Namespace: "some-namespace",
					Annotations: map[string]string{
						cmapi.IssuerNameAnnotationKey: "self-signed-issuer",
						cmapi.AltNamesAnnotationKey:   "example.com,another.example.com",
					},
				},
				Spec: routev1.RouteSpec{
					Host: domain,
				},
				Status: routev1.RouteStatus{
					Ingress: []routev1.RouteIngress{
						{
							Host: domain,
							Conditions: []routev1.RouteIngressCondition{
								{
									Type:   "Admitted",
									Status: "True",
								},
							},
						},
					},
				},
			},
				true),
			want: &cmapi.Certificate{
				ObjectMeta: metav1.ObjectMeta{
					Name:      certName,
					Namespace: "some-namespace",
				},
				Spec: cmapi.CertificateSpec{
					Duration:   &metav1.Duration{Duration: DefaultCertificateDuration},
					IsCA:       false,
					Usages:     []cmapi.KeyUsage{cmapi.UsageServerAuth, cmapi.UsageDigitalSignature, cmapi.UsageKeyEncipherment},
					SecretName: secretName,

					DNSNames: []string{domain, "example.com", "another.example.com"},
				},
			},
			wantErr: nil,
		},

		{
			name: "With custom IPv4 address",
			route: generateRouteStatus(&routev1.Route{
				ObjectMeta: metav1.ObjectMeta{
					Name:      routeName,
					Namespace: "some-namespace",
					Annotations: map[string]string{
						cmapi.IssuerNameAnnotationKey: "self-signed-issuer",
						cmapi.IPSANAnnotationKey:      "169.50.50.50",
					},
				},
				Spec: routev1.RouteSpec{
					Host: domain,
				},
				Status: routev1.RouteStatus{
					Ingress: []routev1.RouteIngress{
						{
							Host: domain,
							Conditions: []routev1.RouteIngressCondition{
								{
									Type:   "Admitted",
									Status: "True",
								},
							},
						},
					},
				},
			},
				true),
			want: &cmapi.Certificate{
				ObjectMeta: metav1.ObjectMeta{
					Name:      certName,
					Namespace: "some-namespace",
				},
				Spec: cmapi.CertificateSpec{
					Duration:   &metav1.Duration{Duration: DefaultCertificateDuration},
					DNSNames:   domainSlice,
					IsCA:       false,
					Usages:     []cmapi.KeyUsage{cmapi.UsageServerAuth, cmapi.UsageDigitalSignature, cmapi.UsageKeyEncipherment},
					SecretName: secretName,

					IPAddresses: []string{"169.50.50.50"},
				},
			},
			wantErr: nil,
		},

		{
			name: "With custom IPv6 address",
			route: generateRouteStatus(&routev1.Route{
				ObjectMeta: metav1.ObjectMeta{
					Name:      routeName,
					Namespace: "some-namespace",
					Annotations: map[string]string{
						cmapi.IssuerNameAnnotationKey: "self-signed-issuer",
						cmapi.IPSANAnnotationKey:      "2a02:ec80:300:ed1a::1",
					},
				},
				Spec: routev1.RouteSpec{
					Host: domain,
				},
				Status: routev1.RouteStatus{
					Ingress: []routev1.RouteIngress{
						{
							Host: domain,
							Conditions: []routev1.RouteIngressCondition{
								{
									Type:   "Admitted",
									Status: "True",
								},
							},
						},
					},
				},
			},
				true),
			want: &cmapi.Certificate{
				ObjectMeta: metav1.ObjectMeta{
					Name:      certName,
					Namespace: "some-namespace",
				},
				Spec: cmapi.CertificateSpec{
					Duration:   &metav1.Duration{Duration: DefaultCertificateDuration},
					DNSNames:   domainSlice,
					IsCA:       false,
					Usages:     []cmapi.KeyUsage{cmapi.UsageServerAuth, cmapi.UsageDigitalSignature, cmapi.UsageKeyEncipherment},
					SecretName: secretName,

					IPAddresses: []string{"2a02:ec80:300:ed1a::1"},
				},
			},
			wantErr: nil,
		},

		{
			name: "With custom mixed IP addresses",
			route: generateRouteStatus(&routev1.Route{
				ObjectMeta: metav1.ObjectMeta{
					Name:      routeName,
					Namespace: "some-namespace",
					Annotations: map[string]string{
						cmapi.IssuerNameAnnotationKey: "self-signed-issuer",
						cmapi.IPSANAnnotationKey:      "169.50.50.50,2a02:ec80:300:ed1a::1,::ffff:192.168.0.1",
					},
				},
				Spec: routev1.RouteSpec{
					Host: domain,
				},
				Status: routev1.RouteStatus{
					Ingress: []routev1.RouteIngress{
						{
							Host: domain,
							Conditions: []routev1.RouteIngressCondition{
								{
									Type:   "Admitted",
									Status: "True",
								},
							},
						},
					},
				},
			},
				true),
			want: &cmapi.Certificate{
				ObjectMeta: metav1.ObjectMeta{
					Name:      certName,
					Namespace: "some-namespace",
				},
				Spec: cmapi.CertificateSpec{
					Duration:   &metav1.Duration{Duration: DefaultCertificateDuration},
					DNSNames:   domainSlice,
					IsCA:       false,
					Usages:     []cmapi.KeyUsage{cmapi.UsageServerAuth, cmapi.UsageDigitalSignature, cmapi.UsageKeyEncipherment},
					SecretName: secretName,

					IPAddresses: []string{"169.50.50.50", "2a02:ec80:300:ed1a::1", "192.168.0.1"},
				},
			},
			wantErr: nil,
		},

		{
			name: "With custom emails",
			route: generateRouteStatus(&routev1.Route{
				ObjectMeta: metav1.ObjectMeta{
					Name:      routeName,
					Namespace: "some-namespace",
					Annotations: map[string]string{
						cmapi.IssuerNameAnnotationKey: "self-signed-issuer",
						cmapi.EmailsAnnotationKey:     "test@example.com,hello@example.com",
					},
				},
				Spec: routev1.RouteSpec{
					Host: domain,
				},
				Status: routev1.RouteStatus{
					Ingress: []routev1.RouteIngress{
						{
							Host: domain,
							Conditions: []routev1.RouteIngressCondition{
								{
									Type:   "Admitted",
									Status: "True",
								},
							},
						},
					},
				},
			},
				true),
			want: &cmapi.Certificate{
				ObjectMeta: metav1.ObjectMeta{
					Name:      certName,
					Namespace: "some-namespace",
				},
				Spec: cmapi.CertificateSpec{
					Duration:   &metav1.Duration{Duration: DefaultCertificateDuration},
					DNSNames:   domainSlice,
					IsCA:       false,
					Usages:     []cmapi.KeyUsage{cmapi.UsageServerAuth, cmapi.UsageDigitalSignature, cmapi.UsageKeyEncipherment},
					SecretName: secretName,

					EmailAddresses: []string{"test@example.com", "hello@example.com"},
				},
			},
			wantErr: nil,
		},

		{
			name: "With all SAN fields",
			route: generateRouteStatus(&routev1.Route{
				ObjectMeta: metav1.ObjectMeta{
					Name:      routeName,
					Namespace: "some-namespace",
					Annotations: map[string]string{
						cmapi.IssuerNameAnnotationKey: "self-signed-issuer",

						cmapi.AltNamesAnnotationKey: "example.com,another.example.com",
						cmapi.URISANAnnotationKey:   "spiffe://example.com/myuri",
						cmapi.IPSANAnnotationKey:    "169.50.50.50,2a02:ec80:300:ed1a::1,::ffff:192.168.0.1",
						cmapi.EmailsAnnotationKey:   "test@example.com,hello@example.com",
					},
				},
				Spec: routev1.RouteSpec{
					Host: domain,
				},
				Status: routev1.RouteStatus{
					Ingress: []routev1.RouteIngress{
						{
							Host: domain,
							Conditions: []routev1.RouteIngressCondition{
								{
									Type:   "Admitted",
									Status: "True",
								},
							},
						},
					},
				},
			},
				true),
			want: &cmapi.Certificate{
				ObjectMeta: metav1.ObjectMeta{
					Name:      certName,
					Namespace: "some-namespace",
				},
				Spec: cmapi.CertificateSpec{
					Duration:   &metav1.Duration{Duration: DefaultCertificateDuration},
					IsCA:       false,
					Usages:     []cmapi.KeyUsage{cmapi.UsageServerAuth, cmapi.UsageDigitalSignature, cmapi.UsageKeyEncipherment},
					SecretName: secretName,

					DNSNames:       []string{domain, "example.com", "another.example.com"},
					URIs:           []string{"spiffe://example.com/myuri"},
					IPAddresses:    []string{"169.50.50.50", "2a02:ec80:300:ed1a::1", "192.168.0.1"},
					EmailAddresses: []string{"test@example.com", "hello@example.com"},
				},
			},
			wantErr: nil,
		},

		{
			name: "With custom renewBefore",
			route: generateRouteStatus(&routev1.Route{
				ObjectMeta: metav1.ObjectMeta{
					Name:      routeName,
					Namespace: "some-namespace",
					Annotations: map[string]string{
						cmapi.IssuerNameAnnotationKey:  "self-signed-issuer",
						cmapi.RenewBeforeAnnotationKey: "30m",
					},
				},
				Spec: routev1.RouteSpec{
					Host: domain,
				},
				Status: routev1.RouteStatus{
					Ingress: []routev1.RouteIngress{
						{
							Host: domain,
							Conditions: []routev1.RouteIngressCondition{
								{
									Type:   "Admitted",
									Status: "True",
								},
							},
						},
					},
				},
			},
				true),
			want: &cmapi.Certificate{
				ObjectMeta: metav1.ObjectMeta{
					Name:      certName,
					Namespace: "some-namespace",
				},
				Spec: cmapi.CertificateSpec{
					Duration:   &metav1.Duration{Duration: DefaultCertificateDuration},
					DNSNames:   domainSlice,
					IsCA:       false,
					Usages:     []cmapi.KeyUsage{cmapi.UsageServerAuth, cmapi.UsageDigitalSignature, cmapi.UsageKeyEncipherment},
					SecretName: secretName,

					RenewBefore: &metav1.Duration{Duration: 30 * time.Minute},
				},
			},
			wantErr: nil,
		},

		{
			name: "missing issuer-name is an error",
			route: generateRouteStatus(&routev1.Route{
				ObjectMeta: metav1.ObjectMeta{
					Name:      routeName,
					Namespace: "some-namespace",
					Annotations: map[string]string{
						cmapi.RenewBeforeAnnotationKey: "30m",
					},
				},
				Spec: routev1.RouteSpec{
					Host: domain,
				},
				Status: routev1.RouteStatus{
					Ingress: []routev1.RouteIngress{
						{
							Host: domain,
							Conditions: []routev1.RouteIngressCondition{
								{
									Type:   "Admitted",
									Status: "True",
								},
							},
						},
					},
				},
			},
				true),
			want:    nil,
			wantErr: fmt.Errorf("missing issuer-name annotation on some-namespace/some-route"),
		},

		{
			name: "invalid duration is an error",
			route: generateRouteStatus(&routev1.Route{
				ObjectMeta: metav1.ObjectMeta{
					Name:      routeName,
					Namespace: "some-namespace",
					Annotations: map[string]string{
						cmapi.IssuerNameAnnotationKey: "self-signed-issuer",
						cmapi.DurationAnnotationKey:   "not-a-time",
					},
				},
				Spec: routev1.RouteSpec{
					Host: domain,
				},
				Status: routev1.RouteStatus{
					Ingress: []routev1.RouteIngress{
						{
							Host: domain,
							Conditions: []routev1.RouteIngressCondition{
								{
									Type:   "Admitted",
									Status: "True",
								},
							},
						},
					},
				},
			},
				true),
			want:    nil,
			wantErr: fmt.Errorf("invalid duration annotation on Route %s/%s", "some-namespace", "some-route"),
		},

		{
			name: "invalid renew-before is an error",
			route: generateRouteStatus(&routev1.Route{
				ObjectMeta: metav1.ObjectMeta{
					Name:      routeName,
					Namespace: "some-namespace",
					Annotations: map[string]string{
						cmapi.IssuerNameAnnotationKey:  "self-signed-issuer",
						cmapi.RenewBeforeAnnotationKey: "not-a-time",
					},
				},
				Spec: routev1.RouteSpec{
					Host: domain,
				},
				Status: routev1.RouteStatus{
					Ingress: []routev1.RouteIngress{
						{
							Host: domain,
							Conditions: []routev1.RouteIngressCondition{
								{
									Type:   "Admitted",
									Status: "True",
								},
							},
						},
					},
				},
			},
				true),
			want:    nil,
			wantErr: fmt.Errorf("invalid renew-before annotation %q on Route %s/%s", "not-a-time", "some-namespace", "some-route"),
		},

		{
			name: "invalid private key size is an error",
			route: generateRouteStatus(&routev1.Route{
				ObjectMeta: metav1.ObjectMeta{
					Name:      routeName,
					Namespace: "some-namespace",
					Annotations: map[string]string{
						cmapi.IssuerNameAnnotationKey:     "self-signed-issuer",
						cmapi.PrivateKeySizeAnnotationKey: "not-a-number",
					},
				},
				Spec: routev1.RouteSpec{
					Host: domain,
				},
				Status: routev1.RouteStatus{
					Ingress: []routev1.RouteIngress{
						{
							Host: domain,
							Conditions: []routev1.RouteIngressCondition{
								{
									Type:   "Admitted",
									Status: "True",
								},
							},
						},
					},
				},
			},
				true),
			want:    nil,
			wantErr: fmt.Errorf("invalid private key size annotation %q on %s/%s", "not-a-number", "some-namespace", "some-route"),
		},

		{
			name: "invalid revision history limit is an error",
			route: generateRouteStatus(&routev1.Route{
				ObjectMeta: metav1.ObjectMeta{
					Name:      routeName,
					Namespace: "some-namespace",
					Annotations: map[string]string{
						cmapi.IssuerNameAnnotationKey:           "self-signed-issuer",
						cmapi.RevisionHistoryLimitAnnotationKey: "not-a-number",
					},
				},
				Spec: routev1.RouteSpec{
					Host: domain,
				},
				Status: routev1.RouteStatus{
					Ingress: []routev1.RouteIngress{
						{
							Host: domain,
							Conditions: []routev1.RouteIngressCondition{
								{
									Type:   "Admitted",
									Status: "True",
								},
							},
						},
					},
				},
			},
				true),
			want:    nil,
			wantErr: fmt.Errorf("invalid revision-history-limit annotation %q on %s/%s", "not-a-number", "some-namespace", "some-route"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			recorder := record.NewFakeRecorder(100)
			r := &RouteController{
				eventRecorder: recorder,
			}

			// test "buildNextCR" function
			cert, err := r.buildNextCert(t.Context(), tt.route)

			// check that we got the expected error (including nil)
			assert.Equal(t, tt.wantErr, err, "buildNextCert()")

			if tt.wantErr != nil || err != nil {
				return
			}

			// check that the returned object is as expected

			if tt.want.Spec.IssuerRef.Name != "" {
				// only check issuerRef if it was specified on want; this saves copying lots
				// of issuerRefs around
				assert.Equal(t, tt.want.Spec.IssuerRef, cert.Spec.IssuerRef)
			}

			assert.Equal(t, tt.want.ObjectMeta.GenerateName, cert.ObjectMeta.GenerateName)
			assert.Equal(t, tt.want.ObjectMeta.Namespace, cert.ObjectMeta.Namespace)
			assert.Equal(t, tt.want.ObjectMeta.Annotations, cert.ObjectMeta.Annotations)
			assert.Equal(t, tt.want.ObjectMeta.Labels, cert.ObjectMeta.Labels)
			assert.Equal(t, tt.want.Spec.Duration, cert.Spec.Duration)
			assert.Equal(t, tt.want.Spec.IsCA, cert.Spec.IsCA)
			assert.Equal(t, tt.want.Spec.Usages, cert.Spec.Usages)
			assert.Equal(t, tt.want.Spec.DNSNames, cert.Spec.DNSNames)
			assert.Equal(t, tt.want.Spec.EmailAddresses, cert.Spec.EmailAddresses)
			assert.Equal(t, tt.want.Spec.IPAddresses, cert.Spec.IPAddresses)
			assert.Equal(t, tt.want.Spec.URIs, cert.Spec.URIs)
			assert.Equal(t, tt.want.Spec.SecretName, cert.Spec.SecretName)

			if tt.want.Spec.PrivateKey != nil {
				assert.Equal(t, tt.want.Spec.PrivateKey, cert.Spec.PrivateKey)
			}

			if tt.want.Spec.Subject != nil {
				assert.Equal(t, tt.want.Spec.Subject, cert.Spec.Subject)
			}

			if tt.want.Spec.RenewBefore != nil {
				assert.Equal(t, tt.want.Spec.RenewBefore, cert.Spec.RenewBefore)
			}

			close(recorder.Events)
		})
	}
}
