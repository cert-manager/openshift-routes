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
	"math/big"
	"sort"
	"testing"
	"time"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
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
			wantedEvents: []string{"Normal Issuing Issuing cert as the existing key is invalid: error decoding private key PEM block"},
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
			wantedEvents: []string{"Normal Issuing Issuing cert as the existing cert is invalid: error decoding certificate PEM block"},
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

// trivial logic that re-implements OpenShift's IngressController behavior
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
