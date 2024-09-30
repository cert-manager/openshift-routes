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

package crcontroller

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"sort"
	"strconv"
	"testing"
	"time"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	utilpki "github.com/cert-manager/cert-manager/pkg/util/pki"
	routev1 "github.com/openshift/api/route/v1"
	fakeroutev1client "github.com/openshift/client-go/route/clientset/versioned/fake"
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
			r := &Route{
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

func TestRoute_hasNextPrivateKey(t *testing.T) {
	// set up key for test cases
	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	ecdsaKeyPEM, err := utilpki.EncodePKCS8PrivateKey(ecdsaKey)
	require.NoError(t, err)
	tests := []struct {
		name         string
		route        *routev1.Route
		want         bool
		wantedEvents []string
	}{
		{
			name: "route has a private key",
			route: &routev1.Route{
				ObjectMeta: metav1.ObjectMeta{
					Name:              "some-route",
					Namespace:         "some-namespace",
					CreationTimestamp: metav1.Time{Time: time.Now().Add(-time.Hour * 24 * 30)},
					Annotations: map[string]string{
						cmapi.IssuerNameAnnotationKey:        "some-issuer",
						cmapi.IsNextPrivateKeySecretLabelKey: string(ecdsaKeyPEM),
					},
				},
				Spec: routev1.RouteSpec{},
			},
			want:         true,
			wantedEvents: nil,
		},
		{
			name: "route has no private key",
			route: &routev1.Route{
				ObjectMeta: metav1.ObjectMeta{
					Name:              "some-route",
					Namespace:         "some-namespace",
					CreationTimestamp: metav1.Time{Time: time.Now().Add(-time.Hour * 24 * 30)},
					Annotations: map[string]string{
						cmapi.IssuerNameAnnotationKey: "some-issuer",
					},
				},
				Spec: routev1.RouteSpec{},
			},
			want:         false,
			wantedEvents: nil,
		},
		{
			name: "route has garbage data in private key",
			route: &routev1.Route{
				ObjectMeta: metav1.ObjectMeta{
					Name:              "some-route",
					Namespace:         "some-namespace",
					CreationTimestamp: metav1.Time{Time: time.Now().Add(-time.Hour * 24 * 30)},
					Annotations: map[string]string{
						cmapi.IssuerNameAnnotationKey: "some-issuer",
						cmapi.IsNextPrivateKeySecretLabelKey: `-----BEGIN PRIVATE KEY-----
SOME GARBAGE
-----END PRIVATE KEY-----`,
					},
				},
				Spec: routev1.RouteSpec{},
			},
			want:         false,
			wantedEvents: []string{"Warning InvalidKey Regenerating Next Private Key as the existing key is invalid: error decoding private key PEM block"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			recorder := record.NewFakeRecorder(100)
			r := &Route{
				eventRecorder: recorder,
			}
			assert.Equal(t, tt.want, r.hasNextPrivateKey(tt.route), "hasNextPrivateKey()")
			close(recorder.Events)
			var gotEvents []string
			for e := range recorder.Events {
				gotEvents = append(gotEvents, e)
			}
			sort.Strings(tt.wantedEvents)
			sort.Strings(gotEvents)
			assert.Equal(t, tt.wantedEvents, gotEvents, "hasNextPrivateKey() events")
		})
	}
}

func TestRoute_generateNextPrivateKey(t *testing.T) {
	tests := []struct {
		name                   string
		route                  *routev1.Route
		want                   error
		wantedEvents           []string
		wantedPrivateKeyHeader string
	}{
		{
			name: "route without algorithm annotation has no private key",
			route: &routev1.Route{
				ObjectMeta: metav1.ObjectMeta{
					Name:              "some-route",
					Namespace:         "some-namespace",
					CreationTimestamp: metav1.Time{Time: time.Now().Add(-time.Hour * 24 * 30)},
					Annotations: map[string]string{
						cmapi.IssuerNameAnnotationKey: "some-issuer",
					},
				},
				Spec: routev1.RouteSpec{},
			},
			want:                   nil,
			wantedEvents:           []string{"Normal Issuing Generated Private Key for route"},
			wantedPrivateKeyHeader: "BEGIN RSA PRIVATE KEY",
		},
		{
			name: "route with rsa algorithm annotation has no private key",
			route: &routev1.Route{
				ObjectMeta: metav1.ObjectMeta{
					Name:              "some-route",
					Namespace:         "some-namespace",
					CreationTimestamp: metav1.Time{Time: time.Now().Add(-time.Hour * 24 * 30)},
					Annotations: map[string]string{
						cmapi.IssuerNameAnnotationKey:          "some-issuer",
						cmapi.PrivateKeyAlgorithmAnnotationKey: "RSA",
					},
				},
				Spec: routev1.RouteSpec{
					Host: "some-host.some-domain.tld",
				},
			},
			want:                   nil,
			wantedEvents:           []string{"Normal Issuing Generated Private Key for route"},
			wantedPrivateKeyHeader: "BEGIN RSA PRIVATE KEY",
		},
		{
			name: "route with ecdsa algorithm annotation has no private key",
			route: &routev1.Route{
				ObjectMeta: metav1.ObjectMeta{
					Name:              "some-route",
					Namespace:         "some-namespace",
					CreationTimestamp: metav1.Time{Time: time.Now().Add(-time.Hour * 24 * 30)},
					Annotations: map[string]string{
						cmapi.IssuerNameAnnotationKey:          "some-issuer",
						cmapi.PrivateKeyAlgorithmAnnotationKey: "ECDSA",
					},
				},
				Spec: routev1.RouteSpec{
					Host: "some-host.some-domain.tld",
				},
			},
			want:                   nil,
			wantedEvents:           []string{"Normal Issuing Generated Private Key for route"},
			wantedPrivateKeyHeader: "BEGIN EC PRIVATE KEY",
		},
		{
			name: "route with invalid algorithm annotation has no private key",
			route: &routev1.Route{
				ObjectMeta: metav1.ObjectMeta{
					Name:              "some-route",
					Namespace:         "some-namespace",
					CreationTimestamp: metav1.Time{Time: time.Now().Add(-time.Hour * 24 * 30)},
					Annotations: map[string]string{
						cmapi.IssuerNameAnnotationKey:          "some-issuer",
						cmapi.PrivateKeyAlgorithmAnnotationKey: "notreal",
					},
				},
				Spec: routev1.RouteSpec{
					Host: "some-host.some-domain.tld",
				},
			},
			want:                   fmt.Errorf("invalid private key algorithm: notreal"),
			wantedEvents:           []string{"Warning InvalidPrivateKeyAlgorithm invalid private key algorithm: notreal"},
			wantedPrivateKeyHeader: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			recorder := record.NewFakeRecorder(100)
			fakeClient := fakeroutev1client.NewSimpleClientset()
			_, err := fakeClient.RouteV1().Routes(tt.route.Namespace).Create(context.TODO(), tt.route, metav1.CreateOptions{})
			assert.NoError(t, err, "fake client returned an error while creating route")
			r := &Route{
				eventRecorder: recorder,
				routeClient:   fakeClient,
			}
			err = r.generateNextPrivateKey(context.TODO(), tt.route)
			assert.Equal(t, tt.want, err, "generateNextPrivateKey()")
			close(recorder.Events)
			var gotEvents []string
			for e := range recorder.Events {
				gotEvents = append(gotEvents, e)
			}
			sort.Strings(tt.wantedEvents)
			sort.Strings(gotEvents)
			assert.Equal(t, tt.wantedEvents, gotEvents, "hasNextPrivateKey() events")
			// If generating the private key failed, there would not be a key to decode/validate
			if tt.want == nil {
				actualRoute, err := fakeClient.RouteV1().Routes(tt.route.Namespace).Get(context.TODO(), tt.route.Name, metav1.GetOptions{})
				assert.NoError(t, err)
				_, err = utilpki.DecodePrivateKeyBytes([]byte(actualRoute.Annotations[cmapi.IsNextPrivateKeySecretLabelKey]))
				assert.NoError(t, err)
				assert.Contains(t, actualRoute.Annotations[cmapi.IsNextPrivateKeySecretLabelKey], tt.wantedPrivateKeyHeader)
			}
		})
	}
}

func Test_getCurrentRevision(t *testing.T) {
	tests := []struct {
		name    string
		route   *routev1.Route
		want    int
		wantErr error
	}{
		{
			name: "route with revision",
			route: &routev1.Route{
				ObjectMeta: metav1.ObjectMeta{
					Name:              "some-route",
					Namespace:         "some-namespace",
					CreationTimestamp: metav1.Time{Time: time.Now().Add(-time.Hour * 24 * 30)},
					Annotations: map[string]string{
						cmapi.IssuerNameAnnotationKey:                 "some-issuer",
						cmapi.CertificateRequestRevisionAnnotationKey: "1337",
					},
				},
				Spec: routev1.RouteSpec{},
			},
			want:    1337,
			wantErr: nil,
		},
		{
			name: "route without revision",
			route: &routev1.Route{
				ObjectMeta: metav1.ObjectMeta{
					Name:              "some-route",
					Namespace:         "some-namespace",
					CreationTimestamp: metav1.Time{Time: time.Now().Add(-time.Hour * 24 * 30)},
					Annotations: map[string]string{
						cmapi.IssuerNameAnnotationKey: "some-issuer",
					},
				},
				Spec: routev1.RouteSpec{},
			},
			want:    0,
			wantErr: fmt.Errorf("no revision found"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := getCurrentRevision(tt.route)
			assert.Equal(t, tt.want, got, "getCurrentRevision()")
			assert.Equal(t, tt.wantErr, err, "getCurrentRevision()")
		})
	}
}

func TestRoute_setRevision(t *testing.T) {
	tests := []struct {
		name     string
		route    *routev1.Route
		revision int
		want     string
		wantErr  error
	}{
		{
			name: "setting revision works",
			route: &routev1.Route{
				ObjectMeta: metav1.ObjectMeta{
					Name:              "some-route",
					Namespace:         "some-namespace",
					CreationTimestamp: metav1.Time{Time: time.Now().Add(-time.Hour * 24 * 30)},
					Annotations: map[string]string{
						cmapi.IssuerNameAnnotationKey: "some-issuer",
					},
				},
				Spec: routev1.RouteSpec{},
			},
			revision: 1337,
			want:     "1337",
			wantErr:  nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fakeClient := fakeroutev1client.NewSimpleClientset()
			_, err := fakeClient.RouteV1().Routes(tt.route.Namespace).Create(context.TODO(), tt.route, metav1.CreateOptions{})
			assert.NoError(t, err, "fake client returned an error while creating route")
			r := &Route{
				routeClient: fakeClient,
			}
			err = r.setRevision(context.TODO(), tt.route, tt.revision)
			assert.Equal(t, tt.wantErr, err, "setRevision()")
			actualRoute, err := fakeClient.RouteV1().Routes(tt.route.Namespace).Get(context.TODO(), tt.route.Name, metav1.GetOptions{})
			assert.NoError(t, err)
			assert.Equal(t, tt.want, actualRoute.Annotations[cmapi.CertificateRequestRevisionAnnotationKey], "setRevision()")
		})
	}
}

func TestRoute_buildNextCR(t *testing.T) {
	// set up key for test cases
	rsaKey, err := rsa.GenerateKey(rand.Reader, 4096)
	require.NoError(t, err)
	rsaPEM, err := utilpki.EncodePKCS8PrivateKey(rsaKey)
	require.NoError(t, err)
	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	ecdsaPEM, err := utilpki.EncodePKCS8PrivateKey(ecdsaKey)
	require.NoError(t, err)

	tests := []struct {
		name       string
		route      *routev1.Route
		revision   int
		want       *cmapi.CertificateRequest
		wantErr    error
		wantCSR    *x509.CertificateRequest
		wantEvents []string
	}{
		{
			name:     "Basic test with duration and hostname",
			revision: 1337,
			route: generateRouteStatus(&routev1.Route{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "some-route",
					Namespace: "some-namespace",
					Annotations: map[string]string{
						cmapi.DurationAnnotationKey:          "42m",
						cmapi.IsNextPrivateKeySecretLabelKey: string(rsaPEM),
					},
				},
				Spec: routev1.RouteSpec{
					Host: "some-host.some-domain.tld",
				},
				Status: routev1.RouteStatus{
					Ingress: []routev1.RouteIngress{
						{
							Host: "some-host.some-domain.tld",
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
			want: &cmapi.CertificateRequest{
				ObjectMeta: metav1.ObjectMeta{
					GenerateName: "some-route-",
					Namespace:    "some-namespace",
					Annotations: map[string]string{
						cmapi.CertificateRequestRevisionAnnotationKey: "1338",
					},
				},
				Spec: cmapi.CertificateRequestSpec{
					Duration: &metav1.Duration{Duration: 42 * time.Minute},
					IsCA:     false,
					Usages:   []cmapi.KeyUsage{cmapi.UsageServerAuth, cmapi.UsageDigitalSignature, cmapi.UsageKeyEncipherment},
				},
			},
			wantErr: nil,
		},
		{
			name:     "Basic test with issuer",
			revision: 1337,
			route: generateRouteStatus(&routev1.Route{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "some-route",
					Namespace: "some-namespace",
					Annotations: map[string]string{
						cmapi.DurationAnnotationKey:          "42m",
						cmapi.IsNextPrivateKeySecretLabelKey: string(rsaPEM),
						cmapi.IssuerNameAnnotationKey:        "self-signed-issuer",
						cmapi.IssuerKindAnnotationKey:        "Issuer",
					},
				},
				Spec: routev1.RouteSpec{
					Host: "some-host.some-domain.tld",
				},
				Status: routev1.RouteStatus{
					Ingress: []routev1.RouteIngress{
						{
							Host: "some-host.some-domain.tld",
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
			want: &cmapi.CertificateRequest{
				ObjectMeta: metav1.ObjectMeta{
					GenerateName: "some-route-",
					Namespace:    "some-namespace",
					Annotations: map[string]string{
						cmapi.CertificateRequestRevisionAnnotationKey: "1338",
					},
				},
				Spec: cmapi.CertificateRequestSpec{
					Duration: &metav1.Duration{Duration: 42 * time.Minute},
					IsCA:     false,
					Usages:   []cmapi.KeyUsage{cmapi.UsageServerAuth, cmapi.UsageDigitalSignature, cmapi.UsageKeyEncipherment},
					IssuerRef: cmmeta.ObjectReference{
						Name: "self-signed-issuer",
						Kind: "Issuer",
					},
				},
			},
			wantErr: nil,
		},
		{
			name:     "Basic test with external issuer",
			revision: 1337,
			route: generateRouteStatus(&routev1.Route{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "some-route",
					Namespace: "some-namespace",
					Annotations: map[string]string{
						cmapi.DurationAnnotationKey:          "42m",
						cmapi.IsNextPrivateKeySecretLabelKey: string(rsaPEM),
						cmapi.IssuerKindAnnotationKey:        "Issuer",
						cmapi.IssuerNameAnnotationKey:        "self-signed-issuer",
						cmapi.IssuerGroupAnnotationKey:       "external-issuer.io",
					},
				},
				Spec: routev1.RouteSpec{
					Host: "some-host.some-domain.tld",
				},
				Status: routev1.RouteStatus{
					Ingress: []routev1.RouteIngress{
						{
							Host: "some-host.some-domain.tld",
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
			want: &cmapi.CertificateRequest{
				ObjectMeta: metav1.ObjectMeta{
					GenerateName: "some-route-",
					Namespace:    "some-namespace",
					Annotations: map[string]string{
						cmapi.CertificateRequestRevisionAnnotationKey: "1338",
					},
				},
				Spec: cmapi.CertificateRequestSpec{
					Duration: &metav1.Duration{Duration: 42 * time.Minute},
					IsCA:     false,
					Usages:   []cmapi.KeyUsage{cmapi.UsageServerAuth, cmapi.UsageDigitalSignature, cmapi.UsageKeyEncipherment},
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
			name:     "Basic test with alternate ingress issuer name annotation",
			revision: 1337,
			route: generateRouteStatus(&routev1.Route{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "some-route",
					Namespace: "some-namespace",
					Annotations: map[string]string{
						cmapi.DurationAnnotationKey:          "42m",
						cmapi.IsNextPrivateKeySecretLabelKey: string(rsaPEM),
						cmapi.IssuerKindAnnotationKey:        "Issuer",
						cmapi.IngressIssuerNameAnnotationKey: "self-signed-issuer",
						cmapi.IssuerGroupAnnotationKey:       "external-issuer.io",
					},
				},
				Spec: routev1.RouteSpec{
					Host: "some-host.some-domain.tld",
				},
				Status: routev1.RouteStatus{
					Ingress: []routev1.RouteIngress{
						{
							Host: "some-host.some-domain.tld",
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
			want: &cmapi.CertificateRequest{
				ObjectMeta: metav1.ObjectMeta{
					GenerateName: "some-route-",
					Namespace:    "some-namespace",
					Annotations: map[string]string{
						cmapi.CertificateRequestRevisionAnnotationKey: "1338",
					},
				},
				Spec: cmapi.CertificateRequestSpec{
					Duration: &metav1.Duration{Duration: 42 * time.Minute},
					IsCA:     false,
					Usages:   []cmapi.KeyUsage{cmapi.UsageServerAuth, cmapi.UsageDigitalSignature, cmapi.UsageKeyEncipherment},
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
			name:     "With subdomain and multiple ICs",
			revision: 1337,
			route: &routev1.Route{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "some-route-with-subdomain",
					Namespace: "some-namespace",
					Annotations: map[string]string{
						cmapi.IsNextPrivateKeySecretLabelKey: string(rsaPEM),
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
			want: &cmapi.CertificateRequest{
				ObjectMeta: metav1.ObjectMeta{
					GenerateName: "some-route-with-subdomain-",
					Namespace:    "some-namespace",
					Annotations: map[string]string{
						cmapi.CertificateRequestRevisionAnnotationKey: "1338",
					},
				},
				Spec: cmapi.CertificateRequestSpec{
					Duration: &metav1.Duration{Duration: DefaultCertificateDuration},
					Usages:   []cmapi.KeyUsage{cmapi.UsageServerAuth, cmapi.UsageDigitalSignature, cmapi.UsageKeyEncipherment},
				},
			},
			wantCSR: &x509.CertificateRequest{
				SignatureAlgorithm: x509.SHA256WithRSA,
				PublicKeyAlgorithm: x509.RSA,
				Subject: pkix.Name{
					CommonName: "",
				},
				DNSNames:    []string{"some-sub-domain.some-domain.tld", "some-sub-domain.some-other-ic.example.com"},
				IPAddresses: []net.IP(nil),
				URIs:        []*url.URL(nil),
			},
			wantErr: nil,
		},
		{
			name:     "With ECDSA private key algorithm annotation",
			revision: 1337,
			route: generateRouteStatus(&routev1.Route{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "some-route",
					Namespace: "some-namespace",
					Annotations: map[string]string{
						cmapi.IsNextPrivateKeySecretLabelKey:   string(ecdsaPEM),
						cmapi.PrivateKeyAlgorithmAnnotationKey: string(cmapi.ECDSAKeyAlgorithm),
					},
				},
				Spec: routev1.RouteSpec{
					Host: "some-host.some-domain.tld",
				},
				Status: routev1.RouteStatus{
					Ingress: []routev1.RouteIngress{
						{
							Host: "some-host.some-domain.tld",
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
			want: &cmapi.CertificateRequest{
				ObjectMeta: metav1.ObjectMeta{
					GenerateName: "some-route-",
					Namespace:    "some-namespace",
					Annotations: map[string]string{
						cmapi.CertificateRequestRevisionAnnotationKey: "1338",
					},
				},
				Spec: cmapi.CertificateRequestSpec{
					Usages:   []cmapi.KeyUsage{cmapi.UsageServerAuth, cmapi.UsageDigitalSignature, cmapi.UsageKeyEncipherment},
					Duration: &metav1.Duration{Duration: DefaultCertificateDuration},
				},
			},
			wantCSR: &x509.CertificateRequest{
				SignatureAlgorithm: x509.ECDSAWithSHA256,
				PublicKeyAlgorithm: x509.ECDSA,
				Subject: pkix.Name{
					CommonName: "",
				},
				DNSNames:    []string{"some-host.some-domain.tld"},
				IPAddresses: []net.IP(nil),
				URIs:        []*url.URL(nil),
			},
			wantErr: nil,
		},
		{
			name:     "With ECDSA 384 private key algorithm and size annotation",
			revision: 1337,
			route: generateRouteStatus(&routev1.Route{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "some-route",
					Namespace: "some-namespace",
					Annotations: map[string]string{
						cmapi.IsNextPrivateKeySecretLabelKey:   string(ecdsaPEM),
						cmapi.PrivateKeyAlgorithmAnnotationKey: string(cmapi.ECDSAKeyAlgorithm),
						cmapi.PrivateKeySizeAnnotationKey:      strconv.Itoa(384),
					},
				},
				Spec: routev1.RouteSpec{
					Host: "some-host.some-domain.tld",
				},
				Status: routev1.RouteStatus{
					Ingress: []routev1.RouteIngress{
						{
							Host: "some-host.some-domain.tld",
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
			want: &cmapi.CertificateRequest{
				ObjectMeta: metav1.ObjectMeta{
					GenerateName: "some-route-",
					Namespace:    "some-namespace",
					Annotations: map[string]string{
						cmapi.CertificateRequestRevisionAnnotationKey: "1338",
					},
				},
				Spec: cmapi.CertificateRequestSpec{
					Usages:   []cmapi.KeyUsage{cmapi.UsageServerAuth, cmapi.UsageDigitalSignature, cmapi.UsageKeyEncipherment},
					Duration: &metav1.Duration{Duration: DefaultCertificateDuration},
				},
			},
			wantCSR: &x509.CertificateRequest{
				SignatureAlgorithm: x509.ECDSAWithSHA256,
				PublicKeyAlgorithm: x509.ECDSA,
				Subject: pkix.Name{
					CommonName: "",
				},
				DNSNames:    []string{"some-host.some-domain.tld"},
				IPAddresses: []net.IP(nil),
				URIs:        []*url.URL(nil),
			},
			wantErr: nil,
		},
		{
			name:     "With ECDSA 521 private key algorithm and size annotation",
			revision: 1337,
			route: generateRouteStatus(&routev1.Route{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "some-route",
					Namespace: "some-namespace",
					Annotations: map[string]string{
						cmapi.IsNextPrivateKeySecretLabelKey:   string(ecdsaPEM),
						cmapi.PrivateKeyAlgorithmAnnotationKey: string(cmapi.ECDSAKeyAlgorithm),
						cmapi.PrivateKeySizeAnnotationKey:      strconv.Itoa(521),
					},
				},
				Spec: routev1.RouteSpec{
					Host: "some-host.some-domain.tld",
				},
				Status: routev1.RouteStatus{
					Ingress: []routev1.RouteIngress{
						{
							Host: "some-host.some-domain.tld",
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
			want: &cmapi.CertificateRequest{
				ObjectMeta: metav1.ObjectMeta{
					GenerateName: "some-route-",
					Namespace:    "some-namespace",
					Annotations: map[string]string{
						cmapi.CertificateRequestRevisionAnnotationKey: "1338",
					},
				},
				Spec: cmapi.CertificateRequestSpec{
					Usages:   []cmapi.KeyUsage{cmapi.UsageServerAuth, cmapi.UsageDigitalSignature, cmapi.UsageKeyEncipherment},
					Duration: &metav1.Duration{Duration: DefaultCertificateDuration},
				},
			},
			wantCSR: &x509.CertificateRequest{
				SignatureAlgorithm: x509.ECDSAWithSHA256,
				PublicKeyAlgorithm: x509.ECDSA,
				Subject: pkix.Name{
					CommonName: "",
				},
				DNSNames:    []string{"some-host.some-domain.tld"},
				IPAddresses: []net.IP(nil),
				URIs:        []*url.URL(nil),
			},
			wantErr: nil,
		},
		{
			name:     "With RSA private key algorithm annotation",
			revision: 1337,
			route: generateRouteStatus(&routev1.Route{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "some-route",
					Namespace: "some-namespace",
					Annotations: map[string]string{
						cmapi.IsNextPrivateKeySecretLabelKey:   string(rsaPEM),
						cmapi.PrivateKeyAlgorithmAnnotationKey: string(cmapi.RSAKeyAlgorithm),
					},
				},
				Spec: routev1.RouteSpec{
					Host: "some-host.some-domain.tld",
				},
				Status: routev1.RouteStatus{
					Ingress: []routev1.RouteIngress{
						{
							Host: "some-host.some-domain.tld",
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
			want: &cmapi.CertificateRequest{
				ObjectMeta: metav1.ObjectMeta{
					GenerateName: "some-route-",
					Namespace:    "some-namespace",
					Annotations: map[string]string{
						cmapi.CertificateRequestRevisionAnnotationKey: "1338",
					},
				},
				Spec: cmapi.CertificateRequestSpec{
					Usages:   []cmapi.KeyUsage{cmapi.UsageServerAuth, cmapi.UsageDigitalSignature, cmapi.UsageKeyEncipherment},
					Duration: &metav1.Duration{Duration: DefaultCertificateDuration},
				},
			},
			wantCSR: &x509.CertificateRequest{
				SignatureAlgorithm: x509.SHA256WithRSA,
				PublicKeyAlgorithm: x509.RSA,
				Subject: pkix.Name{
					CommonName: "",
				},
				DNSNames:    []string{"some-host.some-domain.tld"},
				IPAddresses: []net.IP(nil),
				URIs:        []*url.URL(nil),
			},
			wantErr: nil,
		},
		{
			name:     "With RSA 3072 private key algorithm and size annotation",
			revision: 1337,
			route: generateRouteStatus(&routev1.Route{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "some-route",
					Namespace: "some-namespace",
					Annotations: map[string]string{
						cmapi.IsNextPrivateKeySecretLabelKey:   string(rsaPEM),
						cmapi.PrivateKeyAlgorithmAnnotationKey: string(cmapi.RSAKeyAlgorithm),
						cmapi.PrivateKeySizeAnnotationKey:      strconv.Itoa(3072),
					},
				},
				Spec: routev1.RouteSpec{
					Host: "some-host.some-domain.tld",
				},
				Status: routev1.RouteStatus{
					Ingress: []routev1.RouteIngress{
						{
							Host: "some-host.some-domain.tld",
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
			want: &cmapi.CertificateRequest{
				ObjectMeta: metav1.ObjectMeta{
					GenerateName: "some-route-",
					Namespace:    "some-namespace",
					Annotations: map[string]string{
						cmapi.CertificateRequestRevisionAnnotationKey: "1338",
					},
				},
				Spec: cmapi.CertificateRequestSpec{
					Usages:   []cmapi.KeyUsage{cmapi.UsageServerAuth, cmapi.UsageDigitalSignature, cmapi.UsageKeyEncipherment},
					Duration: &metav1.Duration{Duration: DefaultCertificateDuration},
				},
			},
			wantCSR: &x509.CertificateRequest{
				SignatureAlgorithm: x509.SHA384WithRSA,
				PublicKeyAlgorithm: x509.RSA,
				Subject: pkix.Name{
					CommonName: "",
				},
				DNSNames:    []string{"some-host.some-domain.tld"},
				IPAddresses: []net.IP(nil),
				URIs:        []*url.URL(nil),
			},
			wantErr: nil,
		},
		{
			name:     "With RSA 3072 private key algorithm and size annotation",
			revision: 1337,
			route: generateRouteStatus(&routev1.Route{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "some-route",
					Namespace: "some-namespace",
					Annotations: map[string]string{
						cmapi.IsNextPrivateKeySecretLabelKey:   string(rsaPEM),
						cmapi.PrivateKeyAlgorithmAnnotationKey: string(cmapi.RSAKeyAlgorithm),
						cmapi.PrivateKeySizeAnnotationKey:      strconv.Itoa(4096),
					},
				},
				Spec: routev1.RouteSpec{
					Host: "some-host.some-domain.tld",
				},
				Status: routev1.RouteStatus{
					Ingress: []routev1.RouteIngress{
						{
							Host: "some-host.some-domain.tld",
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
			want: &cmapi.CertificateRequest{
				ObjectMeta: metav1.ObjectMeta{
					GenerateName: "some-route-",
					Namespace:    "some-namespace",
					Annotations: map[string]string{
						cmapi.CertificateRequestRevisionAnnotationKey: "1338",
					},
				},
				Spec: cmapi.CertificateRequestSpec{
					Usages:   []cmapi.KeyUsage{cmapi.UsageServerAuth, cmapi.UsageDigitalSignature, cmapi.UsageKeyEncipherment},
					Duration: &metav1.Duration{Duration: DefaultCertificateDuration},
				},
			},
			wantCSR: &x509.CertificateRequest{
				SignatureAlgorithm: x509.SHA512WithRSA,
				PublicKeyAlgorithm: x509.RSA,
				Subject: pkix.Name{
					CommonName: "",
				},
				DNSNames:    []string{"some-host.some-domain.tld"},
				IPAddresses: []net.IP(nil),
				URIs:        []*url.URL(nil),
			},
			wantErr: nil,
		},
		{
			name:     "With subject annotations",
			revision: 1337,
			route: &routev1.Route{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "some-route-with-subject-annotations",
					Namespace: "some-namespace",
					Annotations: map[string]string{
						cmapi.IsNextPrivateKeySecretLabelKey:          string(rsaPEM),
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
					Host: "example-route.example.com",
				},
				Status: routev1.RouteStatus{
					Ingress: []routev1.RouteIngress{
						{
							Host: "example-route.example.com",
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
			want: &cmapi.CertificateRequest{
				ObjectMeta: metav1.ObjectMeta{
					GenerateName: "some-route-with-subject-annotations-",
					Namespace:    "some-namespace",
					Annotations: map[string]string{
						cmapi.CertificateRequestRevisionAnnotationKey: "1338",
					},
				},
				Spec: cmapi.CertificateRequestSpec{
					Duration: &metav1.Duration{Duration: DefaultCertificateDuration},
					Usages:   []cmapi.KeyUsage{cmapi.UsageServerAuth, cmapi.UsageDigitalSignature, cmapi.UsageKeyEncipherment},
				},
			},
			wantCSR: &x509.CertificateRequest{
				SignatureAlgorithm: x509.SHA256WithRSA,
				PublicKeyAlgorithm: x509.RSA,
				Subject: pkix.Name{
					CommonName:         "",
					Organization:       []string{"Company 1", "Company 2"},
					OrganizationalUnit: []string{"Tech Division", "Other Division"},
					Country:            []string{"Country 1", "Country 2"},
					Province:           []string{"Province 1", "Province 2"},
					Locality:           []string{"City 1", "City 2"},
					PostalCode:         []string{"123ABC", "456DEF"},
					StreetAddress:      []string{"123 Example St", "456 Example Ave"},
					SerialNumber:       "10978342379280287615",
				},
				DNSNames:    []string{"example-route.example.com"},
				IPAddresses: []net.IP{},
				URIs:        []*url.URL{},
			},
			wantErr: nil,
		},
		{
			name:     "With all annotations",
			revision: 1337,
			route: &routev1.Route{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "some-route-with-all-annotations",
					Namespace: "some-namespace",
					Annotations: map[string]string{
						cmapi.IsNextPrivateKeySecretLabelKey:          string(rsaPEM),
						cmapi.DurationAnnotationKey:                   "720h",
						cmapi.IPSANAnnotationKey:                      "10.20.30.40,192.168.192.168",
						cmapi.AltNamesAnnotationKey:                   "mycooldomain.com,mysecondarydomain.com",
						cmapi.URISANAnnotationKey:                     "spiffe://trustdomain/workload",
						cmapi.CommonNameAnnotationKey:                 "mycommonname.com",
						cmapi.EmailsAnnotationKey:                     "email@example.com",
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
					Host: "example-route.example.com",
				},
				Status: routev1.RouteStatus{
					Ingress: []routev1.RouteIngress{
						{
							Host: "example-route.example.com",
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
			want: &cmapi.CertificateRequest{
				ObjectMeta: metav1.ObjectMeta{
					GenerateName: "some-route-with-all-annotations-",
					Namespace:    "some-namespace",
					Annotations: map[string]string{
						cmapi.CertificateRequestRevisionAnnotationKey: "1338",
					},
				},
				Spec: cmapi.CertificateRequestSpec{
					Duration: &metav1.Duration{Duration: time.Hour * 24 * 30},
					Usages:   []cmapi.KeyUsage{cmapi.UsageServerAuth, cmapi.UsageDigitalSignature, cmapi.UsageKeyEncipherment},
				},
			},
			wantCSR: &x509.CertificateRequest{
				SignatureAlgorithm: x509.SHA256WithRSA,
				PublicKeyAlgorithm: x509.RSA,
				Subject: pkix.Name{
					CommonName:         "mycommonname.com",
					Organization:       []string{"Company 1", "Company 2"},
					OrganizationalUnit: []string{"Tech Division", "Other Division"},
					Country:            []string{"Country 1", "Country 2"},
					Province:           []string{"Province 1", "Province 2"},
					Locality:           []string{"City 1", "City 2"},
					PostalCode:         []string{"123ABC", "456DEF"},
					StreetAddress:      []string{"123 Example St", "456 Example Ave"},
					SerialNumber:       "10978342379280287615",
				},
				DNSNames:       []string{"example-route.example.com", "mycooldomain.com", "mysecondarydomain.com"},
				IPAddresses:    []net.IP{net.IPv4(10, 20, 30, 40), net.IPv4(192, 168, 192, 168)},
				URIs:           []*url.URL{{Scheme: "spiffe", Host: "trustdomain", Path: "workload"}},
				EmailAddresses: []string{"email@example.com"},
			},
			wantErr: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			recorder := record.NewFakeRecorder(100)
			r := &Route{
				eventRecorder: recorder,
			}
			// test "buildNextCR" function
			cr, err := r.buildNextCR(context.TODO(), tt.route, tt.revision)

			// check that we got the expected error (including nil)
			assert.Equal(t, tt.wantErr, err, "buildNextCR()")

			// check that the returned object is as expected
			assert.Equal(t, tt.want.ObjectMeta.GenerateName, cr.ObjectMeta.GenerateName)
			assert.Equal(t, tt.want.ObjectMeta.Namespace, cr.ObjectMeta.Namespace)
			assert.Equal(t, tt.want.ObjectMeta.Annotations, cr.ObjectMeta.Annotations)
			assert.Equal(t, tt.want.ObjectMeta.Labels, cr.ObjectMeta.Labels)
			assert.Equal(t, tt.want.Spec.Duration, cr.Spec.Duration)
			assert.Equal(t, tt.want.Spec.IsCA, cr.Spec.IsCA)
			assert.Equal(t, tt.want.Spec.Usages, cr.Spec.Usages)
			assert.Equal(t, tt.want.Spec.IssuerRef, cr.Spec.IssuerRef)

			// check the CSR
			if tt.wantCSR != nil {
				var privateKey any
				if tt.wantCSR.PublicKeyAlgorithm == x509.ECDSA {
					privateKey = ecdsaKey
				} else if tt.wantCSR.PublicKeyAlgorithm == x509.RSA {
					privateKey = rsaKey
				}
				csr, err := x509.CreateCertificateRequest(rand.Reader, tt.wantCSR, privateKey)
				assert.NoError(t, err)

				if tt.wantCSR.PublicKeyAlgorithm == x509.ECDSA {
					// The signature for a ECDSA CSR varies based on a random number, therefore we can not expect
					// the CSR to be identical like we can for RSA. Instead, compare the CSR excluding the signature.
					parsedCSR, err := x509.ParseCertificateRequest(csr)
					assert.NoError(t, err)
					assert.Equal(t, tt.wantCSR.DNSNames, parsedCSR.DNSNames)
					assert.Equal(t, tt.wantCSR.IPAddresses, parsedCSR.IPAddresses)
					assert.Equal(t, tt.wantCSR.PublicKeyAlgorithm, parsedCSR.PublicKeyAlgorithm)
					assert.Equal(t, tt.wantCSR.SignatureAlgorithm, parsedCSR.SignatureAlgorithm)
					assert.Equal(t, tt.wantCSR.Subject.CommonName, parsedCSR.Subject.CommonName)
					assert.Equal(t, tt.wantCSR.URIs, parsedCSR.URIs)

				} else if tt.wantCSR.PublicKeyAlgorithm == x509.RSA {
					csrPEM := pem.EncodeToMemory(&pem.Block{
						Type:  "CERTIFICATE REQUEST",
						Bytes: csr,
					})
					assert.Equal(t, cr.Spec.Request, csrPEM)
				}
			}

			// check the events that were generated
			close(recorder.Events)
			if len(tt.wantEvents) > 0 {
				var gotEvents []string
				for e := range recorder.Events {
					gotEvents = append(gotEvents, e)
				}
				sort.Strings(tt.wantEvents)
				sort.Strings(gotEvents)
				assert.Equal(t, tt.wantEvents, gotEvents, "buildNextCR() events")
			}

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
