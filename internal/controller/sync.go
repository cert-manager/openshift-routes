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
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	cmapiutil "github.com/cert-manager/cert-manager/pkg/api/util"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	utilpki "github.com/cert-manager/cert-manager/pkg/util/pki"
	routev1 "github.com/openshift/api/route/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

const (
	ReasonIssuing                    = `Issuing`
	ReasonInvalidKey                 = `InvalidKey`
	ReasonInvalidPrivateKeyAlgorithm = `InvalidPrivateKeyAlgorithm`
	ReasonInvalidPrivateKeySize      = `InvalidPrivateKeySize`
	ReasonInvalidValue               = `InvalidValue`
	ReasonInternalReconcileError     = `InternalReconcileError`
	ReasonMissingHostname            = `MissingHostname`
)

const DefaultCertificateDuration = time.Hour * 24 * 90 // 90 days

// sync reconciles an Openshift route.
func (r *Route) sync(ctx context.Context, req reconcile.Request, route *routev1.Route) (reconcile.Result, error) {
	var result reconcile.Result
	var err error

	log := r.log.WithName("sync").WithValues("route", req, "resourceVersion", route.ObjectMeta.ResourceVersion)
	defer func() {
		// Always send a warning event if err is not nil
		if err != nil {
			r.log.V(1).Error(err, "error while reconciling", "object", req.NamespacedName)
			r.eventRecorder.Event(route, corev1.EventTypeWarning, ReasonInternalReconcileError, "error while reconciling: "+err.Error())
		}
	}()

	// Does the route contain a valid certificate?
	if r.hasValidCertificate(route) {
		result, err = reconcile.Result{RequeueAfter: r.getRequeueAfterDuration(route)}, nil
		log.V(5).Info("route has valid cert")
		return result, err
	}
	// Do we have a revision? If not set revision to 0
	revision, err := getCurrentRevision(route)
	if err != nil {
		err = r.setRevision(ctx, route, 0)
		log.V(5).Info("generated revision 0")
		return result, err
	}
	// Do we have a next key?
	if !r.hasNextPrivateKey(route) {
		err = r.generateNextPrivateKey(ctx, route)
		log.V(5).Info("generated next private key for route")
		return result, err
	}
	// Is there a CertificateRequest for the Next revision? If not, make it.
	hasNext, err := r.hasNextCR(ctx, route, revision)
	if err != nil {
		return result, err
	}
	if !hasNext {
		// generate manifest for new CR
		log.V(5).Info("route has no matching certificate request", "revision", revision)
		var cr *cmapi.CertificateRequest
		cr, err = r.buildNextCR(ctx, route, revision)
		if err != nil {
			log.V(1).Error(err, "error generating certificate request", "object", req.NamespacedName)
			// Not a reconcile error, so don't retry this revision
			return result, nil
		}

		// create CR and return. We own the CR so it will cause a re-reconcile
		_, err = r.certClient.CertmanagerV1().CertificateRequests(route.Namespace).Create(ctx, cr, metav1.CreateOptions{})
		if err != nil {
			return result, err
		}
		r.eventRecorder.Event(route, corev1.EventTypeNormal, ReasonIssuing, "Created new CertificateRequest for Route %s")
		return result, nil

	}
	// is the CR Ready and Approved?
	ready, cr, err := r.certificateRequestReadyAndApproved(ctx, route, revision)
	if err != nil {
		return result, err
	}
	if !ready {
		log.V(5).Info("cr is not ready yet")
		return result, nil
	}
	// Cert is ready. Populate the route.
	err = r.populateRoute(ctx, route, cr, revision)
	log.V(5).Info("populated route cert")
	return result, err
}

func (r *Route) hasValidCertificate(route *routev1.Route) bool {
	// Valid certificate predicates:

	// TLS config set?
	if route.Spec.TLS == nil {
		r.eventRecorder.Event(route, corev1.EventTypeNormal, ReasonIssuing, "Issuing cert as no TLS is configured")
		return false
	}
	// Cert exists?
	if len(route.Spec.TLS.Certificate) == 0 {
		r.eventRecorder.Event(route, corev1.EventTypeNormal, ReasonIssuing, "Issuing cert as no certificate exists")
		return false
	}
	// Cert parses?
	cert, err := utilpki.DecodeX509CertificateBytes([]byte(route.Spec.TLS.Certificate))
	if err != nil {
		r.eventRecorder.Event(route, corev1.EventTypeNormal, ReasonIssuing, "Issuing cert as the existing cert is invalid: "+err.Error())
		return false
	}
	// Key exists?
	if len(route.Spec.TLS.Key) == 0 {
		r.eventRecorder.Event(route, corev1.EventTypeNormal, ReasonIssuing, "Issuing cert as no private key exists")
		return false
	}
	// Key parses?
	key, err := utilpki.DecodePrivateKeyBytes([]byte(route.Spec.TLS.Key))
	if err != nil {
		r.eventRecorder.Event(route, corev1.EventTypeNormal, ReasonIssuing, "Issuing cert as the existing key is invalid: "+err.Error())
		return false
	}
	// Cert matches key?
	matches, err := utilpki.PublicKeyMatchesCertificate(key.Public(), cert)
	if err != nil {
		r.eventRecorder.Event(route, corev1.EventTypeNormal, ReasonIssuing, "Issuing cert as the certificate's key type is invalid: "+err.Error())
	}
	if !matches {
		r.eventRecorder.Event(route, corev1.EventTypeNormal, ReasonIssuing, "Issuing cert as the public key does not match the certificate")
		return false
	}
	// Cert matches Route hostname?
	hostnames := getRouteHostnames(route)
	for _, host := range hostnames {
		if err := cert.VerifyHostname(host); err != nil {
			r.eventRecorder.Event(route, corev1.EventTypeNormal, ReasonIssuing, "Issuing cert as the hostname does not match the certificate")
			return false
		}
	}
	// Still not after the renew-before window?
	if metav1.HasAnnotation(route.ObjectMeta, cmapi.RenewBeforeAnnotationKey) {
		renewBeforeDuration, err := time.ParseDuration(route.Annotations[cmapi.RenewBeforeAnnotationKey])
		if err == nil {
			if time.Now().After(cert.NotAfter.Add(-renewBeforeDuration)) {
				r.eventRecorder.Event(route, corev1.EventTypeNormal, ReasonIssuing, "Issuing cert as the renew-before period has been reached")
				return false
			}
		} else {
			r.eventRecorder.Eventf(
				route,
				corev1.EventTypeWarning,
				ReasonInvalidKey,
				"the duration %s: %s is invalid (%s)",
				cmapi.RenewBeforeAnnotationKey,
				route.Annotations[cmapi.RenewBeforeAnnotationKey],
				err.Error(),
			)
		}
	}
	// As there is no renew-before, is the cert more than 2/3 through its life?
	totalDuration := cert.NotAfter.Sub(cert.NotBefore)
	timeToExpiry := cert.NotAfter.Sub(time.Now())
	if timeToExpiry < (totalDuration * 1 / 3) {
		r.eventRecorder.Event(route, corev1.EventTypeNormal, ReasonIssuing, "Issuing cert as the existing cert is more than 2/3 through its validity period")
		return false
	}
	return true
}

func (r *Route) hasNextPrivateKey(route *routev1.Route) bool {
	if metav1.HasAnnotation(route.ObjectMeta, cmapi.IsNextPrivateKeySecretLabelKey) {
		// Check if the key is valid
		_, err := utilpki.DecodePrivateKeyBytes([]byte(route.Annotations[cmapi.IsNextPrivateKeySecretLabelKey]))
		if err != nil {
			r.eventRecorder.Event(route, corev1.EventTypeWarning, ReasonInvalidKey, "Regenerating Next Private Key as the existing key is invalid: "+err.Error())
			return false
		}
		return true
	}
	return false
}

func (r *Route) generateNextPrivateKey(ctx context.Context, route *routev1.Route) error {
	privateKeyAlgorithm, found := route.Annotations[cmapi.PrivateKeyAlgorithmAnnotationKey]
	if !found {
		privateKeyAlgorithm = string(cmapi.RSAKeyAlgorithm)
	}

	var privateKeySize int
	privateKeySizeStr, found := route.Annotations[cmapi.PrivateKeySizeAnnotationKey]
	if found {
		var err error
		privateKeySize, err = strconv.Atoi(privateKeySizeStr)
		if err != nil {
			r.eventRecorder.Event(route, corev1.EventTypeWarning, ReasonInvalidPrivateKeySize, "invalid private key size:"+privateKeySizeStr)
			return fmt.Errorf("invalid private key size, %s: %v", privateKeySizeStr, err)
		}
	} else {
		switch privateKeyAlgorithm {
		case string(cmapi.ECDSAKeyAlgorithm):
			privateKeySize = utilpki.ECCurve256
		case string(cmapi.RSAKeyAlgorithm):
			privateKeySize = utilpki.MinRSAKeySize
		}
	}

	var privateKey crypto.PrivateKey
	var err error
	switch privateKeyAlgorithm {
	case string(cmapi.ECDSAKeyAlgorithm):
		privateKey, err = utilpki.GenerateECPrivateKey(privateKeySize)
		if err != nil {
			return fmt.Errorf("could not generate ECDSA key: %w", err)
		}
	case string(cmapi.RSAKeyAlgorithm):
		privateKey, err = utilpki.GenerateRSAPrivateKey(privateKeySize)
		if err != nil {
			return fmt.Errorf("could not generate RSA Key: %w", err)
		}
	default:
		r.eventRecorder.Event(route, corev1.EventTypeWarning, ReasonInvalidPrivateKeyAlgorithm, "invalid private key algorithm: "+privateKeyAlgorithm)
		return fmt.Errorf("invalid private key algorithm: %s", privateKeyAlgorithm)
	}
	encodedKey, err := utilpki.EncodePrivateKey(privateKey, cmapi.PrivateKeyEncoding(cmapi.PKCS1))
	if err != nil {
		return fmt.Errorf("could not encode %s key: %w", privateKeyAlgorithm, err)
	}
	route.Annotations[cmapi.IsNextPrivateKeySecretLabelKey] = string(encodedKey)
	_, err = r.routeClient.RouteV1().Routes(route.Namespace).Update(ctx, route, metav1.UpdateOptions{})
	if err != nil {
		return err
	}
	r.eventRecorder.Event(route, corev1.EventTypeNormal, ReasonIssuing, "Generated Private Key for route")
	return nil
}

func getCurrentRevision(route *routev1.Route) (int, error) {
	revision, found := route.Annotations[cmapi.CertificateRequestRevisionAnnotationKey]
	if !found {
		return 0, fmt.Errorf("no revision found")
	}
	return strconv.Atoi(revision)
}

func (r *Route) setRevision(ctx context.Context, route *routev1.Route, revision int) error {
	revisionString := strconv.Itoa(revision)
	route.Annotations[cmapi.CertificateRequestRevisionAnnotationKey] = revisionString
	_, err := r.routeClient.RouteV1().Routes(route.Namespace).Update(ctx, route, metav1.UpdateOptions{})
	if err != nil {
		return err
	}
	return nil
}

func (r *Route) hasNextCR(ctx context.Context, route *routev1.Route, revision int) (bool, error) {
	cr, err := r.findNextCR(ctx, route, revision)
	if err != nil {
		return false, err
	}
	if cr != nil {
		return true, nil
	}
	return false, nil
}

func (r *Route) findNextCR(ctx context.Context, route *routev1.Route, revision int) (*cmapi.CertificateRequest, error) {
	// Grab all certificateRequests in this namespace
	allCRs, err := r.certClient.CertmanagerV1().CertificateRequests(route.Namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	var candidates []*cmapi.CertificateRequest
	for _, cr := range allCRs.Items {
		// Beware: The cert-manager generated client re-uses the memory behind the slice next time List is called.
		// You must copy here to avoid a race condition where the CR contents changes underneath you!
		crCandidate := cr.DeepCopy()
		for _, owner := range crCandidate.OwnerReferences {
			if owner.UID == route.UID {
				crRevision := crCandidate.Annotations[cmapi.CertificateRequestRevisionAnnotationKey]
				crRevisionInt, err := strconv.Atoi(crRevision)
				if err != nil {
					continue
				}
				if crRevisionInt == revision+1 {
					candidates = append(candidates, crCandidate)
				}
			}
		}
	}
	if len(candidates) == 1 {
		return candidates[0], nil
	}
	if len(candidates) == 0 {
		return nil, nil
	}
	return nil, fmt.Errorf("multiple certificateRequests found for this route at revision " + strconv.Itoa(revision))
}

// buildNextCR generates the manifest of a Certificate Request that is needed for a given Route and revision
// This method expects that the private key has already been generated and added as an annotation on the route
func (r *Route) buildNextCR(ctx context.Context, route *routev1.Route, revision int) (*cmapi.CertificateRequest, error) {
	var key crypto.Signer
	// get private key from route
	k2, err := utilpki.DecodePrivateKeyBytes([]byte(route.Annotations[cmapi.IsNextPrivateKeySecretLabelKey]))
	if err != nil {
		return nil, err
	}
	key = k2

	// get duration from route
	duration, err := certDurationFromRoute(route)
	if err != nil {
		r.log.V(1).Error(err, "the duration annotation is invalid",
			"object", route.Namespace+"/"+route.Name, cmapi.DurationAnnotationKey,
			route.Annotations[cmapi.DurationAnnotationKey])
		r.eventRecorder.Event(route, corev1.EventTypeWarning, ReasonInvalidKey, "annotation "+cmapi.DurationAnnotationKey+": "+route.Annotations[cmapi.DurationAnnotationKey]+" is not a valid duration")
		return nil, fmt.Errorf("Invalid duration annotation on Route %s/%s", route.Namespace, route.Name)
	}

	var dnsNames []string
	// Get the canonical hostname(s) of the Route (from .spec.host or .spec.subdomain)
	dnsNames = getRouteHostnames(route)
	if len(dnsNames) == 0 {
		err := fmt.Errorf("Route is not yet initialized with a hostname")
		r.eventRecorder.Event(route, corev1.EventTypeWarning, ReasonMissingHostname, fmt.Sprint(err))
		return nil, err
	}

	// Parse out SANs
	if metav1.HasAnnotation(route.ObjectMeta, cmapi.AltNamesAnnotationKey) {
		altNames := strings.Split(route.Annotations[cmapi.AltNamesAnnotationKey], ",")
		dnsNames = append(dnsNames, altNames...)
	}
	var ipSans []net.IP
	if metav1.HasAnnotation(route.ObjectMeta, cmapi.IPSANAnnotationKey) {
		ipAddresses := strings.Split(route.Annotations[cmapi.IPSANAnnotationKey], ",")
		for _, i := range ipAddresses {
			ip := net.ParseIP(i)
			if ip != nil {
				ipSans = append(ipSans, ip)
			}
		}
	}
	var uriSans []*url.URL
	if metav1.HasAnnotation(route.ObjectMeta, cmapi.URISANAnnotationKey) {
		urls := strings.Split(route.Annotations[cmapi.URISANAnnotationKey], ",")
		for _, u := range urls {
			ur, err := url.Parse(u)
			if err != nil {
				r.eventRecorder.Event(route, corev1.EventTypeWarning, ReasonInvalidValue, "Ignoring malformed URI SAN "+u)
				continue
			}
			uriSans = append(uriSans, ur)
		}
	}

	privateKeyAlgorithm, found := route.Annotations[cmapi.PrivateKeyAlgorithmAnnotationKey]
	if !found {
		privateKeyAlgorithm = string(cmapi.RSAKeyAlgorithm)
	}

	var privateKeySize int
	privateKeySizeStr, found := route.Annotations[cmapi.PrivateKeySizeAnnotationKey]
	if found {
		privateKeySize, err = strconv.Atoi(privateKeySizeStr)
		if err != nil {
			r.eventRecorder.Event(route, corev1.EventTypeWarning, ReasonInvalidPrivateKeySize, "invalid private key size:"+privateKeySizeStr)
			return nil, fmt.Errorf("invalid private key size, %s: %v", privateKeySizeStr, err)
		}
	}

	var signatureAlgorithm x509.SignatureAlgorithm
	var publicKeyAlgorithm x509.PublicKeyAlgorithm
	switch privateKeyAlgorithm {
	case string(cmapi.ECDSAKeyAlgorithm):
		switch privateKeySize {
		case 521:
			signatureAlgorithm = x509.ECDSAWithSHA512
		case 384:
			signatureAlgorithm = x509.ECDSAWithSHA384
		case 256:
			signatureAlgorithm = x509.ECDSAWithSHA256
		default:
			signatureAlgorithm = x509.ECDSAWithSHA256
		}
		publicKeyAlgorithm = x509.ECDSA
	case string(cmapi.RSAKeyAlgorithm):
		switch {
		case privateKeySize >= 4096:
			signatureAlgorithm = x509.SHA512WithRSA
		case privateKeySize >= 3072:
			signatureAlgorithm = x509.SHA384WithRSA
		case privateKeySize >= 2048:
			signatureAlgorithm = x509.SHA256WithRSA
		default:
			signatureAlgorithm = x509.SHA256WithRSA
		}
		publicKeyAlgorithm = x509.RSA

	default:
		r.eventRecorder.Event(route, corev1.EventTypeWarning, ReasonInvalidPrivateKeyAlgorithm, "invalid private key algorithm: "+privateKeyAlgorithm)
		return nil, fmt.Errorf("invalid private key algorithm, %s", privateKeyAlgorithm)
	}

	csr, err := x509.CreateCertificateRequest(
		rand.Reader,
		&x509.CertificateRequest{
			Version:            0,
			SignatureAlgorithm: signatureAlgorithm,
			PublicKeyAlgorithm: publicKeyAlgorithm,
			Subject: pkix.Name{
				CommonName: route.Annotations[cmapi.CommonNameAnnotationKey],
			},
			DNSNames:    dnsNames,
			IPAddresses: ipSans,
			URIs:        uriSans,
		},
		key,
	)
	if err != nil {
		return nil, err
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csr,
	})

	cr := &cmapi.CertificateRequest{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: route.Name + "-",
			Namespace:    route.Namespace,
			Annotations:  map[string]string{cmapi.CertificateRequestRevisionAnnotationKey: strconv.Itoa(revision + 1)},
			OwnerReferences: []metav1.OwnerReference{
				*metav1.NewControllerRef(
					route,
					routev1.GroupVersion.WithKind("Route"),
				),
			},
		},
		Spec: cmapi.CertificateRequestSpec{
			Duration: &metav1.Duration{Duration: duration},
			IssuerRef: cmmeta.ObjectReference{
				Name:  route.Annotations[cmapi.IssuerNameAnnotationKey],
				Kind:  route.Annotations[cmapi.IssuerKindAnnotationKey],
				Group: route.Annotations[cmapi.IssuerGroupAnnotationKey],
			},
			Request: csrPEM,
			IsCA:    false,
			Usages:  []cmapi.KeyUsage{cmapi.UsageServerAuth, cmapi.UsageDigitalSignature, cmapi.UsageKeyEncipherment},
		},
	}

	if route.Spec.TLS != nil && route.Spec.TLS.Termination == routev1.TLSTerminationReencrypt {
		cr.Spec.Usages = append(cr.Spec.Usages, cmapi.UsageClientAuth)
	}

	return cr, nil
}

func (r *Route) certificateRequestReadyAndApproved(ctx context.Context, route *routev1.Route, revision int) (bool, *cmapi.CertificateRequest, error) {
	cr, err := r.findNextCR(ctx, route, revision)
	if err != nil {
		return false, nil, err
	}
	if cr == nil {
		r.log.Info("BUG: no certificateRequests found, this should never happen")
		return false, nil, nil
	}
	if cmapiutil.CertificateRequestIsApproved(cr) &&
		cmapiutil.CertificateRequestHasCondition(
			cr,
			cmapi.CertificateRequestCondition{
				Type:   cmapi.CertificateRequestConditionReady,
				Status: cmmeta.ConditionTrue,
			},
		) {
		return true, cr, nil
	} else {
		return false, nil, nil
	}
}

func (r *Route) populateRoute(ctx context.Context, route *routev1.Route, cr *cmapi.CertificateRequest, revision int) error {
	// final Sanity checks
	var key crypto.Signer

	// get private key from route
	k, err := utilpki.DecodePrivateKeyBytes([]byte(route.Annotations[cmapi.IsNextPrivateKeySecretLabelKey]))
	if err != nil {
		return err
	}
	key = k

	cert, err := utilpki.DecodeX509CertificateBytes(cr.Status.Certificate)
	if err != nil {
		return err
	}
	matches, err := utilpki.PublicKeyMatchesCertificate(key.Public(), cert)
	if err != nil {
		return err
	}
	if !matches {
		return fmt.Errorf("key does not match certificate (route: %s/%s)", route.Namespace, route.Name)
	}

	route.Annotations[cmapi.CertificateRequestRevisionAnnotationKey] = strconv.Itoa(revision + 1)
	if route.Spec.TLS == nil {
		route.Spec.TLS = &routev1.TLSConfig{
			Termination:                   routev1.TLSTerminationEdge,
			InsecureEdgeTerminationPolicy: routev1.InsecureEdgeTerminationPolicyRedirect,
		}
	}
	encodedKey, err := utilpki.EncodePrivateKey(key, cmapi.PKCS1)
	if err != nil {
		return err
	}
	route.Spec.TLS.Key = string(encodedKey)
	delete(route.Annotations, cmapi.IsNextPrivateKeySecretLabelKey)
	route.Spec.TLS.Certificate = string(cr.Status.Certificate)

	_, err = r.routeClient.RouteV1().Routes(route.Namespace).Update(ctx, route, metav1.UpdateOptions{})
	return err
}

func (r *Route) getRequeueAfterDuration(route *routev1.Route) time.Duration {
	cert, err := utilpki.DecodeX509CertificateBytes([]byte(route.Spec.TLS.Certificate))
	if err != nil {
		// Not expecting the cert to be invalid by the time we get here
		return time.Second * 5
	}
	// renew-before overrides default 2/3 behaviour
	if metav1.HasAnnotation(route.ObjectMeta, cmapi.RenewBeforeAnnotationKey) {
		renewBeforeDuration, err := time.ParseDuration(route.Annotations[cmapi.RenewBeforeAnnotationKey])
		if err != nil {
			// duration is invalid
			r.eventRecorder.Eventf(
				route,
				corev1.EventTypeWarning,
				ReasonInvalidKey,
				"the duration %s: %s is invalid (%s)",
				cmapi.RenewBeforeAnnotationKey,
				route.Annotations[cmapi.RenewBeforeAnnotationKey],
				err.Error(),
			)
		} else {
			return time.Until(cert.NotAfter.Add(-renewBeforeDuration))
		}
	}
	certLifetime := cert.NotAfter.Sub(cert.NotBefore) * 2 / 3
	return time.Until(cert.NotBefore.Add(certLifetime))
}

func certDurationFromRoute(r *routev1.Route) (time.Duration, error) {
	duration := DefaultCertificateDuration
	durationAnnotation, exists := r.Annotations[cmapi.DurationAnnotationKey]
	if exists {
		durationOverride, err := time.ParseDuration(durationAnnotation)
		if err != nil { // Not a reconcile error, so stop.
			return 0, err
		}
		duration = durationOverride
	}
	return duration, nil
}

// This function returns the hostnames that have been admitted by an Ingress Controller.
// Usually this is just `.spec.host`, but as of OpenShift 4.11 users may also specify `.spec.subdomain`,
// in which case the fully qualified hostname is derived from the hostname of the Ingress Controller.
// In both cases, the final hostname is reflected in `.status.ingress[].host`.
// Note that a Route can be admitted by multiple ingress controllers, so it may have multiple hostnames.
func getRouteHostnames(r *routev1.Route) []string {
	hostnames := []string{}
	for _, ing := range r.Status.Ingress {
		// Iterate over all Ingress Controllers which have admitted the Route
		for i := range ing.Conditions {
			if ing.Conditions[i].Type == "Admitted" && ing.Conditions[i].Status == "True" {
				// The same hostname can be exposed by multiple Ingress routers,
				// but we only want a list of unique hostnames.
				if !stringInSlice(hostnames, ing.Host) {
					hostnames = append(hostnames, ing.Host)
				}
			}
		}
	}

	return hostnames
}

func stringInSlice(slice []string, s string) bool {
	for i := range slice {
		if slice[i] == s {
			return true
		}
	}
	return false
}
