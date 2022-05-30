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
	ReasonIssuing                = `Issuing`
	ReasonInvalidKey             = `InvalidKey`
	ReasonInvalidValue           = `InvalidValue`
	ReasonInternalReconcileError = `InternalReconcileError`
)

// sync reconciles an Openshift route.
func (r *Route) sync(ctx context.Context, req reconcile.Request, route *routev1.Route) (result reconcile.Result, err error) {
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
		return
	}
	// Do we have a revision? If not set revision to 0
	revision, err := getCurrentRevision(route)
	if err != nil {
		err = r.setRevision(ctx, route, 0)
		log.V(5).Info("generated revision 0")
		return
	}
	// Do we have a next key?
	if !r.hasNextPrivateKey(route) {
		err = r.generateNextPrivateKey(ctx, route)
		log.V(5).Info("generated next private key for route")
		return
	}
	// Is there a CertificateRequest for the Next revision? If not, make it.
	hasNext, err := r.hasNextCR(ctx, route, revision)
	if err != nil {
		// err above is the returned err - named returns parameters + bare returns can be confusing
		return
	}
	if !hasNext {
		// create CR and return. We own the CR so it will cause a re-reconcile
		log.V(5).Info("route has no matching certificate request", "revision", revision)
		err = r.createNextCR(ctx, route, revision)
		return
	}
	// is the CR Ready and Approved?
	ready, cr, err := r.certificateRequestReadyAndApproved(ctx, route, revision)
	if err != nil {
		// err above is the returned err - named returns parameters + bare returns can be confusing
		return
	}
	if !ready {
		log.V(5).Info("cr is not ready yet")
		return
	}
	// Cert is ready. Populate the route.
	err = r.populateRoute(ctx, route, cr, revision)
	log.V(5).Info("populated route cert")
	return
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
	// As there is no renew-before, is the cert less than 2/3 through its life?
	totalDuration := cert.NotAfter.Sub(cert.NotBefore)
	timeToExpiry := cert.NotAfter.Sub(time.Now())
	if timeToExpiry < (totalDuration * 2 / 3) {
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
	// TODO: different kinds of key
	key, err := utilpki.GenerateRSAPrivateKey(utilpki.MinRSAKeySize)
	if err != nil {
		return fmt.Errorf("could not generate RSA Key: %w", err)
	}

	encodedKey, err := utilpki.EncodePrivateKey(key, cmapi.PKCS1)
	if err != nil {
		return fmt.Errorf("could not encode RSA Key: %w", err)
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

func (r *Route) createNextCR(ctx context.Context, route *routev1.Route, revision int) error {
	var key crypto.Signer
	// get private key from route
	k2, err := utilpki.DecodePrivateKeyBytes([]byte(route.Annotations[cmapi.IsNextPrivateKeySecretLabelKey]))
	if err != nil {
		return err
	}
	key = k2

	// get duration from route
	duration, err := certDurationFromRoute(route)
	if err != nil {
		r.log.V(1).Error(err, "the duration annotation is invalid",
			"object", route.Namespace+"/"+route.Name, cmapi.DurationAnnotationKey,
			route.Annotations[cmapi.DurationAnnotationKey])
		r.eventRecorder.Event(route, corev1.EventTypeWarning, ReasonInvalidKey, "annotation "+cmapi.DurationAnnotationKey+": "+route.Annotations[cmapi.DurationAnnotationKey]+" is not a valid duration")
		// Not a reconcile error, so stop.
		return nil
	}

	// Parse out SANs
	var dnsNames []string
	if metav1.HasAnnotation(route.ObjectMeta, cmapi.AltNamesAnnotationKey) {
		altNames := strings.Split(route.Annotations[cmapi.AltNamesAnnotationKey], ",")
		dnsNames = append(dnsNames, altNames...)
	}
	if len(route.Spec.Host) > 0 {
		dnsNames = append(dnsNames, route.Spec.Host)
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

	csr, err := x509.CreateCertificateRequest(
		rand.Reader,
		&x509.CertificateRequest{
			Version:            0,
			SignatureAlgorithm: x509.SHA256WithRSA,
			PublicKeyAlgorithm: x509.RSA,
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
		return err
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

	_, err = r.certClient.CertmanagerV1().CertificateRequests(route.Namespace).Create(ctx, cr, metav1.CreateOptions{})
	return err
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
	route.Spec.TLS.CACertificate = string(cr.Status.CA)

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
	duration := time.Hour * 24 * 90
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
