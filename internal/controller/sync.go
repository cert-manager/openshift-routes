/*
Copyright 2024 The cert-manager Authors.

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
	"fmt"
	"net"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	cmapiutil "github.com/cert-manager/cert-manager/pkg/api/util"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	cmutil "github.com/cert-manager/cert-manager/pkg/util"
	utilpki "github.com/cert-manager/cert-manager/pkg/util/pki"
	routev1 "github.com/openshift/api/route/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

const (
	ReasonIssuing                    = `Issuing`
	ReasonIssued                     = `Issued`
	ReasonInvalidKey                 = `InvalidKey`
	ReasonInvalidPrivateKeyAlgorithm = `InvalidPrivateKeyAlgorithm`
	ReasonInvalidPrivateKeySize      = `InvalidPrivateKeySize`
	ReasonInvalidValue               = `InvalidValue`
	ReasonInternalReconcileError     = `InternalReconcileError`
	ReasonMissingHostname            = `MissingHostname`
)

const DefaultCertificateDuration = time.Hour * 24 * 90 // 90 days

// sync reconciles an Openshift route.
func (r *RouteController) sync(ctx context.Context, req reconcile.Request, route *routev1.Route) (reconcile.Result, error) {
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

	// Do we already have a Certificate? If not, make it.
	cert, err := r.getCertificateForRoute(ctx, route)
	if err != nil {
		return result, err
	}
	if cert == nil {
		// generate manifest for new certificate
		log.V(5).Info("Route has no matching certificate", "namespace", req.NamespacedName.Namespace, "name", req.NamespacedName.Name)

		var cert *cmapi.Certificate
		cert, err = r.buildNextCert(ctx, route)
		if err != nil {
			log.V(1).Error(err, "error generating certificate", "object", req.NamespacedName)
			// Not a reconcile error, so don't retry this revision
			return result, nil
		}

		// create certificate and return. We own the certificate so it will cause a re-reconcile
		_, err = r.certClient.CertmanagerV1().Certificates(route.Namespace).Create(ctx, cert, metav1.CreateOptions{})
		if err != nil {
			return result, err
		}

		r.eventRecorder.Event(route, corev1.EventTypeNormal, ReasonIssuing, "Created new Certificate")
		return result, nil
	}

	// is the certificate ready?
	ready, cert, err := r.isCertificateReady(ctx, route)
	if err != nil {
		return result, err
	}

	if !ready {
		log.V(5).Info("Certificate is not ready yet")
		return result, nil
	}

	// Cert is ready. Retrieve the associated secret
	secret, err := r.coreClient.Secrets(route.Namespace).Get(ctx, cert.Spec.SecretName, metav1.GetOptions{})
	if err != nil {
		return result, err
	}

	// Populate the route.
	err = r.populateRoute(ctx, route, cert, secret)
	if err != nil {
		log.V(1).Error(err, "Failed to populate Route from Certificate")
		return result, err
	}

	log.V(5).Info("Populated Route from Cert", "name", route.Name)
	r.eventRecorder.Event(route, corev1.EventTypeNormal, ReasonIssued, "Route updated with issued certificate")

	return result, nil
}

func (r *RouteController) hasValidCertificate(route *routev1.Route) bool {
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

func (r *RouteController) getCertificateForRoute(ctx context.Context, route *routev1.Route) (*cmapi.Certificate, error) {
	// Note: this could also implement logic to re-use an existing certificate: route.Annotations[cmapi.CertificateNameKey]

	// Grab all Certificates in this namespace
	allCerts, err := r.certClient.CertmanagerV1().Certificates(route.Namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	var candidates []*cmapi.Certificate
	for _, cert := range allCerts.Items {
		// Beware: The cert-manager generated client re-uses the memory behind the slice next time List is called.
		// You must copy here to avoid a race condition where the CR contents changes underneath you!
		certCandidate := cert.DeepCopy()
		for _, owner := range certCandidate.OwnerReferences {
			if owner.UID == route.UID {
				candidates = append(candidates, certCandidate)
			}
		}
	}

	if len(candidates) == 1 {
		return candidates[0], nil
	}

	if len(candidates) == 0 {
		return nil, nil
	}

	return nil, fmt.Errorf("multiple matching Certificates found for Route %s/%s", route.Namespace, route.Name)
}

// buildNextCert generates the manifest of a Certificate that is needed for a given Route (based on the annotations)
func (r *RouteController) buildNextCert(ctx context.Context, route *routev1.Route) (*cmapi.Certificate, error) {
	var issuerName string
	if metav1.HasAnnotation(route.ObjectMeta, cmapi.IngressIssuerNameAnnotationKey) {
		issuerName = route.Annotations[cmapi.IngressIssuerNameAnnotationKey]
	} else {
		issuerName = route.Annotations[cmapi.IssuerNameAnnotationKey]
	}

	if issuerName == "" {
		return nil, fmt.Errorf("missing issuer-name annotation on %s/%s", route.Namespace, route.Name)
	}

	// Extract various pieces of information from the Route annotations
	duration, err := certDurationFromRoute(route)
	if err != nil {
		r.log.V(1).Error(err, "the duration annotation is invalid",
			"object", route.Namespace+"/"+route.Name, cmapi.DurationAnnotationKey,
			route.Annotations[cmapi.DurationAnnotationKey])
		r.eventRecorder.Event(route, corev1.EventTypeWarning, ReasonInvalidKey, "annotation "+cmapi.DurationAnnotationKey+": "+route.Annotations[cmapi.DurationAnnotationKey]+" is not a valid duration")
		return nil, fmt.Errorf("invalid duration annotation on Route %s/%s", route.Namespace, route.Name)
	}

	var renewBefore *metav1.Duration
	if metav1.HasAnnotation(route.ObjectMeta, cmapi.RenewBeforeAnnotationKey) {
		renewBeforeAnnotation := route.Annotations[cmapi.RenewBeforeAnnotationKey]

		parsedRenewBefore, err := time.ParseDuration(renewBeforeAnnotation)
		if err != nil {
			return nil, fmt.Errorf("invalid renew-before annotation %q on Route %s/%s", renewBeforeAnnotation, route.Namespace, route.Name)
		}

		renewBefore = &metav1.Duration{Duration: parsedRenewBefore}
	}

	var privateKeyAlgorithm cmapi.PrivateKeyAlgorithm
	privateKeyAlgorithmStrRaw, found := route.Annotations[cmapi.PrivateKeyAlgorithmAnnotationKey]
	if !found {
		privateKeyAlgorithmStrRaw = "RSA"
	}

	switch strings.ToLower(privateKeyAlgorithmStrRaw) {
	case "rsa":
		privateKeyAlgorithm = cmapi.RSAKeyAlgorithm
	case "ecdsa":
		privateKeyAlgorithm = cmapi.ECDSAKeyAlgorithm
	case "ed25519":
		privateKeyAlgorithm = cmapi.Ed25519KeyAlgorithm
	default:
		r.log.V(1).Info("unknown private key algorithm, defaulting to RSA", "algorithm", privateKeyAlgorithmStrRaw)
		privateKeyAlgorithm = cmapi.RSAKeyAlgorithm
	}

	var privateKeyEncoding cmapi.PrivateKeyEncoding
	privateKeyEncodingStr, found := route.Annotations[cmapi.PrivateKeyEncodingAnnotationKey]
	if found {
		switch strings.ToLower(privateKeyEncodingStr) {
		case "pkcs8":
			privateKeyEncoding = cmapi.PKCS8
		case "pkcs1":
			privateKeyEncoding = cmapi.PKCS1
		default:
			r.log.V(1).Info("unknown private key encoding, defaulting to PKCS1", "encoding", privateKeyEncodingStr)
			privateKeyEncoding = cmapi.PKCS1
		}
	}

	var privateKeySize int
	privateKeySizeStr, found := route.Annotations[cmapi.PrivateKeySizeAnnotationKey]
	if found {
		privateKeySize, err = strconv.Atoi(privateKeySizeStr)
		if err != nil {
			r.eventRecorder.Event(route, corev1.EventTypeWarning, ReasonInvalidPrivateKeySize, "invalid private key size:"+privateKeySizeStr)
			return nil, fmt.Errorf("invalid private key size annotation %q on %s/%s", privateKeySizeStr, route.Namespace, route.Name)
		}
	}

	var privateKeyRotationPolicy cmapi.PrivateKeyRotationPolicy

	if metav1.HasAnnotation(route.ObjectMeta, cmapi.PrivateKeyRotationPolicyAnnotationKey) {
		// Don't validate the policy here because that would mean we'd need to update this codebase
		// if cert-manager adds new values. Just rely on cert-manager validation when the cert is
		// created. This is brittle; ideally, cert-manager should expose a function for this.
		privateKeyRotationPolicy = cmapi.PrivateKeyRotationPolicy(route.Annotations[cmapi.PrivateKeyRotationPolicyAnnotationKey])
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

	var ipSANs []string
	if metav1.HasAnnotation(route.ObjectMeta, cmapi.IPSANAnnotationKey) {
		ipAddresses := strings.SplitSeq(route.Annotations[cmapi.IPSANAnnotationKey], ",")
		for i := range ipAddresses {
			ip := net.ParseIP(i)
			if ip == nil {
				r.eventRecorder.Event(route, corev1.EventTypeWarning, ReasonInvalidValue, fmt.Sprintf("Ignoring unparseable IP SAN %q", i))
				r.log.V(1).Error(nil, "ignoring unparseble IP address on route", "rawIP", i)
				continue
			}

			ipSANs = append(ipSANs, ip.String())
		}
	}

	var uriSANs []string
	if metav1.HasAnnotation(route.ObjectMeta, cmapi.URISANAnnotationKey) {
		urls := strings.SplitSeq(route.Annotations[cmapi.URISANAnnotationKey], ",")

		for u := range urls {
			ur, err := url.Parse(u)
			if err != nil {
				r.eventRecorder.Event(route, corev1.EventTypeWarning, ReasonInvalidValue, fmt.Sprintf("Ignoring malformed URI SAN %q", u))
				r.log.V(1).Error(err, "ignoring unparseble URI SAN on route", "uri", u)
				continue
			}

			uriSANs = append(uriSANs, ur.String())
		}
	}

	var emailAddresses []string
	if metav1.HasAnnotation(route.ObjectMeta, cmapi.EmailsAnnotationKey) {
		emailAddresses = strings.Split(route.Annotations[cmapi.EmailsAnnotationKey], ",")
	}

	var organizations []string
	if metav1.HasAnnotation(route.ObjectMeta, cmapi.SubjectOrganizationsAnnotationKey) {
		subjectOrganizations, err := cmutil.SplitWithEscapeCSV(route.Annotations[cmapi.SubjectOrganizationsAnnotationKey])
		organizations = subjectOrganizations

		if err != nil {
			r.log.V(1).Error(err, "the organizations annotation is invalid",
				"object", route.Namespace+"/"+route.Name, cmapi.SubjectOrganizationsAnnotationKey,
				route.Annotations[cmapi.SubjectOrganizationsAnnotationKey])
			r.eventRecorder.Event(route, corev1.EventTypeWarning, ReasonInvalidValue, "annotation "+cmapi.SubjectOrganizationsAnnotationKey+": "+route.Annotations[cmapi.SubjectOrganizationsAnnotationKey]+" value is malformed")
			return nil, err
		}
	}

	var organizationalUnits []string
	if metav1.HasAnnotation(route.ObjectMeta, cmapi.SubjectOrganizationalUnitsAnnotationKey) {
		subjectOrganizationalUnits, err := cmutil.SplitWithEscapeCSV(route.Annotations[cmapi.SubjectOrganizationalUnitsAnnotationKey])
		organizationalUnits = subjectOrganizationalUnits

		if err != nil {
			r.log.V(1).Error(err, "the organizational units annotation is invalid",
				"object", route.Namespace+"/"+route.Name, cmapi.SubjectOrganizationalUnitsAnnotationKey,
				route.Annotations[cmapi.SubjectOrganizationalUnitsAnnotationKey])
			r.eventRecorder.Event(route, corev1.EventTypeWarning, ReasonInvalidValue, "annotation "+cmapi.SubjectOrganizationalUnitsAnnotationKey+": "+route.Annotations[cmapi.SubjectOrganizationalUnitsAnnotationKey]+" value is malformed")
			return nil, err
		}

	}

	var countries []string
	if metav1.HasAnnotation(route.ObjectMeta, cmapi.SubjectCountriesAnnotationKey) {
		subjectCountries, err := cmutil.SplitWithEscapeCSV(route.Annotations[cmapi.SubjectCountriesAnnotationKey])
		countries = subjectCountries

		if err != nil {
			r.log.V(1).Error(err, "the countries annotation is invalid",
				"object", route.Namespace+"/"+route.Name, cmapi.SubjectCountriesAnnotationKey,
				route.Annotations[cmapi.SubjectCountriesAnnotationKey])
			r.eventRecorder.Event(route, corev1.EventTypeWarning, ReasonInvalidValue, "annotation "+cmapi.SubjectCountriesAnnotationKey+": "+route.Annotations[cmapi.SubjectCountriesAnnotationKey]+" value is malformed")
			return nil, err
		}
	}

	var provinces []string
	if metav1.HasAnnotation(route.ObjectMeta, cmapi.SubjectProvincesAnnotationKey) {
		subjectProvinces, err := cmutil.SplitWithEscapeCSV(route.Annotations[cmapi.SubjectProvincesAnnotationKey])
		provinces = subjectProvinces

		if err != nil {
			r.log.V(1).Error(err, "the provinces annotation is invalid",
				"object", route.Namespace+"/"+route.Name, cmapi.SubjectProvincesAnnotationKey,
				route.Annotations[cmapi.SubjectProvincesAnnotationKey])
			r.eventRecorder.Event(route, corev1.EventTypeWarning, ReasonInvalidValue, "annotation "+cmapi.SubjectProvincesAnnotationKey+": "+route.Annotations[cmapi.SubjectProvincesAnnotationKey]+" value is malformed")
			return nil, err
		}
	}

	var localities []string
	if metav1.HasAnnotation(route.ObjectMeta, cmapi.SubjectLocalitiesAnnotationKey) {
		subjectLocalities, err := cmutil.SplitWithEscapeCSV(route.Annotations[cmapi.SubjectLocalitiesAnnotationKey])
		localities = subjectLocalities

		if err != nil {
			r.log.V(1).Error(err, "the localities annotation is invalid",
				"object", route.Namespace+"/"+route.Name, cmapi.SubjectLocalitiesAnnotationKey,
				route.Annotations[cmapi.SubjectLocalitiesAnnotationKey])
			r.eventRecorder.Event(route, corev1.EventTypeWarning, ReasonInvalidValue, "annotation "+cmapi.SubjectLocalitiesAnnotationKey+": "+route.Annotations[cmapi.SubjectLocalitiesAnnotationKey]+" value is malformed")
			return nil, err
		}
	}

	var postalCodes []string
	if metav1.HasAnnotation(route.ObjectMeta, cmapi.SubjectPostalCodesAnnotationKey) {
		subjectPostalCodes, err := cmutil.SplitWithEscapeCSV(route.Annotations[cmapi.SubjectPostalCodesAnnotationKey])
		postalCodes = subjectPostalCodes

		if err != nil {
			r.log.V(1).Error(err, "the postal codes annotation is invalid",
				"object", route.Namespace+"/"+route.Name, cmapi.SubjectPostalCodesAnnotationKey,
				route.Annotations[cmapi.SubjectPostalCodesAnnotationKey])
			r.eventRecorder.Event(route, corev1.EventTypeWarning, ReasonInvalidValue, "annotation "+cmapi.SubjectPostalCodesAnnotationKey+": "+route.Annotations[cmapi.SubjectPostalCodesAnnotationKey]+" value is malformed")
			return nil, err
		}
	}

	var streetAddresses []string
	if metav1.HasAnnotation(route.ObjectMeta, cmapi.SubjectStreetAddressesAnnotationKey) {
		subjectStreetAddresses, err := cmutil.SplitWithEscapeCSV(route.Annotations[cmapi.SubjectStreetAddressesAnnotationKey])
		streetAddresses = subjectStreetAddresses

		if err != nil {
			r.log.V(1).Error(err, "the street addresses annotation is invalid",
				"object", route.Namespace+"/"+route.Name, cmapi.SubjectStreetAddressesAnnotationKey,
				route.Annotations[cmapi.SubjectStreetAddressesAnnotationKey])
			r.eventRecorder.Event(route, corev1.EventTypeWarning, ReasonInvalidValue, "annotation "+cmapi.SubjectStreetAddressesAnnotationKey+": "+route.Annotations[cmapi.SubjectStreetAddressesAnnotationKey]+" value is malformed")
			return nil, err
		}
	}

	var serialNumber string
	if metav1.HasAnnotation(route.ObjectMeta, cmapi.SubjectSerialNumberAnnotationKey) {
		serialNumber = route.Annotations[cmapi.SubjectSerialNumberAnnotationKey]
	}

	var revisionHistoryLimit *int32
	if metav1.HasAnnotation(route.ObjectMeta, cmapi.RevisionHistoryLimitAnnotationKey) {
		historyLimitRaw := route.Annotations[cmapi.RevisionHistoryLimitAnnotationKey]

		parsedLimit, err := strconv.ParseInt(historyLimitRaw, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("invalid revision-history-limit annotation %q on %s/%s", historyLimitRaw, route.Namespace, route.Name)
		}

		typedLimit := int32(parsedLimit)
		revisionHistoryLimit = &typedLimit
	}

	secretName := safeKubernetesNameAppend(route.Name, "tls")

	// Build the Certificate resource with the collected information
	// https://cert-manager.io/docs/usage/certificate/
	cert := &cmapi.Certificate{
		ObjectMeta: metav1.ObjectMeta{
			Name:      safeKubernetesNameAppend(route.Name, "cert"),
			Namespace: route.Namespace,
			OwnerReferences: []metav1.OwnerReference{
				*metav1.NewControllerRef(
					route,
					routev1.GroupVersion.WithKind("Route"),
				),
			},
		},
		Spec: cmapi.CertificateSpec{
			SecretName:           secretName,
			Duration:             &metav1.Duration{Duration: duration},
			RenewBefore:          renewBefore,
			RevisionHistoryLimit: revisionHistoryLimit,
			CommonName:           route.Annotations[cmapi.CommonNameAnnotationKey],
			Subject: &cmapi.X509Subject{
				Countries:           countries,
				Localities:          localities,
				Organizations:       organizations,
				OrganizationalUnits: organizationalUnits,
				PostalCodes:         postalCodes,
				Provinces:           provinces,
				SerialNumber:        serialNumber,
				StreetAddresses:     streetAddresses,
			},
			PrivateKey: &cmapi.CertificatePrivateKey{
				Algorithm:      privateKeyAlgorithm,
				Size:           privateKeySize,
				RotationPolicy: privateKeyRotationPolicy,
				Encoding:       privateKeyEncoding,
			},
			EmailAddresses: emailAddresses,
			DNSNames:       dnsNames,
			URIs:           uriSANs,
			IPAddresses:    ipSANs,
			IssuerRef: cmmeta.ObjectReference{
				Name:  issuerName,
				Kind:  route.Annotations[cmapi.IssuerKindAnnotationKey],
				Group: route.Annotations[cmapi.IssuerGroupAnnotationKey],
			},
			IsCA:   false,
			Usages: []cmapi.KeyUsage{cmapi.UsageServerAuth, cmapi.UsageDigitalSignature, cmapi.UsageKeyEncipherment},
		},
	}

	if route.Spec.TLS != nil && route.Spec.TLS.Termination == routev1.TLSTerminationReencrypt {
		cert.Spec.Usages = append(cert.Spec.Usages, cmapi.UsageClientAuth)
	}

	return cert, nil
}

func (r *RouteController) isCertificateReady(ctx context.Context, route *routev1.Route) (bool, *cmapi.Certificate, error) {
	cert, err := r.getCertificateForRoute(ctx, route)
	if err != nil {
		return false, nil, err
	}
	if cert == nil {
		r.log.Info("BUG: no Certificate found, this should never happen")
		return false, nil, nil
	}
	if cmapiutil.CertificateHasCondition(
		cert,
		cmapi.CertificateCondition{
			Type:   cmapi.CertificateConditionReady,
			Status: cmmeta.ConditionTrue,
		},
	) {
		return true, cert, nil
	} else {
		return false, nil, nil
	}
}

func (r *RouteController) populateRoute(ctx context.Context, route *routev1.Route, cert *cmapi.Certificate, secret *corev1.Secret) error {
	// final Sanity checks
	var key crypto.Signer

	// get private key and signed certificate from Secret
	k, err := utilpki.DecodePrivateKeyBytes(secret.Data["tls.key"])
	if err != nil {
		return err
	}
	key = k

	certificates, err := utilpki.DecodeX509CertificateChainBytes(secret.Data["tls.crt"])
	if err != nil {
		return err
	}

	if len(certificates) == 0 {
		// this shouldn't happen; DecodeX509CertificateChainBytes should error in this situation
		// but just in case, catch this case so we don't panic when accessing certificates[0]
		return fmt.Errorf("found no valid certs from DecodeX509CertificateChainBytes")
	}

	matches, err := utilpki.PublicKeyMatchesCertificate(key.Public(), certificates[0])
	if err != nil {
		return err
	}
	if !matches {
		return fmt.Errorf("key does not match certificate (route: %s/%s)", route.Namespace, route.Name)
	}

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

	encodedCerts, err := utilpki.EncodeX509Chain(certificates)
	if err != nil {
		return err
	}

	route.Spec.TLS.Certificate = string(encodedCerts)

	_, err = r.routeClient.RouteV1().Routes(route.Namespace).Update(ctx, route, metav1.UpdateOptions{})
	return err
}

func (r *RouteController) getRequeueAfterDuration(route *routev1.Route) time.Duration {
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
				if !slices.Contains(hostnames, ing.Host) {
					hostnames = append(hostnames, ing.Host)
				}
			}
		}
	}

	return hostnames
}
