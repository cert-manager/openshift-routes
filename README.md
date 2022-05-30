# OpenShift Route Support for cert-manager

This project supports automatically getting a certificate for
OpenShift routes from any cert-manager Issuer.

## Usage

Ensure you have [cert-manager](https://github.com/cert-manager/cert-manager) installed
through the method of your choice.

Install in your cluster using the static manifests:

```shell
oc apply -f https://github.com/cert-manager/cert-manager-openshift-routes/releases/latest/cert-manager-openshift-routes.yaml
```

Annotate your routes:

```yaml
apiVersion: route.openshift.io/v1
kind: Route
metadata:
  name: example-route
  annotations:
    cert-manager.io/issuer-name: my-issuer # This is the only required annotation
    cert-manager.io/issuer-group: cert-manager.io # Optional, defaults to cert-manager.io
    cert-manager.io/issuer-kind: Issuer # Optional, defaults to Issuer, could be ClusterIssuer or an External Issuer
    cert-manager.io/duration: 1h # Optional, defaults to 90 days
    cert-manager.io/renew-before: 30m # Optional, defaults to 1/3 of total certificate duration.
    cert-manager.io/common-name: "My Certificate" # Optional, no default.
    cert-manager.io/alt-names: "mycooldomain.com,mysecondarydomain.com" # Optional, no default
    cert-manager.io/ip-sans: "10.20.30.40,192.168.192.168" # Optional, no default
    cert-manager.io/uri-sans: "spiffe://trustdomain/workload" # Optional, no default
spec:
  host: my-internal-service-host.my-domain # will be added to the Subject Alternative Names of the CertificateRequest
  port:
    targetPort: 8080
  to:
    kind: Service
    name: hello-openshift
```

Observe the `route.Spec.TLS` section of your route being populated automatically by cert-manager.

The route's TLS certificate will be rotated 2/3 of the way through the certificate's lifetime, or 
`cert-manager.io/renew-before` time before it expires.

# Why is This a Separate Project?

We do not wish to support non Kubernetes (or kubernetes-sigs) APIs in cert-manager core. This adds
a large maintenance burden, and it's hard for us to e2e test everyone's CRDs. However, OpenShift is
widely used, so it makes sense to have some support for it in the cert-manager ecosystem.

Ideally we would have contributed this controller to an existing project, e.g.
https://github.com/redhat-cop/cert-utils-operator. Unfortunately, cert-manager is not really designed
to be imported as a module. It has a large number of transitive dependencies that would add an unfair
amount of maintenance to whichever project we submitted it to. In the future, we would like to split
the cert-manager APIs and typed clients out of the main cert-manager repo, at which point it would be
easier for other people to consume in their projects.
