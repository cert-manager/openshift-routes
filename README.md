<p align="center">
  <img src="https://raw.githubusercontent.com/cert-manager/cert-manager/d53c0b9270f8cd90d908460d69502694e1838f5f/logo/logo-small.png" height="256" width="256" alt="cert-manager project logo" />
</p>

# OpenShift Route Support for cert-manager

This project supports automatically getting a certificate for
OpenShift routes from any cert-manager Issuer.

## Prerequisites:

1. Ensure you have [cert-manager](https://github.com/cert-manager/cert-manager) installed
   through the method of your choice. But make sure you install cert-manager and openshift-routes-deployment in the same namespace. By default this is in the namespace **cert-manager**.
   For example, with the regular manifest:

```sh
oc apply -f https://github.com/jetstack/cert-manager/releases/download/v1.12.1/cert-manager.yaml
```

Both **ClusterIssuer** and namespace based **Issuer** are possible. Here a **ClusterIssuer** is used:

2. For example, create the ClusterIssuer (no additional ingress class is needed for the openshift-ingress router. The example.com email must be replaced by another one):

```yaml
apiVersion: v1
items:
  - apiVersion: cert-manager.io/v1
    kind: ClusterIssuer
    metadata:
      annotations:
      name: letsencrypt-prod
    spec:
      acme:
        email: mymail@example.com
        preferredChain: ""
        privateKeySecretRef:
          name: letsencrypt-prod
        server: https://acme-v02.api.letsencrypt.org/directory
        solvers:
          - http01:
              ingress: {}
```

```sh
oc apply -f clusterissuer.yaml
```

3. Make sure that there is an A record on the load balancer IP or a CNAME record on the load balancer hostname in your DNS system for the HTTP-01 subdomain.

```
CNAME:
  Name: *.service.clustername.domain.com
  Alias: your-lb-domain.cloud
```

## Usage

Install in your cluster using the static manifests:

```shell
oc apply -f https://github.com/cert-manager/openshift-routes/releases/latest/download/cert-manager-openshift-routes.yaml
```

If you follow the above prerequisites, use this annotations below

```yaml
---
metadata:
  annotations:
    cert-manager.io/issuer-kind: ClusterIssuer
    cert-manager.io/issuer-name: letsencrypt-prod
---
spec:
  host: app.service.clustername.domain.com
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
    cert-manager.io/private-key-algorithm: "ECDSA" # Optional, defaults to RSA
spec:
  host: app.service.clustername.domain.com # will be added to the Subject Alternative Names of the CertificateRequest
  port:
    targetPort: 8080
  to:
    kind: Service
    name: hello-openshift
```

Observe the `route.Spec.TLS` section of your route being populated automatically by cert-manager.

The route's TLS certificate will be rotated 2/3 of the way through the certificate's lifetime, or
`cert-manager.io/renew-before` time before it expires.

Now the website can be called: https://app.service.clustername.domain.com

## Development

The source code for the controller can be found in the `./internal/` folder.
After modifying the source code, you can execute the tests with:

```sh
go test ./...
```

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

# Release Process

You must have write access to this repository to perform a release.

1. ```bash
   git checkout main
   git pull origin main
   ```

2. Create a tag and push it:

   ```bash
   git tag v0.2.0
   git push origin v0.2.0
   ```

3. Once the GitHub Action has completed, you will see a new GitHub Release for
   that version. Edit the release description if needed.
