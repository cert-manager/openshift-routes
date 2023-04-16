#!/usr/bin/env bash

kubectl apply -f https://github.com/cert-manager/cert-manager/releases/download/v1.12.1/cert-manager.yaml
cat <<EOF | kubectl apply -f -
---
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: selfsigned-issuer
spec:
  selfSigned: {}
---
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: my-selfsigned-ca
spec:
  isCA: true
  commonName: my-selfsigned-ca
  secretName: root-secret
  privateKey:
    algorithm: RSA
    size: 2048
  issuerRef:
    name: selfsigned-issuer
    kind: ClusterIssuer
    group: cert-manager.io
---
apiVersion: cert-manager.io/v1
kind: Issuer
metadata:
  name: my-ca-issuer
spec:
  ca:
    secretName: root-secret
EOF

cat <<EOF | kubectl apply -f -

---
apiVersion: apps/v1
kind: Deployment
metadata:
  labels:
    app: nginx
  name: nginx
spec:
  replicas: 1
  selector:
    matchLabels:
      app: nginx
  template:
    metadata:
      labels:
        app: nginx
    spec:
      containers:
      - image: nginx
        name: nginx
---
apiVersion: v1
kind: Service
metadata:
  name: hello-openshift
spec:
  selector:
    app: nginx
  ports:
  - name: http
    protocol: TCP
    port: 8080
    targetPort: 80
EOF

cat <<EOF | kubectl create -f -
apiVersion: route.openshift.io/v1
kind: Route
metadata:
  generateName: test
  annotations:
    cert-manager.io/issuer-name: my-ca-issuer
    cert-manager.io/duration: 1m
spec:
  host: hello-openshift-hello-openshift.test
  port:
    targetPort: 8080
  to:
    kind: Service
    name: hello-openshift
EOF
