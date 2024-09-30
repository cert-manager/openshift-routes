#!/usr/bin/env bash

# Copyright 2023 The cert-manager Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

set -o errexit
set -o nounset
set -o pipefail

# Create a self-signed CA certificate and Issuer

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

# Create a Route and patch the status with multiple hosts

route_name="test-"$(openssl rand -hex 12)

cat <<EOF | kubectl create -f -
apiVersion: route.openshift.io/v1
kind: Route
metadata:
  name: $route_name
  annotations:
    cert-manager.io/issuer-name: my-ca-issuer
    cert-manager.io/duration: 1h
spec:
  host: hello-openshift-hello-openshift.test
  port:
    targetPort: 8080
  to:
    kind: Service
    name: hello-openshift
EOF

patch=$(cat <<EOF
{
  "status": {
    "ingress": [
      {
        "host": "hello-openshift-hello-openshift.test1",
        "conditions": [
          {
            "type": "Admitted",
            "status": "True",
            "lastTransitionTime": "2023-01-01T00:00:00Z"
          }
        ]
      },
      {
        "host": "hello-openshift-hello-openshift.test2",
        "conditions": [
          {
            "type": "Admitted",
            "status": "True",
            "lastTransitionTime": "2023-01-01T00:00:00Z"
          }
        ]
      }
    ]
  }
}
EOF
)

kubectl patch route "$route_name" --type=merge --subresource=status -p="$patch"

# Wait for the certificate to be issued
SLEEP_TIME=2

for _ in {1..10}; do
  certificate=$(kubectl get route "$route_name" -o jsonpath='{.spec.tls.certificate}')
  if [ "$certificate" != "" ]; then
    break
  fi
  echo "Didn't find certificate on route yet, retrying in $SLEEP_TIME seconds"
  sleep $SLEEP_TIME
done

if [ "$certificate" == "" ]; then
  echo "Failed to get certificate"
  exit 1
fi

echo
echo "++ Certificate:"
echo "$certificate"

# Decode the certificate and check the Subject Alternative Names

certificate_decoded=$(echo "$certificate" | openssl x509 -text -noout)

echo
echo "++ Certificate decoded:"
echo "$certificate_decoded"

echo

if [[ "$certificate_decoded" != *"DNS:hello-openshift-hello-openshift.test1"* ]]; then
  echo "Failed to find DNS:hello-openshift-hello-openshift.test1 in certificate"
  exit 1
else
  echo "Found DNS:hello-openshift-hello-openshift.test1 in certificate"
fi

if [[ "$certificate_decoded" != *"DNS:hello-openshift-hello-openshift.test2"* ]]; then
  echo "Failed to find DNS:hello-openshift-hello-openshift.test2 in certificate"
  exit 1
else
  echo "Found DNS:hello-openshift-hello-openshift.test2 in certificate"
fi

kubectl delete route "$route_name"
