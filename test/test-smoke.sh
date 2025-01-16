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

YQ=${1:-yq}

# Create a self-signed root CA certificate and Issuer
# Then create an intermediate CA and issuer

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
  name: my-root-issuer
spec:
  ca:
    secretName: root-secret
---
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: my-intermediate-ca
spec:
  isCA: true
  commonName: my-intermediate-ca
  secretName: intermediate-secret
  privateKey:
    algorithm: RSA
    size: 2048
  issuerRef:
    name: my-root-issuer
    kind: Issuer
    group: cert-manager.io
---
apiVersion: cert-manager.io/v1
kind: Issuer
metadata:
  name: my-ca-issuer
spec:
  ca:
    secretName: intermediate-secret
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
    cert-manager.io/renew-before: 30m
    cert-manager.io/alt-names: example.com
    cert-manager.io/ip-sans: 192.168.50.1,2001:0db8:85a3:0000:0000:8a2e:0370:7334,::ffff:192.0.2.128
    cert-manager.io/uri-sans: spiffe://example.com/route-66
    cert-manager.io/private-key-algorithm: "EcDsA"
    cert-manager.io/private-key-size: "384"
    cert-manager.io/private-key-rotation-policy: Always
    cert-manager.io/subject-streetaddresses: "1725 Slough Avenue"
    cert-manager.io/subject-countries: "UK"
    cert-manager.io/subject-organizationalunits: "my-ou"
    cert-manager.io/subject-postalcodes: "SW1A 2AA"
    cert-manager.io/subject-organizations: "cert-manager"
    cert-manager.io/subject-provinces: "Ontario"
    cert-manager.io/revision-history-limit: "2"
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

for _ in {1..30}; do
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

cm_cert_name=$(kubectl get certificate --output=name | grep $route_name)

cert_yaml=$(kubectl get $cm_cert_name -oyaml)

echo
echo "++ cert-manager Certificate YAML:"
echo "$cert_yaml"

echo

function look_for_string() {
    if [[ "$1" != *"$2"* ]]; then
        echo "Failed to find \"$2\" in certificate"
        exit 1
    else
        echo "Found \"$2\" in certificate"
    fi
}

look_for_string "$certificate_decoded" "DNS:hello-openshift-hello-openshift.test1"
look_for_string "$certificate_decoded" "DNS:hello-openshift-hello-openshift.test2"
look_for_string "$certificate_decoded" "DNS:example.com"

look_for_string "$certificate_decoded" "IP Address:192.168.50.1"
# NB: This is the IPv6-mapped IPv4 address: ::ffff:192.0.2.128
look_for_string "$certificate_decoded" "IP Address:192.0.2.128"
# NB: OpenSSL formats IPv6 addresses a bit differently to how we specify it above
look_for_string "$certificate_decoded" "IP Address:2001:DB8:85A3:0:0:8A2E:370:7334"
look_for_string "$certificate_decoded" "URI:spiffe://example.com/route-66"

look_for_string "$certificate_decoded" "Public Key Algorithm: id-ecPublicKey"
look_for_string "$certificate_decoded" "Public-Key: (384 bit)"
look_for_string "$certificate_decoded" "NIST CURVE: P-384"

look_for_string "$cert_yaml" "rotationPolicy: Always"
look_for_string "$cert_yaml" "renewBefore: 30m0s"
look_for_string "$cert_yaml" "revisionHistoryLimit: 2"

# Can't do string based matching on subject, output from openssl varies between platforms
echo "$cert_yaml" | $YQ eval --exit-status 'select(.spec.subject.provinces[0] == "Ontario")' > /dev/null && echo "Found 'provinces = [Ontario]' in Certificate YAML"
echo "$cert_yaml" | $YQ eval --exit-status 'select(.spec.subject.streetAddresses[0] == "1725 Slough Avenue")' > /dev/null && echo "Found 'streetAddresses = [1725 Slough Avenue]' in Certificate YAML"
echo "$cert_yaml" | $YQ eval --exit-status 'select(.spec.subject.countries[0] == "UK")' > /dev/null && echo "Found 'countries = [UK]' in Certificate YAML"
echo "$cert_yaml" | $YQ eval --exit-status 'select(.spec.subject.postalCodes[0] == "SW1A 2AA")' > /dev/null && echo "Found 'postal codes = [SW1A 2AA]' in Certificate YAML"
echo "$cert_yaml" | $YQ eval --exit-status 'select(.spec.subject.organizations[0] == "cert-manager")' > /dev/null && echo "Found 'organizations = [cert-manager]' in Certificate YAML"
echo "$cert_yaml" | $YQ eval --exit-status 'select(.spec.subject.organizationalUnits[0] == "my-ou")' > /dev/null && echo "Found 'organizationalUnits = [my-ou]' in Certificate YAML"

echo "$cert_yaml" | $YQ eval --exit-status 'select(.spec.privateKey.rotationPolicy == "Always")' > /dev/null && echo "Found 'rotationPolicy == Always' in Certificate YAML"

echo "$cert_yaml" | $YQ eval --exit-status 'select(.spec.renewBefore == "30m0s")' > /dev/null && echo "Found 'renewBefore == 30m0s' in Certificate YAML"

echo "$cert_yaml" | $YQ eval --exit-status 'select(.spec.revisionHistoryLimit == 2)' > /dev/null && echo "Found 'revisionHistoryLimit == 2' in Certificate YAML"

kubectl delete route "$route_name"
