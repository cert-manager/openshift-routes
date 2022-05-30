#!/usr/bin/env bash
set -euo pipefail
if [ $# -ne 1 ]; then
    echo "Usage: $0 RELEASED_VERSION"
    exit 1
fi
export RELEASED_VERSION="$1"
envsubst < "./deploy/static/cert-manager-openshift-routes.yaml" > "cert-manager-openshift-routes-$RELEASED_VERSION.yaml"
exit 0
