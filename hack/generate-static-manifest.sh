#!/usr/bin/env bash
set -euo pipefail
if [ $# -ne 1 ]; then
    echo "Usage: $0 RELEASED_VERSION"
    exit 1
fi

# First, let's generate the static manifest that can be used with `kubectl apply
# -f`.
export RELEASED_VERSION="$1"
export NAMESPACE=cert-manager
envsubst <"./deploy/static/cert-manager-openshift-routes.yaml" >"cert-manager-openshift-routes-$RELEASED_VERSION.yaml"

# Next, let's generate the static manifest that can be used with `oc process -p
# NAMESPACE=foo -f`.
export NAMESPACE='${NAMESPACE}'
envsubst <"./deploy/static/cert-manager-openshift-routes.yaml" \
    | yq ea '[.]' ./deploy/static/cert-manager-openshift-routes.yaml \
    | yq "$(
        cat <<'EOF'
{
    "apiVersion": "template.openshift.io/v1",
    "kind": "Template",
    "metadata": {
        "name":"cert-manager-openshift-routes-deploy"
    },
    "objects": .,
    "parameters": [
        {
            "name": "NAMESPACE",
            "description": "Namespace where openshift-routes should be installed.",
            "value": "cert-manager",
            "required": true
        }
    ]
}
EOF
    )" \
        >"cert-manager-openshift-routes-$RELEASED_VERSION-tpl.yaml"
exit 0
