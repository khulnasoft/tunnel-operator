#!/usr/bin/env bash

SCRIPT_ROOT=$(dirname "${BASH_SOURCE[0]}")/..

CRD_DIR=$SCRIPT_ROOT/deploy/helm/crds
HELM_DIR=$SCRIPT_ROOT/deploy/helm
STATIC_DIR=$SCRIPT_ROOT/deploy/static

HELM_TMPDIR=$(mktemp -d)
trap "rm -rf $HELM_TMPDIR" EXIT

helm template tunnel-operator $HELM_DIR \
  --namespace trivy-system \
  --set="managedBy=kubectl" \
  --output-dir=$HELM_TMPDIR

cat $CRD_DIR/* > $STATIC_DIR/tunnel-operator.yaml

## if ns.yaml do not exist, cat namespace.yaml to tunnel-operator.yaml (avoid duplicate namespace definition)
[ ! -f $HELM_TMPDIR/tunnel-operator/templates/ns.yaml ] && cat $STATIC_DIR/namespace.yaml >> $STATIC_DIR/tunnel-operator.yaml

cat $HELM_TMPDIR/tunnel-operator/templates/specs/* > $STATIC_DIR/specs.yaml
rm -rf $HELM_TMPDIR/tunnel-operator/templates/specs
cat $HELM_TMPDIR/tunnel-operator/templates/* >> $STATIC_DIR/tunnel-operator.yaml

# Copy all manifests rendered by the Helm chart to the static resources directory,
# where they should be ignored by Git.
# This is done to support local development with partial updates to local cluster.
cp $HELM_TMPDIR/tunnel-operator/templates/* $STATIC_DIR/

