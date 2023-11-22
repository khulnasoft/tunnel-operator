#!/usr/bin/env bash

SCRIPT_ROOT=$(dirname "${BASH_SOURCE[0]}")/..

CRD_DIR=$SCRIPT_ROOT/deploy/helm/crds
HELM_DIR=$SCRIPT_ROOT/deploy/helm
STATIC_DIR=$SCRIPT_ROOT/deploy/static

HELM_TMPDIR=$(mktemp -d)
trap "rm -rf $HELM_TMPDIR" EXIT

helm template tunnel-operator $HELM_DIR \
  --namespace tunnel-system \
  --set="managedBy=kubectl" \
  --output-dir=$HELM_TMPDIR

cat $CRD_DIR/* > $STATIC_DIR/tunnel-operator.yaml

## if namespace.yaml do not exist, cat namespace.yaml to tunnel-operator.yaml (avoid duplicate namespace definition)
[ ! -f $HELM_TMPDIR/tunnel-operator/templates/namespace.yaml ] && cat $STATIC_DIR/namespace.yaml >> $STATIC_DIR/tunnel-operator.yaml

cat $HELM_TMPDIR/tunnel-operator/templates/rbac/* > $STATIC_DIR/rbac.yaml
cp $STATIC_DIR/rbac.yaml $HELM_TMPDIR/tunnel-operator/templates
cat $HELM_TMPDIR/tunnel-operator/templates/serviceaccount.yaml >> $STATIC_DIR/rbac.yaml
rm -rf $HELM_TMPDIR/tunnel-operator/templates/rbac

cat $HELM_TMPDIR/tunnel-operator/templates/configmaps/* > $STATIC_DIR/config.yaml
cat $HELM_TMPDIR/tunnel-operator/templates/secrets/* >> $STATIC_DIR/config.yaml
cp $STATIC_DIR/config.yaml $HELM_TMPDIR/tunnel-operator/templates
rm -rf $HELM_TMPDIR/tunnel-operator/templates/configmaps
rm -rf $HELM_TMPDIR/tunnel-operator/templates/secrets

cat $HELM_TMPDIR/tunnel-operator/templates/specs/* > $STATIC_DIR/specs.yaml
rm -rf $HELM_TMPDIR/tunnel-operator/templates/specs

[ -d $HELM_TMPDIR/tunnel-operator/templates/tunnel-server ] && cat $HELM_TMPDIR/tunnel-operator/templates/tunnel-server/* > $STATIC_DIR/tunnel-server.yaml && cp $STATIC_DIR/tunnel-server.yaml $HELM_TMPDIR/tunnel-operator/templates
rm -rf $HELM_TMPDIR/tunnel-operator/templates/tunnel-server

cat $HELM_TMPDIR/tunnel-operator/templates/monitor/* > $STATIC_DIR/monitor.yaml
cp $STATIC_DIR/monitor.yaml $HELM_TMPDIR/tunnel-operator/templates
rm -rf $HELM_TMPDIR/tunnel-operator/templates/monitor


cat $HELM_TMPDIR/tunnel-operator/templates/* >> $STATIC_DIR/tunnel-operator.yaml

# Copy all manifests rendered by the Helm chart to the static resources directory,
# where they should be ignored by Git.
# This is done to support local development with partial updates to local cluster.

