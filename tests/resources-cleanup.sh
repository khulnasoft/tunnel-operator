#!/usr/bin/env bash
helm uninstall tunnel-operator  -n tunnel-system
kubectl delete crd vulnerabilityreports.khulnasoft.github.io
kubectl delete crd configauditreports.khulnasoft.github.io
kubectl delete crd clusterconfigauditreports.khulnasoft.github.io
kubectl delete crd rbacassessmentreports.khulnasoft.github.io
kubectl delete crd infraassessmentreports.khulnasoft.github.io
kubectl delete crd clusterrbacassessmentreports.khulnasoft.github.io
kubectl delete crd sbomreports.khulnasoft.github.io
kubectl delete crd clustersbomreports.khulnasoft.github.io
