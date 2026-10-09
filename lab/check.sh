#!/bin/sh
# Single low-rate lab-only reachability observation. Requires kubectl and an owned cluster.
set -eu
[ "${1:-}" = "--i-own-this-lab" ] || { echo "Pass --i-own-this-lab after verifying kubectl context"; exit 2; }
context=$(kubectl config current-context)
case "$context" in kind-cyber-defense) ;; *) echo "Unexpected kubectl context: $context" >&2; exit 2 ;; esac
kubectl -n cyber-lab rollout status deployment/frontend --timeout=120s
kubectl -n cyber-lab rollout status deployment/canary --timeout=120s
pod=$(kubectl -n cyber-lab get pod -l app=frontend -o jsonpath='{.items[0].metadata.name}')
echo "Observation from $pod in $context:"
kubectl -n cyber-lab exec "$pod" -- curl -sS --max-time 3 -o /dev/null -w 'http_status=%{http_code}\n' http://canary.cyber-lab.svc.cluster.local:8080/ || echo "connection not completed"
