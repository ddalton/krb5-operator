#!/usr/bin/env bash
# kind.sh: run the end-to-end tests against images built from THIS tree,
# on a throwaway kind cluster. CI (.github/workflows/e2e.yml) runs exactly
# this script; run it on any host with docker to reproduce a CI result.
#
#   1. builds krb5-operator:e2e (Dockerfile) and krb5-kdc:e2e (images/kdc)
#      (BUILD=0: use images already built);
#   2. creates a kind cluster and loads both images into it;
#   3. installs the CRDs and the operator (deploy/), with the e2e image;
#   4. runs chainsaw over tests/ (TESTS=tests/<name> for one test).
#
# Env: CLUSTER (krb5-operator-e2e)  BUILD (1)  KEEP (0; 1 = leave the
#      cluster up)  KIND_NODE_IMAGE (kindest/node:v1.34.0)  TESTS (tests)
#      REPORT_DIR (unset; set = write a JUnit report there)
# Uses a PRIVATE kubeconfig: never touches ~/.kube/config.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
CLUSTER="${CLUSTER:-krb5-operator-e2e}"
BUILD="${BUILD:-1}"
KEEP="${KEEP:-0}"
KIND_NODE_IMAGE="${KIND_NODE_IMAGE:-kindest/node:v1.34.0}"
export KUBECONFIG="${KUBECONFIG_PRIVATE:-$(mktemp -d)/kubeconfig}"

step() { printf '\n▶ %s\n' "$*" >&2; }
fail() { printf '\n✗ %s\n' "$*" >&2; exit 1; }

for t in docker kind kubectl chainsaw; do
  command -v "$t" >/dev/null || fail "$t not found in PATH"
done

cleanup() {
  rc=$?
  if [ "$KEEP" = 1 ]; then
    echo "KEEP=1: cluster $CLUSTER left up; KUBECONFIG=$KUBECONFIG" >&2
  else
    kind delete cluster --name "$CLUSTER" >/dev/null 2>&1 || true
  fi
  exit "$rc"
}
trap cleanup EXIT

if [ "$BUILD" = 1 ]; then
  step "build krb5-operator:e2e"
  DOCKER_BUILDKIT=1 docker build -t krb5-operator:e2e "$ROOT"
  step "build krb5-kdc:e2e"
  DOCKER_BUILDKIT=1 docker build -t krb5-kdc:e2e "$ROOT/images/kdc"
fi

step "kind cluster $CLUSTER ($KIND_NODE_IMAGE)"
kind delete cluster --name "$CLUSTER" >/dev/null 2>&1 || true
kind create cluster --name "$CLUSTER" --image "$KIND_NODE_IMAGE" --kubeconfig "$KUBECONFIG"
step "load images into the cluster"
kind load docker-image --name "$CLUSTER" krb5-operator:e2e krb5-kdc:e2e

step "install the operator"
kubectl apply --server-side -f "$ROOT/deploy/crds.yaml"
kubectl wait --for=condition=Established crd/kerberosrealms.krb5.ddalton.dev crd/kerberosprincipals.krb5.ddalton.dev
perl -pe 's|image: ghcr.io/ddalton/krb5-operator:.*|image: krb5-operator:e2e\n          imagePullPolicy: Never|' \
  "$ROOT/deploy/operator.yaml" | kubectl apply -f -
kubectl -n krb5-operator rollout status deployment/krb5-operator --timeout=120s

TESTS="${TESTS:-tests}"
step "chainsaw: $TESTS"
report=()
if [ -n "${REPORT_DIR:-}" ]; then
  mkdir -p "$REPORT_DIR"
  report=(--report-format JUNIT-TEST --report-path "$REPORT_DIR" --report-name krb5-operator-e2e)
fi
cd "$HERE"
chainsaw test --config chainsaw.yaml --test-dir "$TESTS" "${report[@]}"
