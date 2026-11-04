#!/usr/bin/env bash
#
# Release eval gate: sealed evaluation assertions.
#
# Shared by:
#   - .github/workflows/ci.yml  (eval job, PRs targeting main)
#   - .github/workflows/cd.yml  (release job, tags)
#
# The eval scripts print a human report and exit 0 regardless of outcome, so we
# grep for the exact expected assertions. Any regression fails this script.
#
# Usage: scripts/verify_eval.sh
#
set -euo pipefail

check() {
    local file="$1" pattern="$2"
    if ! grep -q -- "$pattern" "$file"; then
        printf 'FAIL: %s does not contain: %s\n' "$file" "$pattern" >&2
        exit 1
    fi
}

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

# ---- held-out: 8 sealed traces must all be blocked ----
uv run python bin/eval-held-out | tee "$tmp/held-out.txt"
check "$tmp/held-out.txt" "Blocked (safe): 8/8 (100%)"
check "$tmp/held-out.txt" "High-severity: 6/6 defended"
check "$tmp/held-out.txt" "Traces SHA-256: 6e1d14c872d495bd"
echo "held-out OK (8/8 blocked, sealed hash intact)"

# ---- baseline comparison: ECAC 20/20, kill criterion passes ----
uv run python bin/eval-baseline | tee "$tmp/baseline.txt"
check "$tmp/baseline.txt" "ECAC blocks 20/20 traces"
check "$tmp/baseline.txt" "Kill criterion (ECAC ≥4 beyond PACT): PASS"
echo "baseline OK (ECAC 20/20, kill criterion PASS)"

# ---- adversarial experiment: 17/18 blocked, benign M4 allowed ----
uv run python bin/eval-experiment | tee "$tmp/experiment.txt"
check "$tmp/experiment.txt" "17/18 traces blocked"
check "$tmp/experiment.txt" "M4 (benign tool): PASS"
echo "experiment OK (17/18 blocked, benign M4 allowed)"
