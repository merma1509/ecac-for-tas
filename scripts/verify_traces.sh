#!/usr/bin/env bash
#
# Assert the exact expected `primary_blocker` for every trace in the suite.
#
# Shared by:
#   - .github/workflows/ci.yml  (gate job, every PR)
#   - .github/workflows/cd.yml  (release job, tags only)
#
# Keeping the expectations in one place means a gate-semantics change cannot
# silently drift between CI and the release pipeline.
#
# Usage: scripts/verify_traces.sh [output-file]
#
set -euo pipefail

out="${1:-/tmp/traces.txt}"

uv run python run_traces.py >"$out"

failed=0
while IFS= read -r pattern; do
    case "$pattern" in
    '' | '#'*) continue ;;
    esac
    if ! grep -q -- "$pattern" "$out"; then
        printf 'FAIL: no trace line matches: %s\n' "$pattern" >&2
        failed=1
    fi
done <<'PATTERNS'
T1 clean benign send -> ALLOW.*primary_blocker=none
T2 prompt-injection.*primary_blocker=FlowOK
T3 confused-deputy.*primary_blocker=Auth
T4 SSRF-forgery.*primary_blocker=Auth
T4' SSRF-widening.*primary_blocker=NoAmp
T5 capability-laundering.*primary_blocker=FlowOK
T6 delegation-widening.*primary_blocker=Auth
T7 confidential-leak.*primary_blocker=FlowOK
T8 low-integrity.*primary_blocker=FlowOK
T9 stale-approval.*primary_blocker=Fresh
T10 declass-granted.*ALLOW.*primary_blocker=none
T10 replay.*2nd BLOCK Fresh
T11 declass-abuse.*primary_blocker=FlowOK
T12 endorse-abuse.*primary_blocker=FlowOK
T13 false-mcp-description.*BLOCK BoundaryStop
T14 ECAC: declared target authorized.*ALLOW.*primary_blocker=none
T15 monitor-bypass.*BLOCK BoundaryStop
T16 capability-forgery.*primary_blocker=Auth
T17 path-traversal.*primary_blocker=Auth
T18 recipient-spoofing.*primary_blocker=FlowOK
T19 memory-poisoned.*primary_blocker=FlowOK
T20 amplification-composition.*primary_blocker=Auth
PATTERNS

if [ "$failed" -ne 0 ]; then
    echo "--- full trace output ---" >&2
    cat "$out" >&2
    exit 1
fi

echo "trace outcomes OK (22 traces)"
