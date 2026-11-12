#!/usr/bin/env bash
#
# Run `capture_mta_log.py` inside a container, so the real-MTA capture does not
# require postfix on the developer's machine or root on a shared host.
#
# Usage: scripts/capture_mta_log.sh [output-path]
# Default output: tests/data/postfix-maillog.txt
#
# The captured log is committed because it is the fixture `tests/test_mta_log.py`
# parses. Regenerate it only when the parser or the claimed MTA behaviour
# changes; a fixture that drifts from what the MTA writes turns the test into a
# test of itself.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
out_path="${1:-tests/data/postfix-maillog.txt}"

# The script runs as root inside the container, which is what starting a daemon
# needs, and the mounted tree is this checkout — so `--out` lands on the host.
docker run --rm \
    -v "${repo_root}":/w -w /w \
    -e DEBIAN_FRONTEND=noninteractive \
    debian:bookworm-slim \
    sh -c '
set -e
apt-get update -qq >/dev/null 2>&1
apt-get install -y -qq postfix python3 >/dev/null 2>&1
python3 scripts/capture_mta_log.py --out "$1"
' sh "${out_path}"
