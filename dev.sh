#!/usr/bin/env bash
# EffectBroker dev helper — thin wrapper over the Makefile targets
# Usage:
#   ./dev.sh setup      install uv if missing
#   ./dev.sh install    sync deps + create venv
#   ./dev.sh lint       run ruff
#   ./dev.sh format     auto-format
#   ./dev.sh typecheck  run mypy
#   ./dev.sh test       run pytest
#   ./dev.sh run        run the trace suite
#   ./dev.sh experiment run the adversarial workload (M1-M5 + H1-H3)
#   ./dev.sh verify     assert trace outcomes
#   ./dev.sh clean      remove caches/build
#   ./dev.sh doctor     environment status
#   ./dev.sh shell      drop into a shell with the venv active
set -euo pipefail

TARGET="${1:-help}"

case "$TARGET" in
  setup)     make setup ;;
  install)   make install ;;
  sync)      make sync ;;
  lint)      make lint ;;
  format)    make format ;;
  typecheck) make typecheck ;;
  test)      make test ;;
  run)       make run ;;
  experiment) make experiment ;;
  verify)    make verify ;;
  clean)     make clean ;;
  doctor)    make doctor ;;
  shell)
    if [ ! -d .venv ]; then make install; fi
    # shellcheck disable=SC1091
    source .venv/bin/activate
    exec "$SHELL"
    ;;
  help|*)
    # Print only the leading usage comment block, stripped of the '#' marker
    sed -n '2,15p' "$0" | sed 's/^# \{0,1\}//'
    ;;
esac
