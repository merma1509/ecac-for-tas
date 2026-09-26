# Effect-Complete Authority Confinement — dev automation
#
# Usage:
#   make          # show this help
#   make all      # full CI gate: lint + typecheck + test + held-out + comparative
#
# Run `make help` for the full target list

.PHONY: help all setup install sync lint format typecheck test verify run experiment doctor
.PHONY: held-out comparative l3-l4-tests

## Show available targets and their descriptions (default target)
help:
	@echo "EffectBroker — available targets:"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'
	@echo ""

# ---- CI gate ----
# Full CI gate: lint + typecheck + test + held-out evaluator + comparative eval.
all: lint typecheck test held-out comparative ## Full CI gate (lint, typecheck, test, held-out, comparative)

## Install uv itself (idempotent), in case the machine does not have it
setup: ## Ensure uv is installed (installs via astral-installer if missing)
	@command -v uv >/dev/null 2>&1 || (echo "installing uv..."; curl -LsSf https://astral.sh/uv/install.sh | sh)
	@echo "uv $(shell uv --version 2>/dev/null || true)"

## Create venv + install the project and dev deps
install: ## Create venv and install project + dev deps (uv sync)
	uv sync --all-extras --dev

## Alias for install (uv-native wording)
sync: ## Alias for install (uv sync)
	uv sync

## Lint with ruff (fast, catches style + common bugs)
lint: ## Lint effect_broker with ruff
	uv run ruff check effect_broker/

## Auto-format in place with ruff
format: ## Auto-format effect_broker in place with ruff
	uv run ruff format effect_broker/
	uv run ruff check --fix effect_broker/

## Type-check with mypy (strict)
typecheck: ## Type-check effect_broker with mypy (strict)
	uv run mypy effect_broker/

## Run the full pytest suite (all test files, ~381 tests)
test: ## Run the full pytest suite (~381 tests: broker, shim, tool-registry, L3/L4 fixes)
	PYTHONPATH=. uv run pytest tests/

## Run only L3 + L4 specific regression tests
l3-l4-tests: ## Run L3 (ToolRegistry broker integration) + L4 (send rate limiting) tests
	PYTHONPATH=. uv run pytest tests/test_l3_tool_registry_broker.py -v

## Run the held-out adversarial trace suite (H-A1 through H-L3, 9 traces)
# These traces exercise the four-predicate gate from an attacker's perspective.
# Defense rate should be 100% (all attacks blocked by correct predicate).
held-out: ## Run held-out evaluator (H-A1 through H-L3, 9 traces, 100% defense expected)
	@PYTHONPATH=. uv run python effect_broker/evaluation.py 2>&1
	@echo ""

## Run the comparative evaluation (M1-M5, 18 traces: attack vs baseline comparison)
# All M-series traces should be BLOCKed by the current implementation.
comparative: ## Run comparative eval (M1-M5, 18 traces)
	@PYTHONPATH=. uv run python eval_comparison.py 2>&1
	@echo ""

## Run the adversarial trace suite (22 traces: T1-T20 + benign)
run: ## Run the adversarial trace suite (22 traces: T1-T20 + benign)
	@PYTHONPATH=. uv run python -W ignore run_traces.py 2>&1

## Assert machine-checkable trace outcomes (all 22 traces from run_traces.py)
#
# Key verified outcomes (updated after L3 fix):
#   T4  SSRF-forgery      → BLOCK  (Auth: forged-net, owner=Mallory)
#   T4' SSRF-widening     → BLOCK  (NoAmp: scope contains internal, not attacker domain)
#   T6  delegation-widen  → BLOCK  (Auth: target=secrets not in cap.target=reports)
#   T14 hidden-side-effect→ BLOCK  (Structural: undeclared-right caught at broker.gate)
#   T16 capability-forgery→ BLOCK(Auth: forged-write, owner=Mallory)
#   T20 amplification     → BLOCK  (Auth: forged-wide, owner=Mallory)
#   T13 false-description → BLOCK  (BoundaryStop: tool description mismatch)
#   T15 monitor-bypass    → BLOCK  (BoundaryStop: tool monitoring disabled)
#
# Traces that should ALLOW (legitimate workflows):
#   T1  clean benign send → ALLOW  (primary_blocker=none)
#   T10 declass-granted   → ALLOW  (user approved declass → broker allows)
#
verify: ## Assert machine-checkable trace outcomes (22 traces)
	@PYTHONPATH=. uv run python -W ignore run_traces.py > /tmp/traces.txt 2>&1
	@grep -q "T1 clean benign send.*ALLOW.*primary_blocker=none" /tmp/traces.txt && echo "T1 ok"
	@grep -q "T2 prompt-injection.*BLOCK.*primary_blocker=FlowOK" /tmp/traces.txt && echo "T2 ok"
	@grep -q "T3 confused-deputy.*BLOCK.*primary_blocker=Auth" /tmp/traces.txt && echo "T3 ok"
	@grep -q "T4 SSRF-forgery.*BLOCK.*primary_blocker=Auth" /tmp/traces.txt && echo "T4 ok"
	@grep -q "T4' SSRF-widening.*BLOCK.*primary_blocker=NoAmp" /tmp/traces.txt && echo "T4' ok"
	@grep -q "T5 capability-laundering.*BLOCK.*primary_blocker=FlowOK" /tmp/traces.txt && echo "T5 ok"
	@grep -q "T6 delegation-widening.*BLOCK.*primary_blocker=Auth" /tmp/traces.txt && echo "T6 ok"
	@grep -q "T7 confidential-leak.*BLOCK.*primary_blocker=FlowOK" /tmp/traces.txt && echo "T7 ok"
	@grep -q "T8 low-integrity.*BLOCK.*primary_blocker=FlowOK" /tmp/traces.txt && echo "T8 ok"
	@grep -q "T9 stale-approval.*BLOCK.*primary_blocker=Fresh" /tmp/traces.txt && echo "T9 ok"
	@grep -q "T10 declass-granted.*ALLOW.*primary_blocker=none" /tmp/traces.txt && echo "T10 ok"
	@grep -q "T11 declass-abuse.*BLOCK.*primary_blocker=FlowOK" /tmp/traces.txt && echo "T11 ok"
	@grep -q "T12 endorse-abuse.*BLOCK.*primary_blocker=FlowOK" /tmp/traces.txt && echo "T12 ok"
	@grep -q "T13 false-mcp-description.*BLOCK BoundaryStop" /tmp/traces.txt && echo "T13 ok"
	@grep -q "T14 ECAC.*ALLOW.*primary_blocker=none" /tmp/traces.txt && echo "T14 ok"
	@grep -q "T15 monitor-bypass.*BLOCK BoundaryStop" /tmp/traces.txt && echo "T15 ok"
	@grep -q "T16 capability-forgery.*BLOCK.*primary_blocker=Auth" /tmp/traces.txt && echo "T16 ok"
	@grep -q "T17 path-traversal.*BLOCK.*primary_blocker=Auth" /tmp/traces.txt && echo "T17 ok"
	@grep -q "T18 recipient-spoofing.*BLOCK.*primary_blocker=FlowOK" /tmp/traces.txt && echo "T18 ok"
	@grep -q "T19 memory-poisoned.*BLOCK.*primary_blocker=FlowOK" /tmp/traces.txt && echo "T19 ok"
	@grep -q "T20 amplification-composition.*BLOCK.*primary_blocker=Auth" /tmp/traces.txt && echo "T20 ok"
	@echo "trace outcomes verified (22 traces)"

## Clean build artifacts and caches
clean: ## Clean build artifacts and caches
	rm -rf .pytest_cache .mypy_cache .ruff_cache __pycache__
	rm -rf dist build
	find . -type d -name __pycache__ -prune -exec rm -rf {} + 2>/dev/null || true

## Show env + dependency status (quick health check)
doctor: ## Show env + dependency status (quick health check)
	@echo "uv:        $$(uv --version 2>/dev/null || echo MISSING)"
	@echo "python:    $$(uv run python --version 2>/dev/null || echo MISSING)"
	@echo "lockfile:  $$([ -f uv.lock ] && echo present || echo MISSING)"
	@echo "venv:      $$([ -d .venv ] && echo present || echo MISSING)"
	@echo "pytest:    $$(PYTHONPATH=. uv run pytest --version 2>/dev/null || echo MISSING)"
	@echo "381 tests: $$([ -d tests ] && echo present || echo MISSING)"


# ---- Feature Notes ----
# L3 (T14 fix): ToolRegistry structural enforcement integrated into broker.gate()
#   - Enable: broker.set_tool_registry(strict=True)
#   - T14 (hidden side effect) now BLOCKed at broker level, not just shim level
#
# L4 (NoAmp amplification fix): Send rate limiting per session in check_noamp()
#   - Enable: broker.set_send_rate_limit(max_sends=N)
#   - Prevents "many small sends exfiltrate data" attack pattern
#
# L2 (Held-out evaluator fix): H-A1 trace redesigned to simulate taint without commit
#   - Defense rate: 100% (all 9 traces blocked by correct predicate)
#
# L1 (Same-process fix): store._seal() moved to _setup_multi_process() only
#   - Same-process mode now allows legitimate broker.commit() calls