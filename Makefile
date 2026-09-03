# Effect-Complete Authority Confinement — dev automation
# Usage:
#   make          # show this help
#   make all      # full CI gate: lint + typecheck + test + verify
#   make help     # show all targets
# Run `make help` for the target list

.PHONY: help all setup install sync lint format typecheck test verify run traces clean doctor

## Show available targets and their descriptions (default target)
help:
	@echo "EffectBroker — available targets:"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'
	@echo ""

all: setup lint typecheck test verify ## Full CI gate (same as CI: lint, typecheck, test, verify)

## Install uv itself (idempotent), in case the machine does not have it
setup: ## Ensure uv is installed (installs via astral-installer if missing)
	@command -v uv >/dev/null 2>&1 || (echo "installing uv..."; curl -LsSf https://astral.sh/uv/install.sh | sh)
	@echo "s uv $(shell uv --version 2>/dev/null || true)"

## Create venv + install the project and dev deps
install: ## Create venv and install project + dev deps (uv sync)
	uv sync --all-extras --dev

## Alias for install (uv-native wording)
sync: ## Alias for install (uv native wording)
	uv sync

## Lint with ruff (fast, catches style + common bugs)
lint: ## Lint with ruff (fast, catches style + common bugs)
	uv run ruff check .

## Auto-format in place with ruff
format: ## Auto-format in place with ruff
	uv run ruff format .
	uv run ruff check --fix .

## Type-check with mypy (strict)
typecheck: ## Type-check with mypy (strict)
	uv run mypy effect_broker

## Run the pytest suite
test: ## Run the pytest suite
	uv run pytest

## Run the adversarial trace suite (the tiny executable model)
run: ## Run the adversarial trace suite (tiny executable model)
	uv run python run_traces.py

## Assert the machine-checkable trace outcomes (same checks as CI)
verify: run ## Assert machine-checkable trace outcomes (same checks as CI)
	@uv run python run_traces.py > /tmp/traces.txt
	@grep -q "T1 clean benign send -> ALLOW.*primary_blocker=none" /tmp/traces.txt && echo "T1 ok"
	@grep -q "T2 prompt-injection.*primary_blocker=FlowOK" /tmp/traces.txt && echo "T2 ok"
	@grep -q "T3 confused-deputy.*primary_blocker=Auth" /tmp/traces.txt && echo "T3 ok"
	@grep -q "T4 attacker-controlled-URL.*primary_blocker=NoAmp" /tmp/traces.txt && echo "T4 ok"
	@grep -q "T5 capability-laundering.*primary_blocker=FlowOK" /tmp/traces.txt && echo "T5 ok"
	@grep -q "T6 delegation-widening.*primary_blocker=NoAmp" /tmp/traces.txt && echo "T6 ok"
	@grep -q "T7 confidential-leak.*primary_blocker=FlowOK" /tmp/traces.txt && echo "T7 ok"
	@grep -q "T8 low-integrity->privileged.*primary_blocker=FlowOK" /tmp/traces.txt && echo "T8 ok"
	@grep -q "T9 stale-approval.*primary_blocker=Fresh" /tmp/traces.txt && echo "T9 ok"
	@grep -q "T10 replay.*2nd BLOCK Fresh" /tmp/traces.txt && echo "T10 ok"
	@grep -q "T11 declass-abuse.*primary_blocker=FlowOK" /tmp/traces.txt && echo "T11 ok"
	@grep -q "T12 endorse-abuse.*primary_blocker=FlowOK" /tmp/traces.txt && echo "T12 ok"
	@grep -q "T13 false-mcp-description.*BLOCK BoundaryStop" /tmp/traces.txt && echo "T13 ok"
	@grep -q "T14 hidden-side-effect.*BLOCK BoundaryStop" /tmp/traces.txt && echo "T14 ok"
	@grep -q "T15 monitor-bypass.*BLOCK BoundaryStop" /tmp/traces.txt && echo "T15 ok"
	@grep -q "T16 capability-forgery.*primary_blocker=NoAmp" /tmp/traces.txt && echo "T16 ok"
	@grep -q "T17 path-traversal.*primary_blocker=Auth" /tmp/traces.txt && echo "T17 ok"
	@grep -q "T18 recipient-spoofing.*primary_blocker=FlowOK" /tmp/traces.txt && echo "T18 ok"
	@grep -q "T19 memory-poisoned.*primary_blocker=FlowOK" /tmp/traces.txt && echo "T19 ok"
	@grep -q "T20 amplification-composition.*primary_blocker=NoAmp" /tmp/traces.txt && echo "T20 ok"
	@echo "trace outcomes verified (all 20 traces)"

## Clean build artifacts and caches
clean: ## Clean build artifacts and caches
	rm -rf .pytest_cache .mypy_cache .ruff_cache
	rm -rf dist build
	find . -type d -name __pycache__ -prune -exec rm -rf {} +

## Show env + dependency status (quick health check)
doctor: ## Show env + dependency status (quick health check)
	@echo "uv:        $$(uv --version 2>/dev/null || echo MISSING)"
	@echo "python:    $$(uv run python --version 2>/dev/null || echo MISSING)"
	@echo "lockfile:  $$([ -f uv.lock ] && echo present || echo MISSING)"
	@echo "venv:      $$([ -d .venv ] && echo present || echo MISSING)"

