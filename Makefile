# ECAC dev automation

.PHONY: help all setup install sync lint format typecheck test verify run experiment doctor
.PHONY: held-out comparative l3-l4-tests

help:
	@echo "EffectBroker — available targets:"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'
	@echo ""

all: lint typecheck test held-out comparative
setup: ## Ensure uv is installed
	@command -v uv >/dev/null 2>&1 || (echo "installing uv..."; curl -LsSf https://astral.sh/uv/install.sh | sh)
	@echo "uv $(shell uv --version 2>/dev/null || true)"

install: ## Create venv and install deps
	uv sync --all-extras --dev
sync: install
lint: ## Lint with ruff
	uv run ruff check effect_broker/ tests/
format: ## Format with ruff
	uv run ruff format effect_broker/ tests/
	uv run ruff check --fix effect_broker/ tests/
typecheck: ## Type-check with mypy
	uv run mypy effect_broker/
test: ## Run pytest suite
	PYTHONPATH=. uv run pytest tests/
l3-l4-tests: ## Run L3/L4 regression tests
	PYTHONPATH=. uv run pytest tests/test_l3_tool_registry_broker.py -v
held-out: ## Run held-out evaluator
	@PYTHONPATH=. uv run python effect_broker/evaluation.py 2>&1
	@echo ""
comparative: ## Run comparative eval
	@PYTHONPATH=. uv run python eval_comparison.py 2>&1
	@echo ""
run: ## Run adversarial trace suite
	@PYTHONPATH=. uv run python -W ignore run_traces.py 2>&1
verify: ## Verify trace outcomes
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
clean: ## Remove cache files
	rm -rf .pytest_cache .mypy_cache .ruff_cache __pycache__ dist build
	find . -type d -name __pycache__ -prune -exec rm -rf {} + 2>/dev/null || true
doctor: ## Show env status
	@echo "uv:        $$(uv --version 2>/dev/null || echo MISSING)"
	@echo "python:    $$(uv run python --version 2>/dev/null || echo MISSING)"
	@echo "lockfile:  $$([ -f uv.lock ] && echo present || echo MISSING)"
	@echo "venv:      $$([ -d .venv ] && echo present || echo MISSING)"
	@echo "pytest:    $$(PYTHONPATH=. uv run pytest --version 2>/dev/null || echo MISSING)"
	@echo "tests:     $$([ -d tests ] && echo present || echo MISSING)"
