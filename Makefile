# ECAC dev automation

.PHONY: help all setup install sync lint format typecheck test
.PHONY: held-out comparative experiment doctor clean

help:
	@echo "EffectBroker — available targets:"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'
	@echo ""

all: lint typecheck test held-out comparative experiment
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
held-out: ## Run held-out evaluator (8 sealed traces)
	@echo "=== HELD-OUT EVALUATION (8 traces) ==="
	@PYTHONPATH=. uv run python bin/eval-held-out

comparative: ## Run baseline comparison (ECAC vs 7 baselines on 20 traces)
	@echo "=== BASELINE COMPARISON (20 traces, 8 baselines) ==="
	@PYTHONPATH=. uv run python bin/eval-baseline

experiment: ## Run real adversarial tool experiment (M1-M5, H1-H3, T9-T20)
	@echo "=== EXPERIMENT TRACES (M1-M5, H1-H3, T9-T20) ==="
	@PYTHONPATH=. uv run python bin/eval-experiment

run: ## Run the trace suite (T1–T20 + R1)
	@echo "=== TRACES (T1–T20 + R1) ==="
	@PYTHONPATH=. uv run python -m effect_broker

doctor: ## Show env status
	@echo "uv:        $$(uv --version 2>/dev/null || echo MISSING)"
	@echo "python:    $$(uv run python --version 2>/dev/null || echo MISSING)"
	@echo "lockfile:  $$([ -f uv.lock ] && echo present || echo MISSING)"
	@echo "venv:      $$([ -d .venv ] && echo present || echo MISSING)"
	@echo "pytest:    $$(PYTHONPATH=. uv run pytest --version 2>/dev/null || echo MISSING)"
	@echo "tests:     $$([ -d tests ] && echo present || echo MISSING)"
clean: ## Remove cache files
	rm -rf .pytest_cache .mypy_cache .ruff_cache __pycache__ dist build
	find . -type d -name __pycache__ -prune -exec rm -rf {} + 2>/dev/null || true
