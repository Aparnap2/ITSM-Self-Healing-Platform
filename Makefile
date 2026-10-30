# =============================================================================
# ITSM self-healing platform — local quality gates & stack lifecycle (PRD §10)
#
# All gates run via `uv` (locked environment, uv.lock). Deterministic tests
# never require network, Ollama, or GROQ_API_KEY (PRD §9.3).
#
# NOTE(devops): `make` targets below were verified by running the underlying
# commands directly; see the DEVOPS slice report for evidence.
# =============================================================================

SHELL := /bin/sh

.PHONY: help format format-check lint typecheck test-unit test-security \
        test-integration test-scenarios test compose-up compose-down \
        compose-reset demo-reset demo-run

help: ## Show available targets
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  %-18s %s\n", $$1, $$2}'

# --- Quality gates (run in order; stop on first failure) ----------------------

format: ## Auto-format code with ruff
	uv run ruff format .

format-check: ## Check formatting (CI gate 1a)
	uv run ruff format --check .

lint: ## Lint with ruff (CI gate 1b)
	uv run ruff check .

typecheck: ## Strict typecheck with mypy (CI gate 2)
	uv run mypy src tests

# --- Test suites (pytest markers; deterministic, offline) ---------------------

test-unit: ## Unit tests (CI gate 3)
	uv run pytest -m unit

test-contract: ## Adapter contract tests against simulators (offline)
	uv run pytest -m contract

test-security: ## Security invariant tests (CI gate 4)
	uv run pytest -m security

test-fault-injection: ## Deterministic fault injection tests (requires local stack)
	uv run pytest -m fault_injection

test-integration: ## Integration tests (requires local stack or CI services)
	uv run pytest -m integration

test-scenarios: ## 24-scenario evaluation harness (CI gate 7)
	uv run pytest -m scenarios

sast: ## SAST scan of src/ with bandit (must exit 0)
	uv run bandit -q -c pyproject.toml -r src

audit-deps: ## Known-vulnerability audit of the locked dependency set
	uv export --frozen --format requirements-txt --no-emit-project -o .itsm-requirements.txt
	uv run pip-audit --disable-pip -r .itsm-requirements.txt
	rm -f .itsm-requirements.txt

test: ## Full test suite (all markers)
	uv run pytest

# --- Local stack lifecycle ------------------------------------------------------

compose-up: ## Start full local stack and wait for health
	docker compose up -d --wait

compose-down: ## Stop stack (keep volumes)
	docker compose down --remove-orphans

# Destructive: wipes postgres + nats volumes. Guarded against non-local
# DATABASE_URL values so a staging/production shell cannot be nuked by accident.
compose-reset: ## Stop stack and DELETE all volumes (local only)
	@if [ -n "$$DATABASE_URL" ] && ! echo "$$DATABASE_URL" | grep -qE '(localhost|127\.0\.0\.1)'; then \
		echo "REFUSING to reset: DATABASE_URL does not look local:"; \
		echo "  $$DATABASE_URL"; \
		echo "Unset DATABASE_URL or point it at localhost before wiping volumes."; \
		exit 1; \
	fi; \
	docker compose down -v --remove-orphans

# --- Demo (Phase 8) --------------------------------------------------------------

demo-reset: ## Reset stack to a clean state and bring it back up
	$(MAKE) compose-reset
	$(MAKE) compose-up

demo-run: ## Bring stack up, then run the scenario harness
	$(MAKE) compose-up
	uv run pytest -m scenarios
