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

.PHONY: help format format-check lint typecheck test-unit test-contract \
        test-security test-fault-injection test-integration test-scenarios \
        test-e2e verify verify-ci test sast audit-deps hooks-install \
        verify-pre-push act-ci compose-up compose-down \
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

# --- Test suites (single source of selection; CI invokes these targets) ------

PYTEST_OPTS ?=

test-unit: ## Unit tests
	uv run pytest -m unit $(PYTEST_OPTS)

test-contract: ## Adapter contract tests against simulators (offline)
	uv run pytest -m contract $(PYTEST_OPTS)

test-security: ## Security invariant tests (requires PG; fail closed on missing services in CI)
	ITSM_TEST_STRICT=$${ITSM_TEST_STRICT:-1} uv run pytest -m security $(PYTEST_OPTS)

test-fault-injection: ## Deterministic fault injection tests (requires PG+NATS)
	ITSM_TEST_STRICT=$${ITSM_TEST_STRICT:-1} uv run pytest -m fault_injection $(PYTEST_OPTS)

test-integration: ## Integration tests (requires PG+NATS)
	ITSM_TEST_STRICT=$${ITSM_TEST_STRICT:-1} uv run pytest -m integration $(PYTEST_OPTS)

test-scenarios: ## 24-scenario evaluation harness
	ITSM_TEST_STRICT=$${ITSM_TEST_STRICT:-1} uv run pytest -m scenarios $(PYTEST_OPTS)

test-e2e: ## Complete end-to-end scenarios (requires PG+NATS+simulators)
	ITSM_TEST_STRICT=$${ITSM_TEST_STRICT:-1} uv run pytest -m e2e $(PYTEST_OPTS)

verify: ## Local full verification (offline + PG/NATS required)
	$(MAKE) format-check lint typecheck test-unit test-contract test-security test-integration test-scenarios test-e2e sast

verify-ci: ## Strict CI-equivalent verification
	ITSM_TEST_STRICT=1 $(MAKE) format-check lint typecheck sast
	ITSM_TEST_STRICT=1 $(MAKE) test-unit test-contract test-security test-integration test-fault-injection test-scenarios
	ITSM_TEST_STRICT=1 $(MAKE) test-e2e

sast: ## SAST scan of src/ with bandit (must exit 0)
	uv run bandit -q -c pyproject.toml -r src

audit-deps: ## Known-vulnerability audit of the locked dependency set
	uv export --frozen --format requirements-txt --no-emit-project -o .itsm-requirements.txt
	uv run pip-audit --disable-pip -r .itsm-requirements.txt
	rm -f .itsm-requirements.txt

# --- Versioned hooks & local GitHub Actions -----------------------------------

hooks-install: ## Install versioned git hooks (core.hooksPath=.githooks)
	git config core.hooksPath .githooks
	@echo "Installed: core.hooksPath=.githooks (pre-push gate enabled)."

verify-pre-push: ## Run the versioned pre-push gate without pushing
	@printf '' | .githooks/pre-push

act-ci: ## Run fast CI jobs locally via act (ACT_FULL=1 for all jobs)
	@ACT_FLAG=""; if [ "$$ACT_FULL" = "1" ]; then ACT_FLAG="--full"; fi; \
		./tools/act-ci.sh $$ACT_FLAG

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
