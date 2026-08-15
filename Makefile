.PHONY: help install test test-unit test-integration test-e2e test-security test-evals test-performance test-all coverage lint format type-check clean docker-build docker-run

# Default target
help: ## Show this help message
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

# ============================================================
# Installation
# ============================================================

install: ## Install all dependencies
	python -m venv .venv
	.venv/bin/pip install -r backend/requirements.txt -r requirements-dev.txt
	cd frontend && npm ci

install-dev: ## Install development dependencies
	pip install -r backend/requirements.txt
	pip install pytest pytest-cov pytest-asyncio pytest-benchmark hypothesis
	pip install ruff mypy bandit safety
	pip install vcrpy deepeval playwright

# ============================================================
# Testing
# ============================================================

test: test-unit ## Run unit tests (default)

test-unit: ## Run unit tests
	@echo "Running unit tests..."
	python -m pytest tests/unit/ \
		-v \
		--tb=short \
		--cov=backend --cov=argus_engine \
		--cov-report=term-missing \
		-x

test-integration: ## Run integration tests
	@echo "Running integration tests..."
	python -m pytest tests/integration/ \
		-v \
		--tb=short \
		--cov=backend --cov=argus_engine \
		--cov-report=term-missing \
		-x

test-e2e: ## Run E2E tests
	@echo "Running E2E tests..."
	python -m pytest tests/e2e/ \
		-v \
		--tb=short \
		-x

test-security: ## Run security tests
	@echo "Running security tests..."
	python -m pytest tests/security/ \
		-v \
		--tb=short \
		-x

test-evals: ## Run LLM evaluation tests
	@echo "Running LLM evals..."
	python -m pytest tests/evals/ \
		-v \
		--tb=short \
		-x

test-performance: ## Run performance tests
	@echo "Running performance tests..."
	python -m pytest tests/performance/ \
		-v \
		--tb=short \
		-x

test-all: ## Run all tests
	@echo "Running all tests..."
	python -m pytest tests/ \
		-v \
		--tb=short \
		--cov=backend --cov=argus_engine \
		--cov-report=term-missing \
		--cov-report=html:htmlcov \
		--cov-fail-under=16

test-fast: ## Run tests quickly (skip slow tests)
	@echo "Running fast tests..."
	python -m pytest tests/unit/ tests/security/ \
		-v \
		--tb=short \
		-x \
		-m "not slow"

# ============================================================
# Coverage
# ============================================================

coverage: ## Generate coverage report
	@echo "Generating coverage report..."
	python -m pytest tests/unit/ tests/integration/ \
		--cov=backend --cov=argus_engine \
		--cov-report=xml:coverage.xml \
		--cov-report=html:htmlcov \
		--cov-report=term-missing \
		--cov-fail-under=16

coverage-html: ## Generate HTML coverage report
	@echo "Generating HTML coverage report..."
	python -m pytest tests/unit/ tests/integration/ \
		--cov=backend --cov=argus_engine \
		--cov-report=html:htmlcov
	@echo "Coverage report: htmlcov/index.html"

coverage-view: coverage-html ## Generate and view coverage report
	python -m http.server 8080 --directory htmlcov &

# ============================================================
# Linting & Formatting
# ============================================================

lint: ## Run linter (ruff)
	@echo "Running Ruff linter..."
	ruff check --select E9,F63,F7,F82 backend/ argus_engine/ tests/

lint-fix: ## Fix lint issues automatically
	@echo "Fixing lint issues..."
	ruff check --fix backend/ argus_engine/ tests/

format: ## Format code (ruff)
	@echo "Formatting code..."
	ruff format backend/ argus_engine/ tests/

format-check: ## Check code formatting
	@echo "Checking formatting..."
	ruff format --check backend/agents/people.py backend/features/research.py tests/unit/test_production_config.py tests/unit/test_investigation_ownership.py tests/unit/test_research_redaction.py tests/unit/test_people_native_packages.py

type-check: ## Run type checker (mypy)
	@echo "Running MyPy..."
	mypy backend/ argus_engine/ --ignore-missing-imports --no-error-summary
	cd frontend && npx tsc --noEmit

# ============================================================
# Security Scanning
# ============================================================

security-scan: ## Run security scans (Bandit + Safety)
	@echo "Running Bandit security scan..."
	bandit -r backend/ argus_engine/ -f json -o bandit-report.json -ll --exclude argus_engine/.venv || true
	@echo "Running Safety dependency scan..."
	safety check --json --output safety-report.json || true
	@echo "Security reports: bandit-report.json, safety-report.json"

bandit: ## Run Bandit security linter
	@echo "Running Bandit..."
	bandit -r backend/ argus_engine/ -f screen -ll --exclude argus_engine/.venv

safety: ## Run Safety dependency check
	@echo "Running Safety..."
	safety check

# ============================================================
# Combined Checks
# ============================================================

check: lint format-check type-check test-unit ## Run all checks

ci: lint type-check test-all security-scan ## Run full CI pipeline locally

# ============================================================
# Docker
# ============================================================

docker-build: ## Build Docker image
	@echo "Building ARGUS stack..."
	docker compose build

docker-run: ## Run Docker container
	@echo "Starting ARGUS stack..."
	docker compose up -d

docker-test: ## Run tests in Docker
	@echo "Running tests in Docker..."
	docker compose run --rm backend python -m pytest -q

# ============================================================
# Cleanup
# ============================================================

clean: ## Clean generated files
	@echo "Cleaning up..."
	rm -rf __pycache__ .pytest_cache .mypy_cache
	rm -rf htmlcov coverage.xml coverage-*.xml
	rm -rf junit-*.xml bandit-report.json safety-report.json
	rm -rf .ruff_cache .omo/codegraph/cache
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true

clean-all: clean ## Clean everything including .venv
	rm -rf .venv
