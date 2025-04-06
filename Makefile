.PHONY: setup install run dev prod clean test help generate-key export-key test-coverage test-security test-lint test-all

# Default target
help:
	@echo "Available commands:"
	@echo "  make setup        - Create necessary directories and .env file"
	@echo "  make install      - Install dependencies"
	@echo "  make dev          - Run development server on port 5001"
	@echo "  make run          - Alias for make dev"
	@echo "  make prod         - Run production server with gunicorn"
	@echo "  make clean        - Remove cache files and directories"
	@echo "  make test         - Run basic tests"
	@echo "  make test-coverage - Run tests with coverage reporting"
	@echo "  make test-security - Run security checks on dependencies"
	@echo "  make test-lint    - Run linting checks"
	@echo "  make test-all     - Run all tests and checks before deployment"
	@echo "  make generate-key - Generate a new SESSION_SECRET key"
	@echo "  make export-key   - Export session key to environment (emergency use)"

# Setup environment
setup:
	@echo "Creating necessary directories..."
	mkdir -p data/digests
	@if [ ! -f .env ]; then \
		echo "Creating .env file..."; \
		RANDOM_KEY=$$(openssl rand -hex 24); \
		cp .env.example .env 2>/dev/null || \
		echo "# Environment Variables\n\n# Google OAuth for Authentication\nGOOGLE_OAUTH_CLIENT_ID=\nGOOGLE_OAUTH_CLIENT_SECRET=\n\n# Session Security\nSESSION_SECRET=$$RANDOM_KEY\n\n# API Keys\nHUBSPOT_API_KEY=\nCHARGEBEE_API_KEY=\nCHARGEBEE_SITE=\nOPENAI_API_KEY=\nOOTI_API_KEY=" > .env; \
	fi
	@echo "Setup complete! Edit .env with your API keys."

# Install dependencies
install:
	@echo "Installing dependencies..."
	pip3 install -r requirements.txt

# Install development dependencies
install-dev:
	@echo "Installing development dependencies..."
	pip3 install -r requirements-dev.txt

# Run development server
dev:
	@echo "Starting development server on port 5001..."
	@if [ -f .env ]; then \
		echo "Loading environment variables from .env..."; \
		set -a; source .env; set +a; \
		python3 main.py; \
	else \
		echo "Warning: .env file not found. Run 'make setup' first or set environment variables manually."; \
		python3 main.py; \
	fi

# Alias for dev
run: dev

# Run production server with gunicorn
prod:
	@echo "Starting production server with gunicorn..."
	@if [ -f .env ]; then \
		echo "Loading environment variables from .env..."; \
		set -a; source .env; set +a; \
		gunicorn --bind 0.0.0.0:5001 --workers=4 app:app; \
	else \
		echo "Warning: .env file not found. Run 'make setup' first or set environment variables manually."; \
		gunicorn --bind 0.0.0.0:5001 --workers=4 app:app; \
	fi

# Clean cached files
clean:
	@echo "Cleaning cached files..."
	find . -type d -name "__pycache__" -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
	find . -type f -name "*.pyo" -delete
	find . -type d -name "*.egg-info" -exec rm -rf {} +
	find . -type d -name "*.egg" -exec rm -rf {} +
	find . -type d -name ".pytest_cache" -exec rm -rf {} +
	find . -type d -name ".coverage" -exec rm -rf {} +
	find . -type d -name "htmlcov" -exec rm -rf {} +
	find . -type d -name ".tox" -exec rm -rf {} +

# Run basic tests
test:
	@echo "Running basic tests..."
	pytest minimal_tests/

# Run tests with coverage
test-coverage:
	@echo "Running tests with coverage..."
	pytest -v --cov=app --cov-report=term --cov-report=html minimal_tests/
	@echo "Coverage report generated in htmlcov/ directory"
	@echo "Coverage summary:"
	coverage report -m

# Run security checks
test-security:
	@echo "Running security checks on dependencies..."
	@if command -v safety &> /dev/null; then \
		safety check -r requirements.txt; \
	else \
		echo "Safety not found. Installing..."; \
		pip install safety; \
		safety check -r requirements.txt; \
	fi
	@echo "Running Bandit security scanner..."
	@if command -v bandit &> /dev/null; then \
		bandit -r app/ -x app/tests; \
	else \
		echo "Bandit not found. Installing..."; \
		pip install bandit; \
		bandit -r app/ -x app/tests; \
	fi

# Run linting checks
test-lint:
	@echo "Running linting checks..."
	@if command -v flake8 &> /dev/null; then \
		flake8 app/ tests/ --count --select=E9,F63,F7,F82 --show-source --statistics; \
		flake8 app/ tests/ --count --exit-zero --max-complexity=10 --max-line-length=127 --statistics; \
	else \
		echo "Flake8 not found. Installing..."; \
		pip install flake8; \
		flake8 app/ tests/ --count --select=E9,F63,F7,F82 --show-source --statistics; \
		flake8 app/ tests/ --count --exit-zero --max-complexity=10 --max-line-length=127 --statistics; \
	fi

# Run all pre-deployment tests
test-all: install-dev
	@echo "========================================================"
	@echo "Running all pre-deployment tests for CEO Assistant AI"
	@echo "========================================================"
	
	# Set environment to testing
	export FLASK_ENV=testing
	export TESTING=True
	
	# Clean previous coverage reports
	@echo "Cleaning previous coverage data..."
	coverage erase
	
	# Run tests with coverage
	@echo "Running tests with coverage..."
	pytest -v minimal_tests/
	
	# Run linting checks
	@echo "Running linting checks..."
	flake8 minimal_tests/ --count --select=E9,F63,F7,F82 --show-source --statistics
	
	# Run security checks
	@echo "Running security checks..."
	$(MAKE) test-security || true
	
	@echo "========================================================"
	@echo "✅ All pre-deployment tests passed successfully!"
	@echo "The application is ready for deployment."
	@echo "========================================================="

# Generate new session key
generate-key:
	@echo "Generating new SESSION_SECRET..."
	@if [ -f .env ]; then \
		RANDOM_KEY=$$(openssl rand -hex 24); \
		sed -i.bak "s/SESSION_SECRET=.*/SESSION_SECRET=$$RANDOM_KEY/" .env && rm -f .env.bak || \
		sed "s/SESSION_SECRET=.*/SESSION_SECRET=$$RANDOM_KEY/" .env > .env.tmp && mv .env.tmp .env; \
		echo "New SESSION_SECRET has been set in .env file."; \
	else \
		echo "Error: .env file does not exist. Run 'make setup' first."; \
		exit 1; \
	fi

# Export session key directly to environment (for emergency use)
export-key:
	@echo "Generating and exporting a temporary SESSION_SECRET to environment..."
	$(eval export SESSION_SECRET=$(shell openssl rand -hex 24))
	@echo "SESSION_SECRET has been exported to the current shell."
	@echo "To run the server with this key, execute in the same shell:"
	@echo "  make run     # For development"
	@echo "  make prod    # For production"
	@echo "Note: This is temporary! Add the key to your .env file for persistence." 