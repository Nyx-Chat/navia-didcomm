.PHONY: test check clippy fmt clean help

# Default target
all: check

## Help
help:
	@echo "navia-didcomm Development Commands:"
	@echo "  make check       - Check compilation"
	@echo "  make test        - Run all tests"
	@echo "  make clippy      - Run clippy lints"
	@echo "  make fmt         - Format all code"
	@echo "  make clean       - Clean build artifacts"
	@echo "  make ci          - Run CI checks (test + clippy)"

## Check compilation
check:
	@echo "🔍 Checking compilation..."
	@cargo check --all-features

## Run tests
test:
	@echo "🧪 Running tests..."
	@cargo test --lib

## Run clippy
clippy:
	@echo "📎 Running clippy..."
	@cargo clippy --lib -- -D warnings

## Format code
fmt:
	@echo "🎨 Formatting code..."
	@cargo fmt --all

## Clean build artifacts
clean:
	@echo "🧹 Cleaning..."
	@cargo clean

## Run CI checks
ci: test clippy
	@echo "✅ All CI checks passed!"