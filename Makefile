.PHONY: setup dev test check clippy fmt clean ci bench help

# Default target
all: setup

## Help
help:
	@echo "navia-didcomm Development Commands:"
	@echo "  make setup       - Initial setup (install hooks, check tools)"
	@echo "  make dev         - Start development (setup + check)"
	@echo "  make check       - Check compilation"
	@echo "  make test        - Run all tests"
	@echo "  make clippy      - Run clippy lints"
	@echo "  make fmt         - Format all code"
	@echo "  make bench       - Run benchmarks"
	@echo "  make clean       - Clean build artifacts"
	@echo "  make ci          - Run CI checks (test + clippy)"

## Initial setup for new developers
setup:
	@echo "🚀 Setting up navia-didcomm development environment..."
	@cargo check --all-features
	@rusty-hook init
	@echo "✅ Setup complete! Git hooks installed."

## Start development
dev: setup
	@cargo check --all-features

## Check compilation
check:
	@echo "🔍 Checking compilation..."
	@cargo check --all-features

## Run tests
test:
	@echo "🧪 Running tests..."
	@cargo test --lib --all-features
	@cargo test --test integration_tests --all-features
	@cargo test --test error_diagnostics_tests --all-features
	@cargo test --doc --all-features

## Run clippy
clippy:
	@echo "📎 Running clippy..."
	@cargo clippy --all-features -- -D warnings

## Format code
fmt:
	@echo "🎨 Formatting code..."
	@cargo fmt --all

## Run benchmarks
bench:
	@echo "⚡ Running benchmarks..."
	@cargo bench

## Clean build artifacts
clean:
	@echo "🧹 Cleaning..."
	@cargo clean

## Run CI checks
ci: test clippy
	@echo "✅ All CI checks passed!"