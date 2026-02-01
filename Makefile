# Trojan Server Makefile

# Binary name (matches [[bin]] name in Cargo.toml)
BINARY := server
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")

# Build directories
TARGET_DIR := target
RELEASE_DIR := $(TARGET_DIR)/release
DEBUG_DIR := $(TARGET_DIR)/debug

# Default target
.PHONY: all
all: build

# Development build (debug)
.PHONY: build
build:
	cargo build

# Release build (optimized)
.PHONY: release
release:
	cargo build --release

# Run tests
.PHONY: test
test:
	cargo test

# Run tests with output
.PHONY: test-verbose
test-verbose:
	cargo test -- --nocapture

# Run a specific test
.PHONY: test-one
test-one:
	@if [ -z "$(TEST)" ]; then \
		echo "Usage: make test-one TEST=test_name"; \
		exit 1; \
	fi
	cargo test $(TEST) -- --nocapture

# Run clippy linter
.PHONY: clippy
clippy:
	cargo clippy -- -D warnings

# Run clippy with all targets
.PHONY: clippy-all
clippy-all:
	cargo clippy --all-targets -- -D warnings

# Format code
.PHONY: fmt
fmt:
	cargo fmt

# Check formatting without modifying
.PHONY: fmt-check
fmt-check:
	cargo fmt -- --check

# Full check (fmt + clippy + test)
.PHONY: check
check: fmt-check clippy test
	@echo "All checks passed!"

# Clean build artifacts
.PHONY: clean
clean:
	cargo clean

# Watch for changes and rebuild (requires cargo-watch)
.PHONY: watch
watch:
	cargo watch -x build

# Watch for changes and run tests (requires cargo-watch)
.PHONY: watch-test
watch-test:
	cargo watch -x test

# Generate documentation
.PHONY: doc
doc:
	cargo doc --no-deps --open

# Update dependencies
.PHONY: update
update:
	cargo update

# Show dependency tree
.PHONY: deps
deps:
	cargo tree

# Show outdated dependencies (requires cargo-outdated)
.PHONY: outdated
outdated:
	cargo outdated

# Build for Linux x86_64 (cross-compile)
.PHONY: linux
linux:
	cargo build --release --target x86_64-unknown-linux-gnu

# Build for Linux musl (static binary)
.PHONY: linux-musl
linux-musl:
	cargo build --release --target x86_64-unknown-linux-musl

# Build for Linux aarch64
.PHONY: linux-arm64
linux-arm64:
	cargo build --release --target aarch64-unknown-linux-gnu

# Run the server (debug mode)
.PHONY: run
run:
	cargo run -- $(ARGS)

# Run the server (release mode)
.PHONY: run-release
run-release:
	cargo run --release -- $(ARGS)

# Install to /usr/local/bin
.PHONY: install
install: release
	install -m 755 $(RELEASE_DIR)/$(BINARY) /usr/local/bin/

# Uninstall from /usr/local/bin
.PHONY: uninstall
uninstall:
	rm -f /usr/local/bin/$(BINARY)

# Show binary size
.PHONY: size
size: release
	@ls -lh $(RELEASE_DIR)/$(BINARY) | awk '{print $$5, $$9}'
	@if command -v strip >/dev/null 2>&1; then \
		cp $(RELEASE_DIR)/$(BINARY) $(RELEASE_DIR)/$(BINARY).stripped; \
		strip $(RELEASE_DIR)/$(BINARY).stripped; \
		echo "Stripped:"; \
		ls -lh $(RELEASE_DIR)/$(BINARY).stripped | awk '{print $$5, $$9}'; \
		rm $(RELEASE_DIR)/$(BINARY).stripped; \
	fi

# Run benchmarks (if any)
.PHONY: bench
bench:
	cargo bench

# Security audit (requires cargo-audit)
.PHONY: audit
audit:
	cargo audit

# Print version
.PHONY: version
version:
	@echo $(VERSION)

# Help
.PHONY: help
help:
	@echo "Trojan Server Makefile"
	@echo ""
	@echo "Usage: make [target]"
	@echo ""
	@echo "Build targets:"
	@echo "  build        - Debug build (default)"
	@echo "  release      - Release build (optimized)"
	@echo "  linux        - Cross-compile for Linux x86_64"
	@echo "  linux-musl   - Cross-compile for Linux musl (static)"
	@echo "  linux-arm64  - Cross-compile for Linux aarch64"
	@echo ""
	@echo "Test targets:"
	@echo "  test         - Run all tests"
	@echo "  test-verbose - Run tests with output"
	@echo "  test-one     - Run specific test (TEST=name)"
	@echo ""
	@echo "Quality targets:"
	@echo "  clippy       - Run clippy linter"
	@echo "  fmt          - Format code"
	@echo "  fmt-check    - Check formatting"
	@echo "  check        - Run all checks (fmt + clippy + test)"
	@echo "  audit        - Security audit"
	@echo ""
	@echo "Run targets:"
	@echo "  run          - Run debug build"
	@echo "  run-release  - Run release build"
	@echo "  watch        - Watch and rebuild on changes"
	@echo "  watch-test   - Watch and test on changes"
	@echo ""
	@echo "Other targets:"
	@echo "  clean        - Clean build artifacts"
	@echo "  doc          - Generate documentation"
	@echo "  deps         - Show dependency tree"
	@echo "  outdated     - Show outdated dependencies"
	@echo "  size         - Show binary size"
	@echo "  install      - Install to /usr/local/bin"
	@echo "  uninstall    - Uninstall from /usr/local/bin"
	@echo "  version      - Print version"
	@echo "  help         - Show this help"
