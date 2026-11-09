SHELL := /usr/bin/env bash
CACHE_DIR ?= $(HOME)/.cache/beam

.PHONY: help doctor check fmt clippy test build verify smoke acceptance fuzz-smoke stress bench-cache

help:
	@printf '%s\n' \
	  'make doctor      report required and optional local tools' \
	  'make check       fmt + clippy + test' \
	  'make verify      alias for check' \
	  'make smoke       release build, config check, shell syntax' \
	  'make acceptance  verify + smoke' \
	  'make fuzz-smoke  short fuzz run with corpus cache' \
	  'make stress      loopback pre-auth and cover stability probes' \
	  'make bench-cache benchmark into ~/.cache/beam/bench-results'

doctor:
	@set +e; missing=0; \
	printf '%s\n' '=== required build tools ==='; \
	for tool in cargo rustc python3 curl unshare git; do \
	  if command -v "$$tool" >/dev/null 2>&1; then printf 'OK   %s\n' "$$tool"; \
	  else printf 'MISS %s\n' "$$tool"; missing=1; fi; \
	done; \
	printf '%s\n' '=== optional benchmark tools ==='; \
	for tool in sing-box xray iperf3 tc; do \
	  if command -v "$$tool" >/dev/null 2>&1; then printf 'OK   %s\n' "$$tool"; \
	  else printf 'MISS %s (bench only)\n' "$$tool"; fi; \
	done; \
	printf '%s\n' '=== local paths ==='; \
	for path in config.example.toml README.md; do \
	  if [ -e "$$path" ]; then printf 'OK   %s\n' "$$path"; \
	  else printf 'MISS %s\n' "$$path"; fi; \
	done; \
	[ -f "$$HOME/.config/beam/beam.toml" ] && printf '%s\n' 'OK   local beam secrets' || printf '%s\n' 'MISS local beam secrets'; \
	[ -x target/release/beam ] && printf '%s\n' 'OK   target/release/beam' || printf '%s\n' 'MISS target/release/beam (run make smoke)'; \
	exit "$$missing"

check: fmt clippy test

verify: check

fmt:
	cargo fmt --all --check

clippy:
	cargo clippy --workspace --all-targets -- -D warnings

test:
	cargo test --workspace

build:
	cargo build --locked --release

smoke: build
	target/release/beam --check -c config.example.toml
	@for script in $$(git ls-files '*.sh'); do \
	  bash -n "$$script" || exit 1; \
	done

acceptance: verify smoke

fuzz-smoke:
	BEAM_FUZZ_CACHE="$(CACHE_DIR)/fuzz-corpus" bash scripts/fuzz-smoke.sh

stress: build
	python3 tests/stress/loopback.py --beam target/release/beam \
	  --out "$(CACHE_DIR)/stress-results/$$(date -u +%Y%m%dT%H%M%SZ)"

bench-cache:
	bash bench/run.sh --out "$(CACHE_DIR)/bench-results/$$(date -u +%Y%m%dT%H%M%SZ)"
