SHELL := /usr/bin/env bash
CACHE_DIR ?= $(HOME)/.cache/beam
LAB_DIR ?= /home/demir/pi/beam-lab
LAB_PROFILE ?= clean

.PHONY: help doctor check fmt clippy test build verify smoke lab-check acceptance fuzz-smoke bench-cache

help:
	@printf '%s\n' \
	  'make doctor      report required and optional local tools' \
	  'make check       fmt + clippy + test' \
	  'make verify      alias for check' \
	  'make smoke       release build, config check, shell syntax' \
	  'make lab-check   start external lab, run checks, stop (LAB_PROFILE=clean|loss)' \
	  'make acceptance  verify + smoke + lab-check' \
	  'make fuzz-smoke  short fuzz run with corpus cache' \
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
	for path in config.example.toml README.md "$(LAB_DIR)/start-lab.sh"; do \
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

lab-check:
	LAB_DIR="$(LAB_DIR)" LAB_PROFILE="$(LAB_PROFILE)" bash scripts/lab-check.sh

acceptance: verify smoke lab-check

fuzz-smoke:
	BEAM_FUZZ_CACHE="$(CACHE_DIR)/fuzz-corpus" bash scripts/fuzz-smoke.sh

bench-cache:
	bash bench/run.sh --out "$(CACHE_DIR)/bench-results/$$(date -u +%Y%m%dT%H%M%SZ)"
