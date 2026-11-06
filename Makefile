SHELL := /usr/bin/env bash
CACHE_DIR ?= $(HOME)/.cache/beam
LAB_DIR ?= /home/demir/pi/beam-lab
LAB_PROFILE ?= clean

.PHONY: help check fmt clippy test build verify smoke lab-check acceptance fuzz-smoke bench-cache

help:
	@printf '%s\n' \
	  'make check       fmt + clippy + test' \
	  'make verify      alias for check' \
	  'make smoke       release build, config check, shell syntax' \
	  'make lab-check   start external lab, run checks, stop (LAB_PROFILE=clean|loss)' \
	  'make acceptance  verify + smoke + lab-check' \
	  'make fuzz-smoke  short fuzz run with corpus cache' \
	  'make bench-cache benchmark into ~/.cache/beam/bench-results'

check: fmt clippy test

verify: check

fmt:
	cargo fmt --all --check

clippy:
	cargo clippy --workspace --all-targets -- -D warnings

test:
	cargo test --workspace

build:
	cargo build --release

smoke: build
	target/release/beam --check -c config.example.toml
	@for script in deploy/bootstrap.sh deploy/package.sh deploy/verify-production.sh scripts/lab-check.sh scripts/fuzz-smoke.sh; do \
	  bash -n "$$script" || exit 1; \
	done

lab-check:
	LAB_DIR="$(LAB_DIR)" LAB_PROFILE="$(LAB_PROFILE)" bash scripts/lab-check.sh

acceptance: verify smoke lab-check

fuzz-smoke:
	BEAM_FUZZ_CACHE="$(CACHE_DIR)/fuzz-corpus" bash scripts/fuzz-smoke.sh

bench-cache:
	bash bench/run.sh --out "$(CACHE_DIR)/bench-results/$$(date -u +%Y%m%dT%H%M%SZ)"
