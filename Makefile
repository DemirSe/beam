SHELL := /usr/bin/env bash
CACHE_DIR ?= $(HOME)/.cache/beam

.PHONY: help doctor check fmt clippy test test-scripts build verify smoke acceptance fuzz-smoke stress soak bench-cache

help:
	@printf '%s\n' \
	  'make doctor      report required and optional local tools' \
	  'make check       fmt + clippy + test' \
	  'make verify      alias for check' \
	  'make test-scripts rootless script suites: reports, deploy, release, client policy' \
	  'make smoke       release build, config check, shell syntax' \
	  'make acceptance  verify + smoke' \
	  'make fuzz-smoke  short fuzz run with corpus cache' \
	  'make stress      loopback pre-auth and cover stability probes' \
	  'make soak        five-hour local data-path soak (SOAK_SECONDS to override)' \
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
	found=0; for f in "$$HOME"/.config/beam*/beam.toml "$$HOME"/.config/beam*/linux.json; do \
	  [ -f "$$f" ] && { printf 'OK   local profile %s\n' "$$f"; found=1; break; }; done; \
	[ "$$found" = 1 ] || printf '%s\n' 'MISS local profile (server toml or client json)'; \
	[ -x target/release/beam ] && printf '%s\n' 'OK   target/release/beam' || printf '%s\n' 'MISS target/release/beam (run make smoke)'; \
	exit "$$missing"

check: fmt clippy test

verify: check

fmt:
	cargo fmt --all --check

clippy:
	cargo clippy --workspace --all-targets -- -D warnings

test: test-scripts
	cargo test --workspace

# Rootless script suites. The dev-audit and release workflows run this same
# target, so the Makefile stays the one list of required checks.
test-scripts:
	python3 tests/bench/test_report.py
	python3 tests/bench/test_workflow_budget.py
	python3 tests/tun/test_protocol_report.py
	python3 tests/preprod/test_preprod_gate.py
	python3 tests/test_ipv4_only.py
	python3 tests/deploy/test_deploy_contracts.py
	python3 tests/deploy/test_restart_policy.py
	python3 tests/deploy/test_liveness_check.py
	python3 tests/release/test_release_artifact.py
	bash tests/deploy/test_alma_install.sh
	bash tests/deploy/test_beam_install.sh
	bash tests/linux-tray/test_dns_state.sh

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

soak: build
	XRAY_BIN="$${XRAY_BIN:-xray}" python3 bench/soak.py

bench-cache:
	bash bench/run.sh --out "$(CACHE_DIR)/bench-results/$$(date -u +%Y%m%dT%H%M%SZ)"
