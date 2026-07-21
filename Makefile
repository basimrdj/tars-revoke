.PHONY: setup lint test test-python test-python-offline test-web doctor demo demo-scripted demo-live \
	verify-core verify-strict bench crashbench qualify-release serve web-install \
	web-build build audit release-check clean-build

setup:
	$(MAKE) web-install web-build
	uv sync --frozen --extra dev

lint:
	.venv/bin/ruff check src tests tools
	.venv/bin/mypy src/tars_revoke

test: test-python test-web

test-python:
	.venv/bin/pytest

test-python-offline:
	env -u TARS_RUN_LIVE_CODEX .venv/bin/pytest -m 'not live'

test-web:
	cd web && npm test && npm run build

doctor:
	.venv/bin/tars-revoke doctor

demo: demo-live

demo-scripted:
	.venv/bin/tars-revoke demo --scenario external-schema-v2 --scripted

demo-live:
	.venv/bin/tars-revoke demo --scenario external-schema-v2 --live-codex

verify-core:
	@test -n "$(RECEIPT)" || (echo 'Set RECEIPT to the receipt.json path printed by the demo.' >&2; exit 2)
	.venv/bin/tars-revoke verify "$(RECEIPT)" --core

verify-strict:
	@test -n "$(RECEIPT)" || (echo 'Set RECEIPT to the receipt.json path printed by the live demo.' >&2; exit 2)
	.venv/bin/tars-revoke verify "$(RECEIPT)" --strict

bench:
	.venv/bin/tars-revoke bench --suite RevokeBench-20

crashbench:
	.venv/bin/tars-revoke bench --suite CrashBench-11

qualify-release:
	@test -n "$(WORKSPACE)" || (echo 'Set WORKSPACE to a new or empty qualification directory.' >&2; exit 2)
	python3 tools/qualify_release.py --source "$(CURDIR)" --workspace "$(WORKSPACE)"

serve:
	.venv/bin/tars-revoke serve

web-install:
	cd web && npm ci

web-build:
	cd web && npm run build

clean-build:
	rm -rf build dist

build: web-build clean-build
	.venv/bin/python -m build

release-check: build
	.venv/bin/python tools/check_release_archives.py

audit:
	.venv/bin/pip-audit
	cd web && npm audit --audit-level=high
