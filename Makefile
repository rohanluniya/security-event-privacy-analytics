.PHONY: setup pipeline replay serve test chaos bench lint typecheck licenses sbom verify-all clean

setup:
	uv sync --frozen --python 3.12.8

pipeline:
	uv run python -m services.secops_platform.cli run-pipeline --seed 42 --events 3000

replay:
	uv run python -m services.secops_platform.cli replay --seed 42

serve:
	uv run python -m services.secops_platform.cli serve --host 127.0.0.1 --port 8080

lint:
	uv run ruff check services ingestion processing models tests benchmarks scripts

typecheck:
	uv run mypy services ingestion processing models

test:
	uv run pytest -v

chaos:
	uv run pytest -v tests/chaos/test_chaos_drills.py

bench:
	uv run python benchmarks/run_benchmarks.py --profiles smoke local stress

licenses:
	uv run python scripts/check_licenses.py

sbom:
	uv run python scripts/generate_sbom.py

verify-all: lint typecheck licenses sbom test

clean:
	rm -rf .local_data .pytest_cache .mypy_cache .ruff_cache .hypothesis
