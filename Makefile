PY?=python3.11

.PHONY: setup lint test run-api report

setup:
	$(PY) -m venv .venv
	. .venv/bin/activate && $(PY) -m pip install -U pip && pip install -e . -r requirements-dev.txt

lint:
	ruff check .
	black --check .

test:
	$(PY) -m pytest -q

run-api:
	uvicorn sentinelscope.api:app --host 0.0.0.0 --port 8000

report:
	sscan domain example.com --json out/example.json --html out/example.html

