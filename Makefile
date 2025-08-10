PY?=python3.11

.PHONY: setup lint test run-api report publish-pages

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

publish-pages:
	mkdir -p docs
	cp out/example.html docs/index.html
	@echo "Copied out/example.html to docs/index.html. Commit and push, then enable GitHub Pages (Settings → Pages → Deploy from 'main' / '/docs')."

