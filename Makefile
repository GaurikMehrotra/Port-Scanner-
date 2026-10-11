.PHONY: install check test lab-up lab-down
install:
	python3 -m venv .venv
	.venv/bin/python -m pip install -r requirements.lock -r requirements-eval.lock
	.venv/bin/python -m pip install --no-deps --no-build-isolation -e .
check:
	.venv/bin/ruff check src tests eval lab tools
	.venv/bin/ruff format --check src tests eval lab tools
	.venv/bin/mypy src tests eval lab tools
	.venv/bin/pytest -q
test:
	.venv/bin/pytest -q
lab-up:
	docker compose --parallel 2 -f lab/docker-compose.lab.yml --profile tools build
	docker compose -f lab/docker-compose.lab.yml up -d
lab-down:
	docker compose -f lab/docker-compose.lab.yml down
