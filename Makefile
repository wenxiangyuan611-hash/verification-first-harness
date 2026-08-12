.PHONY: install lint typecheck test build check demo

install:
	python -m pip install -e ".[dev]"

lint:
	ruff check .

typecheck:
	mypy src

test:
	pytest

build:
	python -m build

check: lint typecheck test build

demo:
	python -m verification_harness.main
