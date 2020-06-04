lint:
	python -m isort -rc -y .
	python -m black .
	python -m pylama .
	python -m pydocstyle .
	python -m mypy scrapli_asyncssh/

lint_full:
	python -m isort -rc -y .
	python -m black .
	python -m pylama .
	python -m pydocstyle .
	python -m mypy -scrapli_asyncssh/
	find scrapli_asyncssh -type f \( -iname "*.py" ! -iname "ptyprocess.py" \) | xargs darglint -x

cov:
	python -m pytest \
	--cov=scrapli_asyncssh \
	--cov-report html \
	--cov-report term \
	tests/

cov_unit:
	python -m pytest \
	--cov=scrapli_asyncssh \
	--cov-report html \
	--cov-report term \
	tests/unit/

test:
	python -m pytest tests/

test_unit:
	python -m pytest tests/unit/

test_functional:
	python -m pytest tests/functional/
	python -m pytest examples/

.PHONY: docs
docs:
	rm -rf docs/scrapli_asyncssh
	python -m pdoc \
	--html \
	--output-dir docs \
	scrapli_asyncssh \
	--force
