lint:
	python -m isort scrapli_asyncssh/
	python -m isort tests/
	python -m black scrapli_asyncssh/
	python -m black tests/
	python -m pylama scrapli_asyncssh/
	python -m pydocstyle scrapli_asyncssh/
	python -m mypy scrapli_asyncssh/

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
