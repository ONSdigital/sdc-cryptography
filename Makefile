
.PHONY: install build clean test

install:
	poetry install --with test

build:
	poetry build

clean:
	rm -rf sdc/crypto/doc/html
	rm -rf dist/sdc-cryptography-*.tar.gz
	rm -rf dist/sdc-cryptography-*.whl

test:
	poetry run flake8 .
	poetry run pytest -v --cov-report term-missing --cov sdc.crypto --cov-fail-under=87
