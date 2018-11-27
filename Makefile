
.PHONY: build clean sdist test

build:
	pipenv install --dev

clean:
	rm -rf sdc/crypto/doc/html
	rm -v dist/sdc-cryptography-*.tar.gz

sdist:
	python setup.py sdist

test:
	flake8 .
	pytest -v --cov-report term-missing --cov sdc.crypto
