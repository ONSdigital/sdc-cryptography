
.PHONY: build clean sdist test

build:
	pip3 install -r requirements.txt

clean:
	rm -rf sdc/crypto/doc/html
	rm -v dist/sdc-cryptography-*.tar.gz

sdist:
	python setup.py sdist

test: build
	pip3 install -r test_requirements.txt
	flake8 .
	python -m unittest discover sdc
