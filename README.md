# sdc-cryptography

[![Build Status](https://travis-ci.org/ONSdigital/sdc-cryptography.svg?branch=master)](https://travis-ci.org/ONSdigital/sdc-cryptography)
[![Codacy Badge](https://api.codacy.com/project/badge/Grade/b7b2eb54a248411086ddffb66097e578)](https://www.codacy.com/app/ONS/sdc-cryptography?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=ONSdigital/sdc-cryptography&amp;utm_campaign=Badge_Grade)
[![codecov](https://codecov.io/gh/ONSdigital/sdc-cryptography/branch/master/graph/badge.svg)](https://codecov.io/gh/ONSdigital/sdc-cryptography)
A common source code library for SDC services that use JWE. Apps wishing to use this should add the sdc_cryptography
dependency to their requirements.txt and install with pip.

## Basic Use (with pipenv, recommended)

### Install requirements

```bash
pip install pipenv
make build
```

### Run the unit tests

```bash
pipenv run make test
```

### Create a package for deployment

```bash
pipenv run make sdist
```

## Basic Use (with activated virtual environment)

### Install requirements

These commands will generate a requirements file that pip can use.  It doesn't have to be created this way but this is the easiest way.

```bash
pip install pipenv
pipenv lock -r --dev > requirements.txt
pip install -r requirements.txt
```

### Run the unit tests

```bash
make test
```

### Create a package for deployment

```bash
make sdist
```

## Usage

Need to generate a keys.yml file first.  Note, this requires a file system
to store the file.  Then it needs to be loaded, and a key store generated.

```bash
generate_keys.py <key_folder_location>
```

After this has been configured, encrypting and decrypting can be done as in the
example below.

```python
secrets_from_file = yaml.safe_load("keys.yml")

validate_required_secrets(secrets_from_file, EXPECTED_SECRETS, KEY_PURPOSE_SUBMISSION)

key_store = KeyStore(secrets_from_file)

# Encrypt JSON (Purpose has a single encryption key in the key store)
from sdc.crypto.encrypter import encrypt
encrypted_json = encrypt(json, key_store, key_purpose)

# Encrypt JSON with encryption service (Purpose has multiple encryption keys in the key store each tagged with a service)
from sdc.crypto.encrypter import encrypt
encrypted_json = encrypt(json, key_store, key_purpose, encryption_for_service="some-service")

# Decrypt UTF8 jwe token
from sdc.crypto.decrypter import decrypt
data_bytes = data.decode('UTF8')
decrypted_json = decrypt(data_bytes, key_store, key_purpose)
```

## PyPi

This repo is available from PyPi at [sdc-cryptography](https://pypi.org/project/sdc-cryptography/)

The package is published automatically to PyPi when a tag is created in Github. The configuration for this is in the
.travis.yml file.
