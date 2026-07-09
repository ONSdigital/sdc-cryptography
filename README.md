# sdc-cryptography

[![codecov](https://codecov.io/gh/ONSdigital/sdc-cryptography/branch/master/graph/badge.svg)](https://codecov.io/gh/ONSdigital/sdc-cryptography)

A common source code library for SDC services that use JWE. Apps wishing to use this should add the sdc-cryptography dependency to their project.

## Usage

Before using the library, you need to generate a keys.yml file. The `key_folder_location` should contain the public and private keys that are required by the SDC service using the library. To generate the keys.yml run:

```bash
generate_keys.py <key_folder_location>
```

After this has been configured, encrypting and decrypting can be done as follows:

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

The package is published automatically to PyPi via a GitHub Action when a release tag is created in GitHub. The configuration for this is in the [.github/workflows/release.yaml](.github/workflows/release.yaml) file.

## Developing changes

This repository uses poetry. Ensure you have it installed.

To install the dependencies run:

```bash
make install
```

Run linting and the unit tests:

```bash
make test
```

Create a package for deployment:

```bash
make build
```
