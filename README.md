# sdc-cryptography
A common source code library for SDC services that use JWE. Apps wishing to use this should add the sdc_cryptography
dependency to their requirements.txt and install with pip.

### Basic Use

Assuming you are executing from inside an activated virtual environment:

###### Install requirements:

    $ make build

###### Run the unit tests:

    $ make test

###### Create a package for deployment:

    $ make sdist

## Usage

Need to generate a secrets.yml file first.  Note, this requires a file system
to store the file.  Then it needs to be loaded, and a key store generated.
```

python sdc/crypto/scripts/generate_secrets.py <key_folder_location>

```

After this has been configured, encrypting and decrypting can be done like in the
example below.
```python

secrets_from_file = yaml.safe_load("secrets.yml")

validate_required_secrets(secrets_from_file, EXPECTED_SECRETS, KEY_PURPOSE_SUBMISSION)

key_store= KeyStore(secrets_from_file)

# Encrypt json
from sdc.crypto.encrypter import encrypt
encrypted_json = encrypt(json, key_store, key_purpose)

# Decrypt UTF8 jwe token
from sdc.crypto.decrypter import decrypt
data_bytes = data.decode('UTF8')
decrypted_json = decrypt(data_bytes, key_store, key_purpose)

```
