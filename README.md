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
to store the file.  Then it needs to be loaded, and a secret store generated.
```python
from sdc.crypto.utils.generate_secrets import generate_secrets_file


# Generate secrets file
keys = {}
secrets = {}
generate_secrets_file(keys, secrets)

# Load generated secret file and create secret store
import yaml
EXPECTED_SECRETS = []
key_purpose = 'key_purpose'

with open('secrets.yml') as file:
  secrets_from_file = yaml.safe_load(file)

validate_required_secrets(secrets_from_file, EXPECTED_SECRETS, key_purpose)
secret_store = SecretStore(secrets_from_file)
```

After this has been configured, encrypting and decrypting can be done like in the
example below.
```python
# Encrypt json
from sdc.crypto.encrypter import encrypt
encrypted_json = encrypt(json, secret_store, key_purpose)

# Decrypt UTF8 jwe token
from sdc.crypto.decrypter import decrypt
data_bytes = data.decode('UTF8')
decrypted_json = decrypt(data_bytes, secret_store, key_purpose)

```
