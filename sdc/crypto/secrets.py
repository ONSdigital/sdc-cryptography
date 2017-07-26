from jwcrypto import jwk

from sdc.crypto.invalid_token_exception import InvalidTokenException


def validate_required_secrets(secrets, expected_secrets=[], key_purpose="submission"):
    for required_secret in expected_secrets:
        if required_secret not in secrets['secrets']:
            raise Exception("Missing Secret [{}]".format(required_secret))

    validate_required_keys(secrets, key_purpose)


def validate_required_keys(secrets, key_purpose):
    found_public = False
    found_private = False

    for kid in secrets['keys']:
        key = secrets['keys'][kid]
        if key['purpose'] == key_purpose:
            if key['type'] == 'public':
                if found_public:
                    raise Exception("Multiple public keys loaded for the same purpose")
                else:
                    found_public = True

            if key['type'] == 'private':
                if found_private:
                    raise Exception("Multiple private keys loaded for the same purpose")
                else:
                    found_private = True

    if not found_public:
        raise Exception("No public key loaded")

    if not found_private:
        raise Exception("No private key loaded")


class Key:
    def __init__(self, kid, purpose, key_type, value):
        self.kid = kid
        self.purpose = purpose
        self.key_type = key_type
        self.value = value

    def as_jwk(self):
        return jwk.JWK.from_pem(self.value.encode('utf-8'))


class SecretStore:
    def __init__(self, secrets):
        self.secrets = secrets.get('secrets')
        if 'keys' in secrets:
            self.keys = {}
            for _, kid in enumerate(secrets['keys']):
                key = secrets['keys'][kid]
                key_object = Key(kid, key['purpose'], key['type'], key['value'])
                self.keys[kid] = key_object

    def get_secret_by_name(self, secret_name):
        return self.secrets.get(secret_name)

    def get_private_key_by_kid(self, purpose, kid):
        if kid in self.keys:
            key = self.keys[kid]
            if key.purpose == purpose and key.key_type == 'private':
                return key

        raise InvalidTokenException("Invalid Private Key Identifier [{}] for Purpose [{}]".format(kid, purpose))

    def get_public_key_by_kid(self, purpose, kid):
        if kid in self.keys:
            key = self.keys[kid]
            if key.purpose == purpose and key.key_type == 'public':
                return key

        raise InvalidTokenException("Invalid Public Key Identifier [{}] for Purpose [{}]".format(kid, purpose))

    def get_key_for_purpose_and_type(self, purpose, key_type):
        for _, kid in enumerate(self.keys):
            key = self.keys[kid]
            if key.purpose == purpose and key.key_type == key_type:
                return key
