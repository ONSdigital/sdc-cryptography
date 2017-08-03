from jwcrypto import jwk
from structlog import get_logger

from sdc.crypto.invalid_token_exception import InvalidTokenException

logger = get_logger()


def validate_required_keys(secrets, key_purpose):

    def has_purpose_and_type(kid, key_type):
        key = secrets['keys'][kid]
        return key['purpose'] == key_purpose and key['type'] == key_type

    public_keys = [kid for kid in secrets['keys'] if has_purpose_and_type(kid, "public")]

    private_keys = [kid for kid in secrets['keys'] if has_purpose_and_type(kid, "private")]

    if len(private_keys) > 1:
        raise Exception("Multiple private keys loaded for the purpose {}".format(key_purpose))

    if len(public_keys) > 1:
        raise Exception("Multiple public keys loaded for the purpose {}".format(key_purpose))

    if not public_keys:
        raise Exception("No public key loaded for purpose {}".format(key_purpose))

    if not private_keys:
        Exception("No private key loaded for purpose {}".format(key_purpose))


class Key:
    def __init__(self, kid, purpose, key_type, value):
        self.kid = kid
        self.purpose = purpose
        self.key_type = key_type
        self.value = value

    def as_jwk(self):
        return jwk.JWK.from_pem(self.value.encode('utf-8'))


class KeyStore:
    def __init__(self, secrets):
        try:
            self.keys = {kid: Key(kid, key['purpose'], key['type'], key['value']) for kid, key in secrets['keys'].items()}
        except KeyError as e:
            logger.warning("Missing mandatory key values", error=str(e))
            raise Exception(e)

    def get_private_key_by_kid(self, purpose, kid):
        return self.get_key_by_kid(purpose, kid, "private")

    def get_public_key_by_kid(self, purpose, kid):
        return self.get_key_by_kid(purpose, kid, "public")

    def get_key_by_kid(self, purpose, kid, key_type):
        try:
            key = self.keys[kid]
            if key.purpose != purpose or key.key_type != key_type:
                raise InvalidTokenException
        except(KeyError, InvalidTokenException):
            raise InvalidTokenException("Invalid {} Key Identifier [{}] for Purpose [{}]".format(key_type, kid, purpose))
        else:
            return key

    def get_key_for_purpose_and_type(self, purpose, key_type):
        key = [key for key in self.keys.values() if key.purpose == purpose and key.key_type == key_type]
        try:
            return key[0]
        except IndexError:
            return None
