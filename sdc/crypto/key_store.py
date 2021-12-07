import logging

from jwcrypto import jwk

from sdc.crypto.exceptions import InvalidTokenException, CryptoError

logger = logging.getLogger(__name__)


def validate_required_keys(keys, key_purpose):

    def has_purpose_and_type(kid, key_type):
        key = keys['keys'][kid]
        return key['purpose'] == key_purpose and key['type'] == key_type

    public_keys = [kid for kid in keys['keys'] if has_purpose_and_type(kid, "public")]

    private_keys = [kid for kid in keys['keys'] if has_purpose_and_type(kid, "private")]

    if not public_keys:
        raise CryptoError("No public key loaded for purpose {}".format(key_purpose))

    if not private_keys:
        raise CryptoError("No private key loaded for purpose {}".format(key_purpose))


class Key:
    def __init__(self, kid, purpose, key_type, value, service):
        self.kid = kid
        self.purpose = purpose
        self.key_type = key_type
        self.value = value
        self.service = service

    def as_jwk(self):
        return jwk.JWK.from_pem(self.value.encode('utf-8'))


class KeyStore:
    def __init__(self, keys):
        try:
            self.keys = {kid: Key(kid, key['purpose'], key['type'], key['value'], key['service']) for kid, key in keys['keys'].items()}
        except KeyError as e:
            logger.warning("Missing mandatory key values")
            raise CryptoError from e

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
        """
        Gets a list of keys that match the purpose and key_type, and returns the first key in that list
        Note, if there are many keys that match the criteria, the one you get back will be random from that list
        :returns: A key object that matches the criteria
        """
        key = [key for key in self.keys.values() if key.purpose == purpose and key.key_type == key_type]
        try:
            return key[0]
        except IndexError:
            return None

    def get_key_for_purpose_type_and_service(self, purpose, key_type, service):
        """
        Gets a list of keys that match the purpose, key_type and service, and returns the first key in that list
        Note, if there are many keys that match the criteria, the one you get back will be random from that list
        :returns: A key object that matches the criteria
        """
        key = [key for key in self.keys.values() if key.purpose == purpose and key.key_type == key_type and key.service == service]
        try:
            return key[0]
        except IndexError:
            return None
