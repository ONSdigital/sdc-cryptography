from sdc.crypto.exceptions import InvalidTokenException
from sdc.crypto.jwe_helper import JWEHelper
from sdc.crypto.jwt_helper import JWTHelper


def decrypt(token, key_store, key_purpose, leeway=120):
    """This decrypts the provided jwe token, then decodes resulting jwt token and returns
    the payload.

    :param str token: The jwe token.
    :param key_store: The key store.
    :param str key_purpose: Context for the key.
    :param int leeway: Extra allowed time in seconds after expiration to account for clock skew.
    :return: The decrypted payload.

    """
    tokens = token.split('.')
    if len(tokens) != 5:
        raise InvalidTokenException("Incorrect number of tokens")

    decrypted_token = JWEHelper.decrypt(token, key_store, key_purpose)

    payload = JWTHelper.decode(decrypted_token, key_store, key_purpose, leeway)

    return payload
