from sdc.crypto.jwe_helper import JWEHelper
from sdc.crypto.jwt_helper import JWTHelper


def encrypt(json, key_store, key_purpose):
    """This encrypts the supplied json and returns a jwe token.

    :param str json: The json to be encrypted.
    :param key_store: The key store.
    :param str key_purpose: Context for the key.
    :return: A jwe token.

    """
    jwt_key = key_store.get_key_for_purpose_and_type(key_purpose, "private")

    payload = JWTHelper.encode(json, jwt_key.kid, key_store, key_purpose)

    jwe_key = key_store.get_key_for_purpose_and_type(key_purpose, "public")

    return JWEHelper.encrypt(payload, jwe_key.kid, key_store, key_purpose)
