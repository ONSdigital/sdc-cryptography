from sdc.crypto.jwe_helper import JWEHelper
from sdc.crypto.jwt_helper import JWTHelper


def encrypt(json, key_store, key_purpose, encryption_for_service=None):
    """This encrypts the supplied json and returns a jwe token.

    :param str json: The json to be encrypted.
    :param key_store: The key store.
    :param str key_purpose: Context for the key.
    :param Optional[str] encryption_for_service: The name of the downstream service the JWT is being encrypted for
    :return: A jwe token.

    """
    jwt_key = key_store.get_key(purpose=key_purpose, key_type="private")

    payload = JWTHelper.encode(json, jwt_key.kid, key_store, key_purpose)

    jwe_key = key_store.get_key(purpose=key_purpose, key_type="public", service=encryption_for_service)

    return JWEHelper.encrypt(payload, jwe_key.kid, key_store, key_purpose)
