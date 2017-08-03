from sdc.crypto.invalid_token_exception import InvalidTokenException
from sdc.crypto.token_helper import decrypt_jwe, decode_jwt


def decrypt(token, key_store, key_purpose, leeway=120):
    """This decrypts the provided jwe token and the resulting jwt token and returns
    the payload.

    :param str token: The jwe token.
    :param key_store: The secret store.
    :param str key_purpose: Context for the key.
    :param int leeway: Extra allowed time after expiration to account for clock skew.
    :return: The decrypted payload.

    """
    tokens = token.split('.')
    if len(tokens) != 5:
        raise InvalidTokenException("Incorrect number of tokens")

    decrypted_token = decrypt_jwe(token, key_store, key_purpose)

    payload = decode_jwt(decrypted_token, key_store, key_purpose, leeway)

    return payload
