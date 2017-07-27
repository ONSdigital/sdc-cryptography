from sdc.crypto.invalid_token_exception import InvalidTokenException
from sdc.crypto.token_helper import decrypt_jwe, decode_jwt


def decrypt(token, secret_store, key_purpose, leeway=120):
    tokens = token.split('.')
    if len(tokens) != 5:
        raise InvalidTokenException("Incorrect number of tokens")

    decrypted_token = decrypt_jwe(token, secret_store, key_purpose)

    payload = decode_jwt(decrypted_token, secret_store, key_purpose, leeway)

    return payload
