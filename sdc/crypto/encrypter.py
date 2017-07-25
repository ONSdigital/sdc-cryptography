from sdc.crypto.token_helper import encode_jwt, encrypt_jwe


def encrypt(json, secret_store, key_purpose):

    jwt_key = secret_store.get_key_for_purpose_and_type(key_purpose, "private")

    payload = encode_jwt(json, jwt_key.kid, secret_store, key_purpose)

    jwe_key = secret_store.get_key_for_purpose_and_type(key_purpose, "public")

    return encrypt_jwe(payload, jwe_key.kid, secret_store, key_purpose)
