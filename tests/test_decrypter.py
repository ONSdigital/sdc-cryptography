import pytest

from sdc.crypto.decrypter import decrypt
from sdc.crypto.key_store import KeyStore
from sdc.crypto.exceptions import InvalidTokenException
from tests import TEST_DO_NOT_USE_UPSTREAM_PUBLIC_PEM, TEST_DO_NOT_USE_SR_PRIVATE_PEM
from tests import TOO_FEW_TOKENS_JWE, VALID_JWE


KEY_PURPOSE_AUTHENTICATION = "authentication"

# jwt.io public key signed
TEST_DO_NOT_USE_PUBLIC_KEY = """-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDdlatRjRjogo3Wojg
GHFHYLugdUWAY9iR3fy4arWNA1KoS8kVw33cJibXr8bvwUAUparCwlv
dbH6dvEOfou0/gCFQsHUfQrSDv+MuSUMAe8jzKE4qW+jK+xQU9a03GU
nKHkkle+Q0pX/g6jXZ7r1/xAK5Do2kQ+X5xK9cipRgEKwIDAQAB
-----END PUBLIC KEY-----"""


class TestDecrypter:

    key_store = KeyStore({
        "keys": {
            "e19091072f920cbf3ca9f436ceba309e7d814a62": {'purpose': KEY_PURPOSE_AUTHENTICATION,
                                                         'type': 'private',
                                                         'value': TEST_DO_NOT_USE_SR_PRIVATE_PEM},
            "EQ_USER_AUTHENTICATION_SR_PRIVATE_KEY": {'purpose': KEY_PURPOSE_AUTHENTICATION,
                                                      'type': 'private',
                                                      'value': TEST_DO_NOT_USE_SR_PRIVATE_PEM},
            "EDCRRM": {'purpose': KEY_PURPOSE_AUTHENTICATION,
                       'type': 'public',
                       'value': TEST_DO_NOT_USE_PUBLIC_KEY},
            "709eb42cfee5570058ce0711f730bfbb7d4c8ade": {'purpose': KEY_PURPOSE_AUTHENTICATION,
                                                         'type': 'public',
                                                         'value': TEST_DO_NOT_USE_UPSTREAM_PUBLIC_PEM},
        }
    })

    def test_decrypt(self):
        json = decrypt(VALID_JWE, self.key_store, KEY_PURPOSE_AUTHENTICATION)
        assert json == {'user': 'jimmy', 'iat': 1498137519.135479, 'exp': 1.0000000000014982e+21}

    def test_decrypt_too_few_tokens_in_jwe(self):
        """Tests an InvalidTokenException when the token isn't comprised of 5 parts, seperated by several '.' characters"""
        with pytest.raises(InvalidTokenException):
            decrypt(TOO_FEW_TOKENS_JWE, self.key_store, KEY_PURPOSE_AUTHENTICATION)
