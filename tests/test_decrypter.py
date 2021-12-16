import pytest

from sdc.crypto.decrypter import decrypt
from sdc.crypto.exceptions import InvalidTokenException
from tests import TOO_FEW_TOKENS_JWE, VALID_JWE
from tests import get_mock_key_store

KEY_PURPOSE_AUTHENTICATION = "authentication"


class TestDecrypter:

    key_store = get_mock_key_store(KEY_PURPOSE_AUTHENTICATION)

    def test_decrypt(self):
        json = decrypt(VALID_JWE, self.key_store, KEY_PURPOSE_AUTHENTICATION)
        assert json == {'user': 'jimmy', 'iat': 1498137519.135479, 'exp': 1.0000000000014982e+21}

    def test_decrypt_too_few_tokens_in_jwe(self):
        """Tests an InvalidTokenException when the token isn't comprised of 5 parts, seperated by several '.' characters"""
        with pytest.raises(InvalidTokenException):
            decrypt(TOO_FEW_TOKENS_JWE, self.key_store, KEY_PURPOSE_AUTHENTICATION)
