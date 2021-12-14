import json

from sdc.crypto.encrypter import encrypt
from tests import get_mock_key_store

KEY_PURPOSE_AUTHENTICATION = "authentication"


class TestEncrypter:

    key_store = get_mock_key_store(KEY_PURPOSE_AUTHENTICATION)

    def test_encrypt(self):
        """
        This is to validate encrypt is able to run without any issues.
        The tokens is different on each run, hence not asserted.
        """
        assert encrypt(json.dumps({"test": "test"}), self.key_store, KEY_PURPOSE_AUTHENTICATION)
