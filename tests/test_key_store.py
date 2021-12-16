import pytest
from sdc.crypto.exceptions import CryptoError, InvalidTokenException
from sdc.crypto.key_store import KeyStore, validate_required_keys
from tests import TEST_DO_NOT_USE_SR_PRIVATE_PEM
from tests import get_mock_key_store, TEST_DO_NOT_USE_PUBLIC_KEY

KEY_PURPOSE_AUTHENTICATION = "authentication"
KEY_PURPOSE_SUBMISSION = "submission"


class TestKeyStore:

    key_store = get_mock_key_store(KEY_PURPOSE_AUTHENTICATION)

    def test_get_key_by_kid_with_incorrect_type(self):
        with pytest.raises(InvalidTokenException):
            self.key_store.get_key_by_kid(KEY_PURPOSE_AUTHENTICATION, "e19091072f920cbf3ca9f436ceba309e7d814a62", "public")

    def test_get_key_by_kid_with_incorrect_purpose(self):
        with pytest.raises(InvalidTokenException):
            self.key_store.get_key_by_kid(KEY_PURPOSE_SUBMISSION, "e19091072f920cbf3ca9f436ceba309e7d814a62", "private")

    def test_get_key_with_purpose_and_type_no_service(self):
        """
        Test that we get a key if there is one in the store that matches the criteria
        Note that if there are many, you'll get a random one.
        """
        result = self.key_store.get_key(purpose=KEY_PURPOSE_AUTHENTICATION, key_type="private")
        assert result.kid in ["e19091072f920cbf3ca9f436ceba309e7d814a62", "EQ_USER_AUTHENTICATION_SR_PRIVATE_KEY"]
        assert result.purpose == KEY_PURPOSE_AUTHENTICATION
        assert result.key_type == "private"
        assert result.value == TEST_DO_NOT_USE_SR_PRIVATE_PEM

    def test_get_key_with_purpose_type_and_service(self):
        """
        Test that we get a key if there is one in the store that matches the criteria
        Note that if there are many, you'll get a random one.
        """
        result = self.key_store.get_key(purpose=KEY_PURPOSE_AUTHENTICATION, key_type="public", service="eq_v2")
        assert result.kid == "KID_FOR_EQ_V2"
        assert result.purpose == KEY_PURPOSE_AUTHENTICATION
        assert result.key_type == "public"
        assert result.value == TEST_DO_NOT_USE_PUBLIC_KEY

    @pytest.mark.parametrize(
        "service",
        ["eq_v3", None],
    )
    def test_get_key_not_found(self, service):
        """Test that None is returned if no keys in the store matches the criteria"""
        result = self.key_store.get_key(
            purpose=KEY_PURPOSE_SUBMISSION, key_type="private", service=service
        )
        assert result is None

    @staticmethod
    def test_incomplete_key():
        """Tests that an exception is thrown a malformed key is created with the keystore"""
        with pytest.raises(CryptoError):
            KeyStore({
                "keys": {
                    "e19091072f920cbf3ca9f436ceba309e7d814a62": {'purpose': KEY_PURPOSE_AUTHENTICATION,
                                                                 'value': TEST_DO_NOT_USE_SR_PRIVATE_PEM},
                }
            })

    @staticmethod
    def test_validate_required_keys_missing_public_keys_for_purpose():
        """Tests exeception is raised if there are no public keys with 'authentication' purpose"""
        with pytest.raises(CryptoError):
            keystore_dict = {
                "keys": {
                    "insert_kid_here": {'purpose': KEY_PURPOSE_AUTHENTICATION,
                                        'type': 'private',
                                        'value': TEST_DO_NOT_USE_SR_PRIVATE_PEM},
                }
            }
            validate_required_keys(keystore_dict, KEY_PURPOSE_AUTHENTICATION)

    @staticmethod
    def test_validate_required_keys_missing_private_keys_for_purpose():
        """Tests exeception is raised if there are no private keys with 'authentication' purpose"""
        with pytest.raises(CryptoError):
            keystore_dict = {
                "keys": {
                    "insert_kid_here": {'purpose': KEY_PURPOSE_AUTHENTICATION,
                                        'type': 'public',
                                        'value': TEST_DO_NOT_USE_SR_PRIVATE_PEM},
                }
            }
            validate_required_keys(keystore_dict, KEY_PURPOSE_AUTHENTICATION)
