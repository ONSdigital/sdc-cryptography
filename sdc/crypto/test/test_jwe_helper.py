import os
from unittest import TestCase

from sdc.crypto.exceptions import InvalidTokenException
from sdc.crypto.jwe_helper import JWEHelper
from sdc.crypto.key_store import KeyStore
from sdc.crypto.test import VALID_JWE, TEST_DO_NOT_USE_UPSTREAM_PUBLIC_PEM, TEST_DO_NOT_USE_SR_PRIVATE_PEM, \
    VALID_SIGNED_JWT, TEST_DO_NOT_USE_UPSTREAM_PRIVATE_KEY, TEST_DO_NOT_USE_SR_PUBLIC_KEY
from sdc.crypto.test.jwe_encrypter import Encoder

KEY_PURPOSE_AUTHENTICATION = "authentication"

# jwt.io public key signed
TEST_DO_NOT_USE_PUBLIC_KEY = """-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDdlatRjRjogo3Wojg
GHFHYLugdUWAY9iR3fy4arWNA1KoS8kVw33cJibXr8bvwUAUparCwlv
dbH6dvEOfou0/gCFQsHUfQrSDv+MuSUMAe8jzKE4qW+jK+xQU9a03GU
nKHkkle+Q0pX/g6jXZ7r1/xAK5Do2kQ+X5xK9cipRgEKwIDAQAB
-----END PUBLIC KEY-----"""

jwtio_header = "eyJraWQiOiI3MDllYjQyY2ZlZTU1NzAwNThjZTA3MTFmNzMwYmZiYjdkNGM4YWRlIiwiYWxnIjoiUlMyNTYiLCJ0eXAiOiJqd3" \
               "QifQ"
jwtio_payload = "eyJ1c2VyIjoiamltbXkiLCJpYXQiOjE0OTgxMzc1MTkuMTM1NDc5LCJleHAiOjEuMDAwMDAwMDAwMDAxNDk4MmUrMjF9"
jwtio_signature = "tXGcIZf" \
                  "bTIgxrd7ILj_XqcoiRLtmgjnJ0WORPBJ4M9Kd3zKTBkoIM6pN5XWdqsfvdby53mxQzi3_DZS4Ab4XvF29Wce49GVv7k69ZZJ-5g2NX9iJ" \
                  "y4_Be8uTZNKSwMpfrnkRrsbaWAGrXe9NKC3WC_Iq4UuE3KM7ltvOae4be-2863DP7_QEUtaAtXSwUkjPcgkvMPns-SurtFNXgFFVToNnw" \
                  "IuJ9UWsY8JlX1UB56wfqu68hbl88lenIf9Ym0r5hq0DlOZYNtjVizVDFciRx_52d4oeKMSzwJ1jB5aZ7YKRNHTo38Kltb5FkHRcIkV1Ae" \
                  "68-5dZeE9Yu_JHPMi_hw"

jwtio_signed = jwtio_header + "." + jwtio_payload + "." + jwtio_signature


class TestJWEHelper(TestCase):
    CHECK_CLAIMS = {
        "exp": None,
        "iat": None,
    }

    def setUp(self):
        self.key_store = KeyStore({
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

        self.kid = "e19091072f920cbf3ca9f436ceba309e7d814a62"

        self.encoder_args = (
            TEST_DO_NOT_USE_UPSTREAM_PRIVATE_KEY,
            TEST_DO_NOT_USE_SR_PUBLIC_KEY
        )

    def test_decrypt_jwe_valid(self):
        token = JWEHelper.decrypt(VALID_JWE, self.key_store, KEY_PURPOSE_AUTHENTICATION)
        self.assertEqual(VALID_SIGNED_JWT, token)

    def test_decrypt_jwe_does_not_contain_four_instances_of_full_stop(self):
        jwe = VALID_JWE.replace('.', '', 1)

        self.assert_in_decrypt_exception(jwe, "InvalidJWEData")

    def test_missing_algorithm(self):
        jwe_protected_header = bytes('{"enc":"A256GCM","kid":"' + self.kid + '"}', 'utf-8')
        encoder = Encoder(*self.encoder_args)
        jwe = encoder.encrypt_token(VALID_SIGNED_JWT.encode(), self.kid, jwe_protected_header=jwe_protected_header)

        self.assert_in_decrypt_exception(jwe.decode(), "Algorithm not allowed")

    def test_invalid_algorithm(self):
        jwe_protected_header = bytes('{"alg":"PBES2_HS256_A128KW","enc":"A256GCM","kid":"' + self.kid + '"}', 'utf-8')
        encoder = Encoder(*self.encoder_args)
        jwe = encoder.encrypt_token(VALID_SIGNED_JWT.encode(), self.kid, jwe_protected_header=jwe_protected_header)

        self.assert_in_decrypt_exception(jwe.decode(), "Algorithm not allowed")

    def test_enc_missing(self):
        jwe_protected_header = bytes('{"alg":"PBES2_HS256_A128KW","kid":"' + self.kid + '"}', 'utf-8')

        encoder = Encoder(*self.encoder_args)
        jwe = encoder.encrypt_token(VALID_SIGNED_JWT.encode(), self.kid, jwe_protected_header=jwe_protected_header)

        self.assert_in_decrypt_exception(jwe.decode(), "Algorithm not allowed")

    def test_missing_kid(self):
        jwe_protected_header = bytes('{"alg":"RSA-OAEP","enc":"A256GCM"}', 'utf-8')

        encoder = Encoder(*self.encoder_args)
        jwe = encoder.encrypt_token(VALID_SIGNED_JWT.encode(), self.kid, jwe_protected_header=jwe_protected_header)

        self.assert_in_decrypt_exception(jwe.decode(), "Missing kid")

    def test_invalid_enc(self):
        jwe_protected_header = bytes('{"alg":"PBES2_HS256_A128KW","enc":"A128GCM","kid":"' + self.kid + '"}', 'utf-8')
        encoder = Encoder(*self.encoder_args)
        jwe = encoder.encrypt_token(VALID_SIGNED_JWT.encode(), self.kid, jwe_protected_header=jwe_protected_header)

        self.assert_in_decrypt_exception(jwe.decode(), "Algorithm not allowed")

    def test_jwe_header_contains_kid(self):
        jwe_protected_header = bytes('{"alg":"RSA-OAEP","enc":"A256GCM"}', 'utf-8')
        encoder = Encoder(*self.encoder_args)
        jwe = encoder.encrypt_token(VALID_SIGNED_JWT.encode(), self.kid, jwe_protected_header=jwe_protected_header)

        self.assert_in_decrypt_exception(jwe.decode(), "Missing kid")

    def test_jwe_key_not_2048_bits(self):
        cek = os.urandom(32)

        encoder = Encoder(*self.encoder_args)
        encoder.cek = cek
        encrypted_key = encoder._encrypted_key(cek)  # pylint: disable=protected-access
        encrypted_key = encrypted_key[0:-2]
        jwe = encoder.encrypt_token(VALID_SIGNED_JWT.encode(), self.kid, encrypted_key=encrypted_key)

        self.assert_in_decrypt_exception(jwe.decode(), "ValueError")

    def test_cek_not_256_bits(self):
        cek = os.urandom(24)

        encoder = Encoder(*self.encoder_args)
        encoder.cek = cek
        jwe = encoder.encrypt_token(VALID_SIGNED_JWT.encode(), self.kid)

        self.assert_in_decrypt_exception(jwe.decode(), "Expected key of lenght 256, got 192")

    def test_authentication_tag_not_128_bits(self):
        encoder = Encoder(*self.encoder_args)
        jwe = encoder.encrypt_token(VALID_SIGNED_JWT.encode(), self.kid, tag=os.urandom(10))

        self.assert_in_decrypt_exception(jwe.decode(), "Authentication tag must be 16 bytes or longer")

    def assert_in_decrypt_exception(self, jwe, error):
        with self.assertRaises(InvalidTokenException) as ite:
            JWEHelper.decrypt(jwe, self.key_store, KEY_PURPOSE_AUTHENTICATION)

        if error not in ite.exception.value:
            raise AssertionError(
                '"{}" not found in decrypt exception. Actual exception message [{}]'.format(error, ite.exception.value))

    def test_authentication_tag_corrupted(self):
        encoder = Encoder(*self.encoder_args)
        jwe = encoder.encrypt_token(VALID_SIGNED_JWT.encode(), self.kid, tag=b'adssadsadsadsadasdasdasads')

        with self.assertRaises(InvalidTokenException):
            JWEHelper.decrypt(jwe.decode(), self.key_store, KEY_PURPOSE_AUTHENTICATION)

    def test_cipher_text_corrupted(self):
        encoder = Encoder(*self.encoder_args)
        jwe = encoder.encrypt_token(VALID_SIGNED_JWT.encode(), self.kid)

        tokens = jwe.decode().split('.')
        jwe_protected_header = tokens[0]
        encrypted_key = tokens[1]
        encoded_iv = tokens[2]
        encoded_cipher_text = tokens[3]
        encoded_tag = tokens[4]

        corrupted_cipher = encoded_cipher_text[0:-1]
        reassembled = jwe_protected_header + "." + encrypted_key + "." + encoded_iv + "." + corrupted_cipher + "." + encoded_tag

        with self.assertRaises(InvalidTokenException):
            JWEHelper.decrypt(reassembled, self.key_store, KEY_PURPOSE_AUTHENTICATION)
