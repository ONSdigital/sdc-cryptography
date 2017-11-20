import base64
import os
from unittest import TestCase
import json

from sdc.crypto.exceptions import InvalidTokenException
from sdc.crypto.jwt_helper import JWTHelper
from sdc.crypto.key_store import KeyStore
from sdc.crypto.test import TEST_DO_NOT_USE_UPSTREAM_PUBLIC_PEM, TEST_DO_NOT_USE_SR_PRIVATE_PEM, \
    TEST_DO_NOT_USE_UPSTREAM_PRIVATE_KEY, TEST_DO_NOT_USE_SR_PUBLIC_KEY, TEST_DO_NOT_USE_EQ_PRIVATE_KEY, \
    TEST_DO_NOT_USE_EQ_PUBLIC_KEY

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
                  "bTIgxrd7ILj_XqcoiRLtmgjnJ0WORPBJ4M9Kd3zKTBkoIM6pN5XWdqsfvdby53mxQzi3_" \
                  "DZS4Ab4XvF29Wce49GVv7k69ZZJ-5g2NX9iJy4_Be8uTZNKSwMpfrnkRrsbaWAGrXe9NKC3WC_Iq4UuE3KM7ltvOae4be-2" \
                  "863DP7_QEUtaAtXSwUkjPcgkvMPns-SurtFNXgFFVToNnwIuJ9UWsY8JlX1UB56wfqu68hbl88" \
                  "lenIf9Ym0r5hq0DlOZYNtjVizVDFciRx_52d4oeKMSzwJ1jB5aZ7YKRNHTo38Kltb5FkHRcIkV1Ae68-5dZeE9Yu_JHPMi_hw"

jwtio_signed = jwtio_header + "." + jwtio_payload + "." + jwtio_signature


class TestTokenHelper(TestCase):  # pylint: disable=too-many-public-methods

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
                "EQ_USER_AUTHENTICATION_EQ_KEY": {'purpose': KEY_PURPOSE_AUTHENTICATION,
                                                  'type': 'private',
                                                  'value': TEST_DO_NOT_USE_EQ_PRIVATE_KEY},

            }
        })
        self.key_store_secondary = KeyStore({
            "keys": {
                "EQ_USER_AUTHENTICATION_EQ_KEY": {'purpose': KEY_PURPOSE_AUTHENTICATION,
                                                  'type': 'public',
                                                  'value': TEST_DO_NOT_USE_EQ_PUBLIC_KEY},
            }
        })

        self.kid = "e19091072f920cbf3ca9f436ceba309e7d814a62"

        self.encoder_args = (
            TEST_DO_NOT_USE_UPSTREAM_PRIVATE_KEY,
            TEST_DO_NOT_USE_SR_PUBLIC_KEY
        )

    def test_jwt_io(self):
        token = JWTHelper.decode(jwtio_signed, self.key_store, purpose=KEY_PURPOSE_AUTHENTICATION,
                                 check_claims=self.CHECK_CLAIMS)
        self.assertEqual("jimmy", token.get("user"))

    def test_does_not_contain_two_instances_of_full_stop(self):
        jwe = jwtio_signed.replace('.', '', 1)
        self.assert_in_decode_signed_jwt_exception(jwe, "Invalid Header")

    def test_jwt_contains_empty_header(self):
        token_without_header = "e30." + jwtio_payload + "." + jwtio_signature

        self.assert_in_decode_signed_jwt_exception(token_without_header, "Missing kid")

    def test_jwt_does_not_contain_header_at_all(self):
        token_without_header = "." + jwtio_payload + "." + jwtio_signature

        self.assert_in_decode_signed_jwt_exception(token_without_header, "Missing Headers")

    def test_jwt_contains_empty_payload(self):
        token_without_payload = jwtio_header + ".e30." + jwtio_signature

        self.assert_in_decode_signed_jwt_exception(token_without_payload, "InvalidSignature")

    def test_jwt_does_not_contain_payload(self):
        token_without_payload = jwtio_header + ".." + jwtio_signature

        self.assert_in_decode_signed_jwt_exception(token_without_payload, "InvalidSignature")

    def test_jwt_does_not_contain_signature(self):
        jwt = jwtio_header + "." + jwtio_payload + ".e30"

        self.assert_in_decode_signed_jwt_exception(jwt, "InvalidSignature")

    def test_jose_header_missing_type(self):
        header = base64.urlsafe_b64encode(b'{"alg":"RS256", "kid":"EDCRRM"}')
        jwt = header.decode() + "." + jwtio_payload + "." + jwtio_signature

        self.assert_in_decode_signed_jwt_exception(jwt, "InvalidSignature")

    def test_jose_header_invalid_type(self):
        header = base64.urlsafe_b64encode(b'{"alg":"RS256", "kid":"EDCRRM", "typ":"TEST"}')
        jwt = header.decode() + "." + jwtio_payload + "." + jwtio_signature

        self.assert_in_decode_signed_jwt_exception(jwt, "InvalidSignature")

    def test_jose_header_contains_multiple_type(self):
        header = base64.urlsafe_b64encode(b'{"alg":"RS256", "kid":"EDCRRM","typ":"JWT","typ":"TEST"}')
        jwt = header.decode() + "." + jwtio_payload + "." + jwtio_signature

        self.assert_in_decode_signed_jwt_exception(jwt, "InvalidSignature")

    def test_jose_header_missing_alg(self):
        header = base64.urlsafe_b64encode(b'{"kid":"EDCRRM","typ":"JWT"}')
        jwt = header.decode() + "." + jwtio_payload + "." + jwtio_signature

        self.assert_in_decode_signed_jwt_exception(jwt, "No \"alg\" in headers")

    def test_jose_header_invalid_alg(self):
        header = base64.urlsafe_b64encode(b'{"alg":"invalid","kid":"EDCRRM","typ":"JWT"}')
        jwt = header.decode() + "." + jwtio_payload + "." + jwtio_signature

        self.assert_in_decode_signed_jwt_exception(jwt, "Algorithm not allowed")

    def test_jose_header_none_alg(self):
        header = base64.urlsafe_b64encode(b'{"alg":"None","kid":"EDCRRM","typ":"JWT"}')
        jwt = header.decode() + "." + jwtio_payload + "." + jwtio_signature

        self.assert_in_decode_signed_jwt_exception(jwt, "Algorithm not allowed")

    def test_jose_header_contains_multiple_alg(self):
        header = base64.urlsafe_b64encode(b'{"alg":"RS256", "alg":"HS256","kid":"EDCRRM", "typ":"JWT"}')
        jwt = header.decode() + "." + jwtio_payload + "." + jwtio_signature

        self.assert_in_decode_signed_jwt_exception(jwt, "Algorithm not allowed")

    def test_jose_header_missing_kid(self):
        header = base64.urlsafe_b64encode(b'{"alg":"RS256", "typ":"JWT"}')
        jwt = header.decode() + "." + jwtio_payload + "." + jwtio_signature

        self.assert_in_decode_signed_jwt_exception(jwt, "Missing kid")

    def test_jose_header_contains_multiple_kid(self):
        header = base64.urlsafe_b64encode(b'{"alg":"RS256", "kid":"test", "kid":"EDCRRM", "typ":"JWT"}')
        jwt = header.decode() + "." + jwtio_payload + "." + jwtio_signature

        self.assert_in_decode_signed_jwt_exception(jwt, "InvalidSignature")

    def test_jose_header_contains_invalid_kid(self):
        header = base64.urlsafe_b64encode(b'{"alg":"RS256", "kid":"UNKNOWN", "typ":"JWT"}')
        jwt = header.decode() + "." + jwtio_payload + "." + jwtio_signature

        self.assert_in_decode_signed_jwt_exception(jwt, "Invalid public Key Identifier")

    def test_signature_not_2048_bits(self):
        jwt = jwtio_header + "." + jwtio_payload + "." + base64.urlsafe_b64encode(os.urandom(255)).decode()

        self.assert_in_decode_signed_jwt_exception(jwt, "InvalidSignature")

    def test_payload_corrupt(self):
        jwt = jwtio_header + ".asdasd." + jwtio_signature

        self.assert_in_decode_signed_jwt_exception(jwt, "InvalidSignature")

    def test_header_corrupt(self):
        jwt = "asdsadsa" + "." + jwtio_payload + "." + jwtio_signature

        self.assert_in_decode_signed_jwt_exception(jwt, "Invalid Header")

    def test_signature_corrupt(self):
        jwt = jwtio_header + "." + jwtio_payload + ".asdasddas"

        self.assert_in_decode_signed_jwt_exception(jwt, "Invalid base64 string")

    def test_payload_contains_malformed_json(self):
        payload = base64.urlsafe_b64encode(b'{"user":"jimmy,"iat": "1454935765","exp": "2075297148"')
        jwt = jwtio_header + "." + payload.decode() + "." + jwtio_signature

        self.assert_in_decode_signed_jwt_exception(jwt, "InvalidSignature")

    def test_payload_contains_corrupted_json(self):
        payload = base64.urlsafe_b64encode(b'{"user":"jimmy","iat": "1454935765","exp": "2075297148"}ABDCE')
        jwt = jwtio_header + "." + payload.decode() + "." + jwtio_signature

        self.assert_in_decode_signed_jwt_exception(jwt, "InvalidSignature")

    def test_payload_does_not_contain_exp(self):
        valid_token_no_exp = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IkVEQ1JSTSJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibm" \
                             "FtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6IjE0NTQ5MzU3NjcifQ.VupTBEOEzeDjxd37PQ34xv" \
                             "BlLzeGTA0xFdGnLZDcnxAS1AjNcJ66edRmr4tmPIXnD6Mgen3HSB36xuXSnfzPld2msFHUXmB18CoaJQK19BXEY" \
                             "vosrBPzc1ohSvam_DgXCzdSMAcWSE63e6LTWNCT93-npD3p9tjdY_TWpEOOg14"

        self.assert_in_decode_signed_jwt_exception(valid_token_no_exp, "Claim exp is missing")

    def test_payload_does_not_contain_iat(self):
        valid_token_no_iat = "eyJhbGciOiJSUzI1NiIsImtpZCI6IjcwOWViNDJjZmVlNTU3MDA1OGNlMDcxMWY3MzBiZmJiN2Q0YzhhZGUiLCJ" \
                             "0eXAiOiJqd3QifQ.eyJlcV9pZCI6IjEiLCJleHAiOjIwNzcxODg5MDksImZvcm1fdHlwZSI6IjAyMDUiLCJqdGk" \
                             "iOiIzMmIxNDdjNS04OWEzLTQxMzUtYjgxMy02YzQzNTE1Yzk3MTkifQ.lPTbkzQhrktcRCgn2-ku4eqr5zpgetn" \
                             "I8JjipBsm3WrxALnnQc4QebtsPIP9vxv9cRLkis6FMZa3Lm6A5fVAHwsCKMOsDjBFf3QXVtLIgRMW-Q8VNowj5F" \
                             "UW5TAQhRAka-Og9lI3gTpcN-ynhnb0arlGKhbzJU03K0KEBPTT6TDRUeKZAUTAA29qxmPIVbhuQNAjmHX7uSW4z" \
                             "_OKLi1OdIlFEvC6X5rddkfv2yhGDNpO4ZfUcHvcfCgyg16WQDSBKVLQf2uk8-Ju_zOv4818Obb12N7CJvAb5eys" \
                             "vnW3MSbAQhvvJJYe8WCN7j1uHZxRpwIPgAGvGiN9Sa1Gq14EWA"

        self.assert_in_decode_signed_jwt_exception(valid_token_no_iat, "Claim iat is missing")

    def test_payload_invalid_exp(self):
        valid_token_with_invalid_exp = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IkVEQ1JSTSJ9.eyJzdWIiOiIxMjM0NTY3" \
                                       "ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6IjE0NTQ5MzU3NjUiLCJle" \
                                       "HAiOiI_In0.0ApxEXw1rzo21XQo8WgcPvnz0e8QnT0GaoXVbCj-OdJtB7GArPzaiQ1cU53WaJsvGE" \
                                       "zHTczc6Y0xN7WzcTdcXN8Yjenf4VqoiYc6_FXGJ1s9Brd0JOFPyVipTFxPoWvYTWLXE-CAEpXrEb3" \
                                       "0kB3nRjHFV_yVhLiiZUU-gpUHqNQ"

        self.assert_in_decode_signed_jwt_exception(valid_token_with_invalid_exp, "Claim exp is not an integer")

    def test_payload_invalid_iat(self):
        valid_token_with_invalid_iat = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IkVEQ1JSTSJ9.eyJzdWIiOiIxMjM0NTY3" \
                                       "ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6ImEiLCJleHAiOiIyMDc1M" \
                                       "jk3MTQ4In0.1NIuxcD1FsZlU17NxK4UHdCfzl7qTV03qEaTRcqTC6A1Fs2Alc7mSQgkF_SpUw4Ylt" \
                                       "n-7DhO2InfcwDA0VhxBOHDL6ZzcEvzw-49iD-AaSd4aINIkDK-Iim5uzbKzgQCuZqSXFqxsZlezA4" \
                                       "BtwV7Lv2puqdPrXT8k3SvM2rOwRw"

        self.assert_in_decode_signed_jwt_exception(valid_token_with_invalid_iat, "Claim iat is not an integer")

    def test_payload_expired_exp(self):
        valid_token_with_exp_in_the_past = "eyJraWQiOiI3MDllYjQyY2ZlZTU1NzAwNThjZTA3MTFmNzMwYmZiYjdkNGM4YWRlIiwidHlwI" \
                                           "joiand0IiwiYWxnIjoiUlMyNTYifQ.eyJpYXQiOjE0OTg2NTQzOTcuMDgxOTE1LCJlcV9pZCI" \
                                           "6IjEiLCJmb3JtX3R5cGUiOiIwMjA1IiwiZXhwIjoxNDk4NjU0Mzk2LjA4MTkxNSwianRpIjoi" \
                                           "NzZlNjllYTAtZWRlYi00NGY5LThkYWEtY2Q1ZDQzNzg5YmM1In0.CKWYyIcDbZaUXvdDno2B3" \
                                           "0w599_VXqicKkVjoeF4kNxc8aUcc_6J-rxTI8OU0OEoy8ywUTMBwYQnCHAuleBUYcmE9oNaHA" \
                                           "HHbfvTRVDpi1rIFc3vnoy37hx7v-iRElNJ_CNrGw5aURZ_eFarH2EiSNf7tdIy8H1xn0GnHMB" \
                                           "3-fmFylj9wvNR4td5MteAAeZlvsRf4uPj2GCm44re-n4iRY9z3ocZcKvUYVIJFOEK3XUerUdy" \
                                           "zZBGqbf-uIPB615nJgZF0PPS6e85VzrmyLD54fqrDrSnklKhu4dfMf_YdbegWvi7lUv7z_QIH" \
                                           "PRlUgxPsWKmV2G1SeVKRqbx1n_raA"

        self.assert_in_decode_signed_jwt_exception(valid_token_with_exp_in_the_past, "Expired at")

    def test_payload_exp_less_than_iat(self):
        valid_token_with_exp_less_than_iat = "eyJraWQiOiI3MDllYjQyY2ZlZTU1NzAwNThjZTA3MTFmNzMwYmZiYjdkNGM4YWRlIiwiYW" \
                                             "xnIjoiUlMyNTYiLCJ0eXAiOiJqd3QifQ.eyJmb3JtX3R5cGUiOiIwMjA1IiwiaWF0IjoxNDk" \
                                             "4NjU0MjEzLjk5NjQ2MywianRpIjoiNWFkODdjMGQtZjZlOC00MDEyLWEyM2UtMjc4MzY4YjF" \
                                             "kZmFmIiwiZXFfaWQiOiIxIiwiZXhwIjoxNDk4NjUwNjEzLjk5NjQ2M30.kAAO0uZG02sTJpQ" \
                                             "DzUFkIU7UGR9ulJV6idZJsWkJcsIu4G1JHfCoyNCzJr9xT8RRPbUrgkdVkuLD0gzOnD0Ylqj" \
                                             "xKxpoRTVUtD4p2l-5FuXcqIpy6jtQWsx1YGvMfdCRwsvpVVAUiFAhSddC0QRHvqweet7WgMq" \
                                             "SAvNz6zkOTVvW5ChjrK3IaGOAl3T6jWFN1xJCHcdlMef6S8t3ECP5NaP5HRnRxiVmV63x_RR" \
                                             "uSBwLbz_IMHUPPe6JcMRTMnzL8qM2Kwg227mHlmQhn3OMjagzraZZeQ4aedghalYoItZE80d" \
                                             "AcfDWs8DPJPqhJ0JGdA08A7ningHV67LRm6zkYw"

        self.assert_in_decode_signed_jwt_exception(valid_token_with_exp_less_than_iat, "Expired at")

    def test_payload_contains_more_than_one_iat(self):
        payload = base64.urlsafe_b64encode(b'{"user":"jimmy",'
                                           b'"iat": "1454935765",'
                                           b'"iat": "1454935765",'
                                           b'"exp": "2075297148"}')
        jwt = jwtio_header + "." + payload.decode() + "." + jwtio_signature

        self.assert_in_decode_signed_jwt_exception(jwt, "InvalidSignature")

    def test_payload_contains_more_than_one_exp(self):
        payload = base64.urlsafe_b64encode(b'{"user":"jimmy",'
                                           b'"iat": "1454935765",'
                                           b'"exp": "1454935765",'
                                           b'"exp": "2075297148"}')
        jwt = jwtio_header + "." + payload.decode() + "." + jwtio_signature

        self.assert_in_decode_signed_jwt_exception(jwt, "InvalidSignature")

    def assert_in_decode_signed_jwt_exception(self, jwe, error):
        with self.assertRaises(InvalidTokenException) as ite:
            JWTHelper.decode(jwe, self.key_store, purpose=KEY_PURPOSE_AUTHENTICATION, check_claims=self.CHECK_CLAIMS)

        if error not in ite.exception.value:
            raise AssertionError(
                '"{}" not found in decode exception. Actual exception message [{}]'.format(error, ite.exception.value))

    def test_encode_with_dict_and_string(self):
        claims_as_dict = {
            'data': [
                {
                    'string': 'something',
                    'boolean': True,
                    'number': 10,
                    'decimal': 10.1,
                    'null': None
                }
            ]
        }
        claims_as_string = json.dumps(claims_as_dict)

        string_token = JWTHelper.encode(claims=claims_as_string, kid='EQ_USER_AUTHENTICATION_EQ_KEY',
                                        key_store=self.key_store, purpose=KEY_PURPOSE_AUTHENTICATION)
        dict_token = JWTHelper.encode(claims=claims_as_dict, kid='EQ_USER_AUTHENTICATION_EQ_KEY',
                                      key_store=self.key_store, purpose=KEY_PURPOSE_AUTHENTICATION)

        string_token_decode = JWTHelper.decode(jwt_token=string_token, key_store=self.key_store_secondary,
                                               purpose=KEY_PURPOSE_AUTHENTICATION)
        dict_token_decode = JWTHelper.decode(jwt_token=dict_token, key_store=self.key_store_secondary,
                                             purpose=KEY_PURPOSE_AUTHENTICATION)

        self.assertEqual(string_token_decode, dict_token_decode)
