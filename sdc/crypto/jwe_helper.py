import logging

from jwcrypto import jwe
from jwcrypto.jwe import InvalidJWEData

from sdc.crypto.exceptions import InvalidTokenException, MissingKeyException
from sdc.crypto.helper import extract_kid_from_header

logger = logging.getLogger(__name__)


class JWEHelper:
    '''
    Helper methods for encrypting a JWS/JWT. This class assumes you have used the RSA-OAP-A256GCM alogrithm
    and the required private key is available in the keystore.
    '''
    @staticmethod
    def decrypt(encrypted_token, key_store=None, purpose=None):
        try:
            jwe_token = jwe.JWE(algs=['RSA-OAEP', 'A256GCM'])
            jwe_token.deserialize(encrypted_token)

            jwe_kid = extract_kid_from_header(encrypted_token)

            logger.info("Decrypting JWE kid is {}".format(jwe_kid))

            private_jwk = key_store.get_private_key_by_kid(purpose, jwe_kid).as_jwk()
            if not private_jwk:
                raise MissingKeyException

            jwe_token.decrypt(private_jwk)

            return jwe_token.payload.decode()
        except (ValueError, InvalidJWEData) as e:
            raise InvalidTokenException(str(e)) from e

    @staticmethod
    def decrypt_with_key(encrypted_token, key):
        try:
            jwe_token = jwe.JWE(algs=['RSA-OAEP', 'A256GCM'])
            jwe_token.deserialize(encrypted_token)

            jwe_token.decrypt(key)

            return jwe_token.payload.decode()
        except (ValueError, InvalidJWEData) as e:
            raise InvalidTokenException(str(e)) from e

    @staticmethod
    def encrypt(payload, kid, key_store=None, purpose=None):

        try:
            logger.info("Encrypting JWE kid is {}".format(kid))

            public_jwk = key_store.get_public_key_by_kid(purpose, kid).as_jwk()
            if not public_jwk:
                raise MissingKeyException

            protected_header = {
                "alg": "RSA-OAEP",
                "enc": "A256GCM",
                "kid": kid,
            }

            token = jwe.JWE(plaintext=payload, protected=protected_header)

            token.add_recipient(public_jwk)
        except (ValueError, InvalidJWEData) as e:
            raise InvalidTokenException(str(e)) from e

        return token.serialize(compact=True)

    @staticmethod
    def encrypt_with_key(payload, kid, key):
        try:

            logger.info("Encrypting JWE with provided key and kid {}".format(kid))

            protected_header = {
                "alg": "RSA-OAEP",
                "enc": "A256GCM",
                "kid": kid,
            }

            token = jwe.JWE(plaintext=payload, protected=protected_header)

            token.add_recipient(key)
        except (ValueError, InvalidJWEData) as e:
            raise InvalidTokenException(str(e)) from e

        return token.serialize(compact=True)
