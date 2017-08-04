from jwcrypto import jwe
from jwcrypto.jwe import InvalidJWEData
from structlog import get_logger

from sdc.crypto.exceptions import InvalidTokenException
from sdc.crypto.helper import extract_kid_from_header

logger = get_logger()


class JWEHelper:
    '''
    Helper methods for encrypting a JWS/JWT. This class assumes you have used the RSA-OAP-A256GCM algoritm
    and the required private key is available in the keystore.
    '''
    @staticmethod
    def decrypt(encrypted_token, key_store=None, purpose=None, key=None):
        try:
            jwe_token = jwe.JWE(algs=['RSA-OAEP', 'A256GCM'])
            jwe_token.deserialize(encrypted_token)

            if key:
                logger.info("Decrypting JWE with provided key")
                private_jwk = key
            else:
                jwe_kid = extract_kid_from_header(encrypted_token)

                logger.info("Decrypting JWE", kid=jwe_kid)

                private_jwk = key_store.get_private_key_by_kid(purpose, jwe_kid).as_jwk()

            jwe_token.decrypt(private_jwk)

            return jwe_token.payload.decode()
        except (ValueError, InvalidJWEData) as e:
            raise InvalidTokenException(repr(e))

    @staticmethod
    def encrypt(payload, kid, key_store=None, purpose=None, alg="RSA-OAEP", enc="A256GCM", key=None):

        try:
            if key:
                public_jwk = key
            else:
                logger.info("Encrypting JWE", kid=kid)

                public_jwk = key_store.get_public_key_by_kid(purpose, kid).as_jwk()

            protected_header = {
                "alg": alg,
                "enc": enc,
                "kid": kid,
            }

            token = jwe.JWE(plaintext=payload, protected=protected_header)

            token.add_recipient(public_jwk)
        except (ValueError, InvalidJWEData) as e:
            raise InvalidTokenException(repr(e))

        return token.serialize(compact=True)
