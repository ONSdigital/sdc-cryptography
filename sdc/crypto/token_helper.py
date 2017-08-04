import json
from structlog import get_logger

from jwcrypto import jwe, jwt
from jwcrypto.common import base64url_decode
from jwcrypto.jwe import InvalidJWEData
from jwcrypto.jws import InvalidJWSSignature, InvalidJWSObject
from jwcrypto.jwt import JWTInvalidClaimFormat, JWTMissingClaim, JWTExpired

from sdc.crypto.invalid_token_exception import InvalidTokenException

logger = get_logger()


def extract_kid_from_header(token):
    header = token.split('.')[:1][0]

    if header is "":
        raise InvalidTokenException("Missing Headers")

    try:
        protected_header = base64url_decode(header).decode()

        protected_header_data = json.loads(protected_header)

        if 'kid' in protected_header:
            return protected_header_data['kid']
    except ValueError:
        raise InvalidTokenException("Invalid Header")

    raise InvalidTokenException("Missing kid")


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


class JWTHelper:

    @staticmethod
    def decode(jwt_token, key_store, purpose, leeway=None, check_claims={}):
        try:
            jwt_kid = extract_kid_from_header(jwt_token)

            logger.info("Decoding JWT", kid=jwt_kid)

            public_jwk = key_store.get_public_key_by_kid(purpose, jwt_kid).as_jwk()

            signed_token = jwt.JWT(algs=['RS256'], check_claims=check_claims)

            if leeway:
                signed_token.leeway = leeway

            signed_token.deserialize(jwt_token, key=public_jwk)

            return json.loads(signed_token.claims)
        except (InvalidJWSObject,
                InvalidJWSSignature,
                JWTInvalidClaimFormat,
                JWTMissingClaim,
                JWTExpired,
                ValueError) as e:
            raise InvalidTokenException(repr(e))

    @staticmethod
    def encode(claims, kid, key_store, purpose):
        logger.info("Encoding JWT", kid=kid)

        private_jwk = key_store.get_private_key_by_kid(purpose, kid).as_jwk()

        header = {
            'kid': kid,
            'typ': 'jwt',
            'alg': 'RS256',
        }
        token = jwt.JWT(claims=claims, header=header)

        token.make_signed_token(private_jwk)

        return token.serialize()
