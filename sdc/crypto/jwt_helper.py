import json

from jwcrypto import jwt
from jwcrypto.jws import InvalidJWSSignature, InvalidJWSObject
from jwcrypto.jwt import JWTInvalidClaimFormat, JWTMissingClaim, JWTExpired
from structlog import get_logger

from sdc.crypto.exceptions import InvalidTokenException
from sdc.crypto.helper import extract_kid_from_header

logger = get_logger()


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
