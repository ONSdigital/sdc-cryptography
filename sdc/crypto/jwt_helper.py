import json
import logging

from jwcrypto import jwt
from jwcrypto.jws import InvalidJWSSignature, InvalidJWSObject
from jwcrypto.jwt import JWTInvalidClaimFormat, JWTMissingClaim, JWTExpired

from sdc.crypto.exceptions import InvalidTokenException
from sdc.crypto.helper import extract_kid_from_header

logger = logging.getLogger(__name__)


class JWTHelper:

    @staticmethod
    def decode(jwt_token, key_store, purpose, leeway=None, check_claims={}):
        try:
            jwt_kid = extract_kid_from_header(jwt_token)

            logger.info("Decoding JWT kid is {}".format(jwt_kid))

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
            raise InvalidTokenException(str(e)) from e

    @staticmethod
    def encode(claims, kid, key_store, purpose):
        logger.info("Encoding JWT kid is {}".format(kid))

        private_jwk = key_store.get_private_key_by_kid(purpose, kid).as_jwk()

        header = {
            'kid': kid,
            'typ': 'jwt',
            'alg': 'RS256',
        }
        token = jwt.JWT(claims=claims, header=header)

        token.make_signed_token(private_jwk)

        return token.serialize()
