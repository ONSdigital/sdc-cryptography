import json
from structlog import get_logger

from jwcrypto import jwe, jwt
from jwcrypto.common import base64url_decode
from jwcrypto.jwe import InvalidJWEData
from jwcrypto.jws import InvalidJWSSignature, InvalidJWSObject
from jwcrypto.jwt import JWTInvalidClaimFormat, JWTMissingClaim, JWTExpired

from sdc.crypto.invalid_token_exception import InvalidTokenException

logger = get_logger()


def decrypt_jwe(encrypted_token, key_store, purpose):
    try:
        jwe_token = jwe.JWE(algs=['RSA-OAEP', 'A256GCM'])
        jwe_token.deserialize(encrypted_token)

        jwe_kid = extract_kid_from_header(encrypted_token)

        logger.info("Decrypting JWE", kid=jwe_kid)

        private_jwk = key_store.get_private_key_by_kid(purpose, jwe_kid).as_jwk()

        jwe_token.decrypt(private_jwk)

        return jwe_token.payload.decode()
    except InvalidJWEData as e:
        raise InvalidTokenException(repr(e))


def encrypt_jwe(payload, kid, key_store, purpose, alg="RSA-OAEP", enc="A256GCM"):

    logger.info("Encrypting JWE", kid=kid)

    public_jwk = key_store.get_public_key_by_kid(purpose, kid).as_jwk()

    protected_header = {
        "alg": alg,
        "enc": enc,
        "kid": kid,
    }

    token = jwe.JWE(plaintext=payload, protected=protected_header)

    token.add_recipient(public_jwk)

    return token.serialize(compact=True)


def decode_jwt(jwt_token, key_store, purpose, leeway=None, check_claims={}):
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


def encode_jwt(claims, kid, key_store, purpose):
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
