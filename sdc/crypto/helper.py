import json

from jwcrypto.common import base64url_decode
from sdc.crypto.exceptions import InvalidTokenException


def extract_kid_from_header(token):
    header = token.split('.')[:1][0]

    if not header:
        raise InvalidTokenException("Missing Headers")

    try:
        protected_header = base64url_decode(header).decode()

        protected_header_data = json.loads(protected_header)

        if 'kid' in protected_header:
            return protected_header_data['kid']
    except ValueError:
        raise InvalidTokenException("Invalid Header")

    raise InvalidTokenException("Missing kid")
