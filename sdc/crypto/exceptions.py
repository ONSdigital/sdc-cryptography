
class CryptoError(Exception):
    ''' General Exception raised by this library if an error occurs not covered below '''
    pass


class MissingKeyException(Exception):
    ''' Raised if a key cannot be found in the keystore '''
    pass


class InvalidTokenException(Exception):
    ''' Raised if there is an issue with the JWT and/or JWE headers and payloads '''
    def __init__(self, value="This token is invalid"):
        self.value = value

    def __str__(self):
        return self.value
