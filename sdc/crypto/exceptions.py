
class CryptoError(Exception):
    ''' General Exception raise by this libraray if an error occurs not covered below '''
    pass


class InvalidTokenException(Exception):
    ''' Raised if there is an issue with the JWT and/or JWE headers and payloads '''
    def __init__(self, value="This token is invalid"):
        self.value = value

    def __str__(self):
        return self.value
