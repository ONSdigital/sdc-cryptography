
class CryptoError(Exception):
    pass


class InvalidTokenException(Exception):
    def __init__(self, value="This token is invalid"):
        self.value = value

    def __str__(self):
        return self.value
