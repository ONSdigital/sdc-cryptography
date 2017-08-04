import unittest

from sdc.crypto.exceptions import InvalidTokenException


class InvalidTokenExceptionTest(unittest.TestCase):

    def test(self):
        invalid_token = InvalidTokenException("test")
        self.assertEqual("test", str(invalid_token))

if __name__ == '__main__':
    unittest.main()
