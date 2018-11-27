from sdc.crypto.exceptions import InvalidTokenException


class InvalidTokenExceptionTest:

    @staticmethod
    def test_str_value_of_exception_is_error_text():
        """Tests that the string representation of an InvalidTokenException will return the
        error message text
        """
        invalid_token = InvalidTokenException("test")
        assert str(invalid_token) == "test"
