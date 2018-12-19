import os

from sdc.crypto.scripts.generate_keys import get_file_contents, get_public_key, get_private_key


class TestGenerateKeys:

    @staticmethod
    def get_file(folder, filename):
        with open(os.path.join(folder, filename), 'r') as f:
            data = f.read()
        return data

    def test_get_file_contents(self):
        "Test get_file_contents correctly retrieves a file"
        test_data = self.get_file("tests/test_keys", "sdc-sdx-submission-encryption-public-v2.pem")
        data = get_file_contents("tests/test_keys", "sdc-sdx-submission-encryption-public-v2.pem")
        assert data == test_data

    def test_get_file_contents_with_trim(self):
        "Test get_file_contents correctly retrieves a file"
        test_data = self.get_file("tests/test_keys", "sdc-sdx-submission-encryption-public-v2.pem")
        test_data = test_data.rstrip('\r\n')
        data = get_file_contents("tests/test_keys", "sdc-sdx-submission-encryption-public-v2.pem", trim=True)
        assert data == test_data

    def test_get_public_key(self):
        "Test the dictionary is created in the right format for public keys"
        public_key = self.get_file("tests/test_keys", "sdc-sdx-submission-encryption-public-v2.pem")
        kid, result = get_public_key('sdc', 'sdx', 'encryption', 'submission', 'v2', 'sdc-sdx-submission-encryption-public-v2.pem', "tests/test_keys")
        assert kid == "bf3abb2c2e6445cf014a0ffed81d314699040b37"
        assert result == {'platform': 'sdc',
                          'service': 'sdx',
                          'use': 'submission',
                          'type': 'public',
                          'purpose': 'encryption',
                          'version': 'v2',
                          'value': public_key}

    def test_get_private_key(self):
        "Test the dictionary is created in the right format for private keys"
        private_key = self.get_file("tests/test_keys", "sdc-sdx-submission-encryption-private-v2.pem")
        kid, result = get_private_key('sdc', 'sdx', 'encryption', 'submission', 'v2', 'sdc-sdx-submission-encryption-private-v2.pem', "tests/test_keys")
        assert kid == "bf3abb2c2e6445cf014a0ffed81d314699040b37"
        assert result == {'platform': 'sdc',
                          'service': 'sdx',
                          'use': 'submission',
                          'type': 'private',
                          'purpose': 'encryption',
                          'version': 'v2',
                          'value': private_key}
