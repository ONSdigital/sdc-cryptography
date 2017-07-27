import hashlib
import os

from cryptography.hazmat.backends.openssl.backend import backend
from cryptography.hazmat.primitives.serialization import load_pem_private_key, Encoding, PublicFormat
import yaml
from yaml.representer import SafeRepresenter


'''
 This util file helps the user generate a yml file in the following format.
 It is made up of two parts, string secrets (passwords) and keys (public and private) keys:
  1234567890123456789012345678901234567890:
    purpose: submission
    type: public
    value: |
      -----BEGIN PUBLIC KEY-----
      #######################
      -----END PUBLIC KEY-----
    secrets:
        PASSWORD: 'secret_value'
'''


class LiteralUnicode(str):
    # Needed to ensure that the yaml file has the private/public keys formatted correctly
    pass


def change_style(style, representer):
    """
    This function is used to format the key value as a multi-line string maintaining the line breaks
    """
    def new_representer(dumper, data):
        scalar = representer(dumper, data)
        scalar.style = style
        return scalar
    return new_representer

represent_literal_unicode = change_style('|', SafeRepresenter.represent_str)
yaml.add_representer(LiteralUnicode, represent_literal_unicode)


def get_file_contents(folder, filename, trim=False):
    with open(os.path.join(folder, filename), 'r') as f:
        data = f.read()
        if trim:
            data = data.rstrip('\r\n')
    return data


def _generate_kid_from_key_and_add_to_dict(keys, key_type, purpose, public_key, private_key=None, kid_override=None):
    if not kid_override:
        hash_object = hashlib.sha1(public_key.encode())
        kid = hash_object.hexdigest()

    key = {
        "type": key_type,
        "purpose": purpose,
        "value": LiteralUnicode(private_key if private_key else public_key),
    }

    keys[kid_override if kid_override else kid] = key


def add_public_key_to_dict(keys, purpose, public_key, keys_folder, kid_override=None):
    '''
    Loads a public key from the file system and adds it to a dict of keys
    :param keys: A dict of keys
    :param purpose: The purpose of the public key
    :param private_key: The name of the public key to add
    :param keys_folder: The location on disk where the key exists
    :param kid_override: This allows the caller to override the generated KID value
    :return: None
    '''
    public_key_data = get_file_contents(keys_folder, public_key)

    _generate_kid_from_key_and_add_to_dict(keys, "public", purpose, public_key_data, kid_override=kid_override)


def add_private_key_to_dict(keys, purpose, private_key, keys_folder, kid_override=None):
    '''
    Loads a private key from the file system and adds it to a dict of keys
    :param keys: A dict of keys
    :param purpose: The purpose of the private key
    :param private_key: The name of the private key to add
    :param keys_folder: The location on disk where the key exists
    :param kid_override: This allows the caller to override the generated KID value
    :return: None
    '''
    private_key_data = get_file_contents(keys_folder, private_key)

    private_key = load_pem_private_key(private_key_data.encode(), None, backend=backend)

    pub_key = private_key.public_key()

    pub_bytes = pub_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)

    _generate_kid_from_key_and_add_to_dict(keys, "private", purpose, pub_bytes.decode(), private_key_data, kid_override=kid_override)


def generate_secrets_file(keys, secrets):
    with open('secrets.yml', 'w') as f:
        yaml.dump({"keys": keys, "secrets": secrets}, f, default_flow_style=False)
