#!/usr/bin/env python

import hashlib
import os
import argparse

from cryptography.hazmat.backends.openssl.backend import backend
from cryptography.hazmat.primitives.serialization import load_pem_private_key, Encoding, PublicFormat
import yaml
from yaml.representer import SafeRepresenter


'''
  This script will generate a secrets.yml file with key information extracted from the provided folder. It assumes
  keys are in the format:
  
  <platform>-<service>-<purpose>-<key_use>-<key_type>-<version>.pem

    platform | Platform the keys are used on e.g. sdc 
    service  | Service the key originates from (holder of the private key) e.g. rrm, sdx or eq 
    purpose  | Purpose of the key in the service e.g. authentication or submission
    key_use  | encryption or signing
    key_type | public or private
    version  | Version identifier e.g. v1
    
  e.g. sdc-rrm-authentication-encryption-public-v1.pem

  This script generates a yml file in the following format.
  1234567890123456789012345678901234567890:
    platform: sdc
    service: eq
    purpose: submission
    use: encryption
    type: public
    value: |
      -----BEGIN PUBLIC KEY-----
      #######################
      -----END PUBLIC KEY-----
  a44fa298eb4fb951372a2f70ee0711e6775ead68:
    platform: sdc
    service: eq
    purpose: submission
    use: encryption
    type: private
    version: v1
    value: |
      -----BEGIN RSA PRIVATE KEY-----
      #######################
      -----END RSA PRIVATE KEY-----
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


def _generate_kid_from_key_and_add_to_dict(keys, key_type, platform, service, purpose, key_use, version, public_key, private_key=None, kid_override=None):
    if not kid_override:
        hash_object = hashlib.sha1(public_key.encode())
        kid = hash_object.hexdigest()

    key = {
        "platform": platform,
        "service": service,
        "use": key_use,
        "type": key_type,
        "purpose": purpose,
        "version": version,
        "value": LiteralUnicode(private_key if private_key else public_key),
    }

    keys[kid_override if kid_override else kid] = key


def add_public_key_to_dict(keys, platform, service, purpose, key_use, version, public_key, keys_folder, kid_override=None):
    '''
    Loads a public key from the file system and adds it to a dict of keys
    :param keys: A dict of keys
    :param platform the platform the key is for
    :param service the service the key is for
    :param key_use what the key is used for
    :param version the version of the key
    :param purpose: The purpose of the public key
    :param private_key: The name of the public key to add
    :param keys_folder: The location on disk where the key exists
    :param kid_override: This allows the caller to override the generated KID value
    :return: None
    '''
    public_key_data = get_file_contents(keys_folder, public_key)

    _generate_kid_from_key_and_add_to_dict(keys, "public", platform, service, purpose, key_use, version, public_key_data, kid_override=kid_override)


def add_private_key_to_dict(keys, platform, service, purpose, key_use, version, private_key, keys_folder, kid_override=None):
    '''
    Loads a private key from the file system and adds it to a dict of keys
    :param keys: A dict of keys
    :param platform the platform the key is for
    :param service the service the key is for
    :param key_use what the key is used for
    :param version the version of the key
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

    _generate_kid_from_key_and_add_to_dict(keys, "private", platform, service, purpose, key_use, version, pub_bytes.decode(), private_key_data, kid_override=kid_override)


def generate_secrets_file(keys,):
    with open('secrets.yml', 'w') as f:
        yaml.dump({"keys": keys}, f, default_flow_style=False)


def generate_keys(keys_folder):

    key_files = [f for f in os.listdir(keys_folder) if os.path.isfile(os.path.join(keys_folder, f))]

    keys = {}

    for key_file in key_files:
        try:
            # remove the .pem extension
            key_file_no_pem = key_file[:key_file.index(".")]
            platform, service, purpose, key_use, key_type, version = key_file_no_pem.split("-")
            if key_type == "public":
                add_public_key_to_dict(keys, platform, service, purpose, key_use, version, key_file, keys_folder)
            elif key_type == "private":
                add_private_key_to_dict(keys, platform, service, purpose, key_use, version, key_file, keys_folder)
            else:
                print("Unknown key type {} in {}".format(key_type, key_file))

        except ValueError:
            print("File {} is not in correct format".format(key_file))

    generate_secrets_file(keys)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Generate secrets key file.')
    parser.add_argument('folder', type=str,
                        help='The folder that contains the secrets and keys')

    args = parser.parse_args()

    keys_folder = args.folder
    generate_keys(keys_folder)
