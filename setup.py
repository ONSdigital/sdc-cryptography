#!/usr/bin/env python
# encoding: UTF-8

import ast
import os.path

from setuptools import setup

try:
    # For setup.py install
    from sdc.crypto import __version__ as version
except ImportError:
    # For pip installations
    version = str(
        ast.literal_eval(
            open(
                os.path.join(os.path.dirname(__file__), "sdc", "crypto", "__init__.py"),
                "r",
            )
            .read()
            .split("=")[-1]
            .strip()
        )
    )

with open("./README.md") as fp:
    description = fp.read()

# For more info on pipenv and setuptools - https://realpython.com/pipenv-guide/#package-distribution
# and https://pipenv.readthedocs.io/en/latest/advanced/#pipfile-vs-setup-py
setup(
    name="sdc-cryptography",
    version=version,
    description="A shared library for SDC services that use JWT with JWE",
    author="ONS",
    url="https://github.com/ONSdigital/sdc-cryptography",
    long_description=description,
    long_description_content_type="text/markdown",
    classifiers=[
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.9",
        "License :: OSI Approved :: MIT License",
    ],
    packages=[
        "sdc.crypto",
        "sdc.crypto.scripts",
    ],
    scripts=["sdc/crypto/scripts/generate_keys.py"],
    install_requires=["jwcrypto", "cryptography", "PyYAML"],
    entry_points={
        "console_scripts": [],
    },
    namespace_packages=["sdc"],
    zip_safe=False,
)
