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
            open(os.path.join(
                os.path.dirname(__file__),
                "sdc", "crypto", "__init__.py"),
                'r').read().split("=")[-1].strip()
        )
    )

installRequirements = [
    i.strip() for i in open(
        os.path.join(os.path.dirname(__file__), "requirements.txt"), 'r'
    ).readlines()
]

setup(
    name="sdc-cryptography",
    version=version,
    description="A shared library for SDC services that use JWT with JWE",
    author="W Bailey",
    author_email="warren@warrenbailey.net",
    url="https://github.com/ONSdigital/sdc-cryptography",
    long_description=__doc__,
    classifiers=[
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3.4",
        "Programming Language :: Python :: 3.5",
        "Programming Language :: Python :: 3.6",
        "License :: OSI Approved :: MIT License",
    ],
    packages=[
        "sdc.crypto",
        "sdc.crypto.scripts",
        "sdc.crypto.test",
    ],
    package_data={
        "sdc.crypto": [
            "requirements.txt",
        ],
    },
    scripts=['sdc/crypto/scripts/generate_keys.py'],
    install_requires=installRequirements,
    entry_points={
        "console_scripts": [
        ],
    },
    namespace_packages=["sdc"],
    zip_safe=False
)
