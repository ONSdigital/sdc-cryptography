# sdc-cryptography
A common source code library for SDC services that use JWE. Apps wishing to use this should add the sdc_cryptography
dependency to their requirements.txt and install with pip.

### Basic Use

Assuming you are executing from inside an activated virtual environment:

###### Install requirements:

    $ make build

###### Run the unit tests:

    $ make test

###### Create a package for deployment:

    $ make sdist
