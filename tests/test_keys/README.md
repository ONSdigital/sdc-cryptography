The keys in this folder were generated with the following commands:

```bash
sudo openssl genrsa -out sdc-sdx-submission-encryption-private-v2.pem 4096
sudo openssl rsa -pubout -in sdc-sdx-submission-encryption-private-v2.pem -out sdc-sdx-submission-encryption-public-v2.pem
```