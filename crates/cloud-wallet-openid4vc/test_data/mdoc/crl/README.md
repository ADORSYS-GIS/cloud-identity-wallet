# CRL Test Fixtures

This directory contains X.509 certificate and CRL fixtures for testing CRL-based revocation checking.

## Files

- `ca.der` - Self-signed CA certificate (DER format) used as the DSC issuer
- `dsc_with_crl_dp.der` - DSC certificate with serial 0x0102030405 and CRL Distribution Points extension
- `dsc_nonrevoked.der` - DSC certificate with serial 0xDEADBEEF and CRL Distribution Points extension
- `crl_empty.crl` - Empty CRL signed by CA (no revoked certificates)
- `crl_revoked.crl` - CRL signed by CA with serial 0x0102030405 revoked
- `crl_invalid.crl` - CRL signed by a different CA (invalid signature)

## Tests

These fixtures enable the following security-critical tests:

1. `check_revocation_empty_crl_clears_nonrevoked_dsc` - CRL without DSC serial returns Ok(())
2. `check_revocation_revoked_dsc_returns_error` - CRL with DSC serial returns CertificateRevoked
3. `check_revocation_invalid_crl_signature_rejected_hardfail` - Invalid CRL signature rejected under HardFail

## Regeneration

To regenerate these fixtures, run the following commands:

```sh
cd test_data/mdoc/crl
rm -f ca.* dsc_* crl_*

# Generate CA key and self-signed certificate
openssl genrsa -out ca.key 2048
openssl req -x509 -new -nodes -key ca.key -sha256 -days 365 -out ca.crt \
  -subj "/C=DE/O=Test IACA/CN=Test IACA Root"
openssl x509 -in ca.crt -outform DER -out ca.der

# Create extension config for DSC with CRL Distribution Points
cat > dsc_ext.cnf << 'EOF'
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req

[req_distinguished_name]

[v3_req]
crlDistributionPoints = URI:https://example.com/crl.crl
EOF

cat > ca_ext.cnf << 'EOF'
[ca_ext]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
crlDistributionPoints = URI:https://example.com/crl.crl
EOF

# Generate DSC with serial 0x0102030405 (will be revoked)
openssl genrsa -out dsc_with_crl_dp.key 2048
openssl req -new -key dsc_with_crl_dp.key -out dsc_with_crl_dp.csr \
  -subj "/C=DE/O=Test Issuer/CN=Test DSC with CRL DP" \
  -config dsc_ext.cnf
openssl x509 -req -in dsc_with_crl_dp.csr -CA ca.crt -CAkey ca.key -set_serial 0x0102030405 \
  -days 365 -extfile ca_ext.cnf -extensions ca_ext -out dsc_with_crl_dp.crt
openssl x509 -in dsc_with_crl_dp.crt -outform DER -out dsc_with_crl_dp.der

# Generate DSC with serial 0xDEADBEEF (non-revoked)
openssl genrsa -out dsc_nonrevoked.key 2048
openssl req -new -key dsc_nonrevoked.key -out dsc_nonrevoked.csr \
  -subj "/C=DE/O=Test Issuer/CN=Test DSC NonRevoked" \
  -config dsc_ext.cnf
openssl x509 -req -in dsc_nonrevoked.csr -CA ca.crt -CAkey ca.key -set_serial 0xDEADBEEF \
  -days 365 -extfile ca_ext.cnf -extensions ca_ext -out dsc_nonrevoked.crt
openssl x509 -in dsc_nonrevoked.crt -outform DER -out dsc_nonrevoked.der

# Generate empty CRL
mkdir -p demoCA/newcerts
touch demoCA/index.txt
echo "01" > demoCA/crlnumber

cat > demoCA/openssl.cnf << 'EOF'
[ca]
default_ca = test_ca

[test_ca]
database = demoCA/index.txt
new_certs_dir = demoCA/newcerts
serial = demoCA/serial
crlnumber = demoCA/crlnumber
certificate = ca.crt
private_key = ca.key
default_md = sha256
default_crl_days = 365
policy = policy_anything

[policy_anything]
countryName = optional
stateOrProvinceName = optional
localityName = optional
organizationName = optional
organizationalUnitName = optional
commonName = supplied
emailAddress = optional
EOF

openssl ca -gencrl -config demoCA/openssl.cnf -out crl_empty.pem
openssl crl -in crl_empty.pem -outform DER -out crl_empty.crl

# Generate CRL with DSC serial revoked
echo "R\t260623073316Z\t$(date +%y%m%d%H%M%SZ)\t0102030405\tunknown\t/C=DE/O=Test Issuer/CN=Test DSC with CRL DP" > demoCA/index.txt
echo "01" > demoCA/crlnumber
openssl ca -gencrl -config demoCA/openssl.cnf -out crl_revoked.pem
openssl crl -in crl_revoked.pem -outform DER -out crl_revoked.crl

# Generate CRL with wrong signer (for invalid signature test)
openssl genrsa -out wrong_ca.key 2048
openssl req -x509 -new -nodes -key wrong_ca.key -sha256 -days 365 -out wrong_ca.crt \
  -subj "/C=DE/O=Wrong IACA/CN=Wrong IACA Root"
mkdir -p wrong_ca_demoCA/newcerts
touch wrong_ca_demoCA/index.txt
echo "01" > wrong_ca_demoCA/crlnumber

cat > wrong_ca_demoCA/openssl.cnf << 'EOF'
[ca]
default_ca = wrong_ca

[wrong_ca]
database = wrong_ca_demoCA/index.txt
new_certs_dir = wrong_ca_demoCA/newcerts
serial = wrong_ca_demoCA/serial
crlnumber = wrong_ca_demoCA/crlnumber
certificate = wrong_ca.crt
private_key = wrong_ca.key
default_md = sha256
default_crl_days = 365
EOF

openssl ca -gencrl -config wrong_ca_demoCA/openssl.cnf -out crl_invalid.pem
openssl crl -in crl_invalid.pem -outform DER -out crl_invalid.crl

# Clean up intermediate files
rm -rf demoCA wrong_ca_demoCA ca.key ca.crt dsc_*.key dsc_*.crt dsc_*.csr wrong_ca.* *.pem dsc_ext.cnf ca_ext.cnf
```

## Security Note

These fixtures are for testing only. The private keys have been deleted after generating the fixtures.
The CA private key is NOT committed to the repository to prevent accidental use in production.