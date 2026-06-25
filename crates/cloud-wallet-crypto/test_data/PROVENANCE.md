# JWE Interop Test Vectors

Generated offline using **joserfc** (an independent JOSE implementation),  
NOT by this crate's own `encrypt()` function.

- joserfc version: 1.7.1  
- OpenSSL version: 3.6.1  

---

## RSA-OAEP-256 / A256GCM token

- Recipient private key: `rsa2048.pkcs8.der`
- Public key exported via: `openssl rsa -in rsa2048.pem -pubout`
- Plaintext: `"interop test vector"`

---

## ECDH-ES / A256GCM token

- Recipient private key: `p256_recipient.pkcs8.der`
- Generated via: `openssl ecparam -name prime256v1 -genkey ...`
- Plaintext: `"ecdh interop"`

---

## Token generation code

```python
from joserfc import jwe
from joserfc.jwk import ECKey, RSAKey


def encrypt_token(header, payload, key, algorithms):
    return jwe.encrypt_compact(
        header,
        payload,
        key,
        algorithms=algorithms,
    )


with open("p256_recipient.pub.pem") as f:
    ecdh_public_key = ECKey.import_key(f.read())

token_ecdh = encrypt_token(
    {"alg": "ECDH-ES", "enc": "A256GCM"},
    b"ecdh interop",
    ecdh_public_key,
    ["ECDH-ES", "A256GCM"],
)

print("token_ecdh:", token_ecdh)


with open("rsa2048.pub.pem") as f:
    rsa_public_key = RSAKey.import_key(f.read())

token_rsa = encrypt_token(
    {"alg": "RSA-OAEP-256", "enc": "A256GCM"},
    b"interop test vector",
    rsa_public_key,
    ["RSA-OAEP-256", "A256GCM"],
)

print("token_rsa:", token_rsa)
