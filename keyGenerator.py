##Eichelle Turner ect0065 CSCE 3550 JWKS Server 9.19.24

import datetime
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

KEYS = {}

def generate_rsa_key_pair(kid, expire=5):
    privateKey = rsa.generate_privateKey(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    publicKey = privateKey.publicKey()
    private_pem = privateKey.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_pem = publicKey.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    expiry_time = datetime.datetime.utc() + datetime.timedelta(minutes=expire)
    
    KEYS[kid] = {
        'privateKey': private_pem,
        'publicKey': public_pem,
        'expiry': expiry_time,
    }

    return private_pem, public_pem



