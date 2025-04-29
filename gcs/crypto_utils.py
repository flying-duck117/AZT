from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding
from cryptography.hazmat.primitives import serialization
from cryptography.x509 import load_pem_x509_certificate
from cryptography.x509.oid import NameOID
import datetime
from typing import Tuple, Optional
import logging

class CryptoUtils:
    @staticmethod
    def generate_key_pair() -> Tuple[ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey]:
        """Generate an ECDSA P-256 key pair"""
        private_key = ec.generate_private_key(ec.SECP256R1())
        public_key = private_key.public_key()
        return private_key, public_key
    
    @staticmethod
    def load_public_key_from_certificate(pem_data: bytes) -> ec.EllipticCurvePublicKey:
        """Load a public key from a PEM certificate"""
        try:
            cert = load_pem_x509_certificate(pem_data)
            return cert.public_key()
        except Exception as e:
            logging.error(f"Failed to load public key from certificate: {str(e)}")
            raise ValueError("Invalid certificate format or content")
    
    @staticmethod
    def verify_certificate_signature(cert_data: bytes, ca_public_key: ec.EllipticCurvePublicKey) -> bool:
        """Verify a certificate's signature using the CA public key"""
        try:
            cert = load_pem_x509_certificate(cert_data)
            ca_public_key.verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                ec.ECDSA(hashes.SHA256())
            )
            return True
        except Exception as e:
            logging.error(f"Certificate verification failed: {str(e)}")
            return False