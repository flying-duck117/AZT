# pki_setup.py
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from datetime import datetime, timedelta
import json
import os
import secrets
import base64
from pathlib import Path
import logging
from typing import Tuple, Optional

class PKISetup:
    def __init__(self, output_dir: str = "pki"):
        """Initialize PKI Setup with output directory"""
        self.output_dir = Path(output_dir)
        self.setup_directory_structure()
        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger('PKISetup')
        
    def setup_directory_structure(self) -> None:
        """Create the necessary directory structure"""
        directories = [
            self.output_dir,
            self.output_dir / "ca",
            self.output_dir / "crl",
            self.output_dir / "certs",
            self.output_dir / "private",
            self.output_dir / ".secure"  # Directory for password storage
        ]
        
        for directory in directories:
            directory.mkdir(parents=True, exist_ok=True)
            # Set restrictive permissions for security
            os.chmod(directory, 0o700)

    def generate_secure_password(self, length: int = 32) -> bytes:
        """
        Generate a cryptographically secure random password
        
        Args:
            length: Length of the random bytes to generate
            
        Returns:
            Bytes object containing the secure random password
        """
        return secrets.token_bytes(length)

    def save_password_securely(self, password: bytes) -> None:
        """
        Save the generated password securely and create instructions
        
        Args:
            password: The generated password bytes
        """
        try:
            # Save password to secure file
            password_file = self.output_dir / '.secure' / 'ca_password.bin'
            
            with open(password_file, 'wb') as f:
                f.write(password)
            os.chmod(password_file, 0o600)  # Only owner can read/write
            
            # Create instructions file
            instructions_file = self.output_dir / 'IMPORTANT_PASSWORD_INSTRUCTIONS.txt'
            with open(instructions_file, 'w') as f:
                f.write("""
IMPORTANT: CA Private Key Password Management Instructions

1. The CA private key password has been generated and saved to:
   .secure/ca_password.bin

2. For security:
   - Move the password file to a secure location separate from the CA private key
   - Consider using a secure password manager or hardware security module
   - Keep secure backups of the password file
   
3. Delete this instructions file after securing the password

4. Regular password rotation is recommended. To update:
   - Generate a new password
   - Re-encrypt the CA private key
   - Update all systems using the CA private key
   
WARNING: Loss of this password will require regenerating the entire PKI infrastructure!
""")
            
            self.logger.info("Password saved successfully. Please follow the instructions in "
                         "IMPORTANT_PASSWORD_INSTRUCTIONS.txt")
            
        except Exception as e:
            self.logger.error(f"Failed to save password: {str(e)}")
            raise

    @staticmethod
    def read_password_file(password_path: Path) -> bytes:
        """
        Read the password from the password file
        
        Args:
            password_path: Path to the password file
            
        Returns:
            The password as bytes
        """
        try:
            with open(password_path, 'rb') as f:
                return f.read()
        except Exception as e:
            raise ValueError(f"Failed to read password file: {str(e)}")
            
    def generate_ca_keypair(self) -> Tuple[ec.EllipticCurvePrivateKey, x509.Certificate]:
        """
        Generate the root CA key pair and self-signed certificate
        Returns (private_key, certificate)
        """
        # Generate key pair
        private_key = ec.generate_private_key(ec.SECP256R1())
        
        # Create certificate builder
        builder = x509.CertificateBuilder()
        
        # Set serial number
        builder = builder.serial_number(x509.random_serial_number())
        
        # Set CA name
        name = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, u"Drone PKI Root CA"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Drone PKI System"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, u"Root CA")
        ])
        
        # Set subject and issuer (same for root CA)
        builder = builder.subject_name(name)
        builder = builder.issuer_name(name)
        
        # Set validity period (e.g., 10 years for root CA)
        now = datetime.utcnow()
        builder = builder.not_valid_before(now)
        builder = builder.not_valid_after(now + timedelta(days=3650))
        
        # Set public key
        builder = builder.public_key(private_key.public_key())
        
        # Add extensions
        builder = builder.add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True
        )
        
        builder = builder.add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False
            ),
            critical=True
        )
        
        # Sign the certificate
        certificate = builder.sign(
            private_key=private_key,
            algorithm=hashes.SHA256()
        )
        
        return private_key, certificate
        
    def initialize_crl(self) -> None:
        """Initialize an empty CRL"""
        crl_data = {
            'version': '1.0',
            'last_update': datetime.utcnow().isoformat(),
            'next_update': (datetime.utcnow() + timedelta(days=1)).isoformat(),
            'revoked_certificates': []
        }
        
        crl_path = self.output_dir / "crl" / "drone_crl.json"
        with open(crl_path, 'w') as f:
            json.dump(crl_data, f, indent=4)
            
        self.logger.info(f"Initialized CRL at {crl_path}")
            
    def save_ca_materials(self, private_key: ec.EllipticCurvePrivateKey, 
                         certificate: x509.Certificate,
                         password: bytes) -> None:
        """Save CA private key and certificate using secure password"""
        # Save private key
        private_key_path = self.output_dir / "private" / "ca_key.pem"
        with open(private_key_path, 'wb') as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.BestAvailableEncryption(password)
            ))
        os.chmod(private_key_path, 0o600)
        
        # Save public certificate
        cert_path = self.output_dir / "ca" / "ca_cert.pem"
        with open(cert_path, 'wb') as f:
            f.write(certificate.public_bytes(
                encoding=serialization.Encoding.PEM
            ))
            
        self.logger.info(f"Saved CA private key to {private_key_path}")
        self.logger.info(f"Saved CA certificate to {cert_path}")
        
    def setup_pki(self) -> None:
        """Run the complete PKI setup process"""
        try:
            self.logger.info("Starting PKI setup...")
            
            # Generate secure password first
            ca_password = self.generate_secure_password()
            self.save_password_securely(ca_password)
            
            # Generate CA key pair and certificate
            private_key, certificate = self.generate_ca_keypair()
            
            # Save CA materials with secure password
            self.save_ca_materials(private_key, certificate, ca_password)
            
            # Initialize CRL
            self.initialize_crl()
            
            self.logger.info("PKI setup completed successfully")
            self.logger.info("IMPORTANT: Follow the instructions in IMPORTANT_PASSWORD_INSTRUCTIONS.txt "
                         "to securely store the CA private key password")
            
        except Exception as e:
            self.logger.error(f"PKI setup failed: {str(e)}")
            raise

def main():
    """Main function to run PKI setup"""
    setup = PKISetup(output_dir="certs")
    setup.setup_pki()

if __name__ == "__main__":
    main()