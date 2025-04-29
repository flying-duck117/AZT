from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID, ExtensionOID
from datetime import datetime, timedelta, timezone
from typing import Dict, Any, Optional
import logging, os
from pathlib import Path
from crypto_utils import CryptoUtils
from crl_manager import CRLManager
from config import PKIConfig
from flask import Flask, request, jsonify
from pki_gen import PKISetup
import json

class GCS:
    def __init__(self, base_dir: str = "certs"):
        self.logger = logging.getLogger('GCS_SERVER')
        self.logger.setLevel(logging.INFO)
        self.base_dir = Path(base_dir)
        self.config = PKIConfig()
        self.crypto_utils = CryptoUtils()
        self.app = Flask(__name__)
        self.cert_validity_minutes = int(os.getenv('CERT_VALIDITY_MINUTES', '59'))
        self.skip_verification = os.getenv('SKIP_VERIFICATION', 'false').lower() == 'true' # Skips hardware verification for each node
        self.setup_routes()
        self.private_key, self.public_key = self.crypto_utils.generate_key_pair()
        self._ensure_pki_infrastructure()
        self._load_pki_materials()
        self.allowed_devices = set()
        self.load_allowed_devices('allowed_devices.json')
        self._start_bootstrap_phase()
        self.issued_certificates = {}
        self.leader_drones = set() # Note: No included implementation for updating a leader note

        self.leader_ids = [id.strip() for id in os.getenv('LEADER_DRONES', '').split(',') if id.strip()]
        for leader_id in self.leader_ids:
            self.register_leader(leader_id)
        print(self.leader_ids)

    def load_allowed_devices(self, filepath: str) -> None:
        """Load allowed devices from a JSON file containing serial numbers and EEPROM IDs"""
        try:
            with open(filepath, 'r') as f:
                devices = json.load(f)
                self.allowed_devices = {(d['serial_number'], d['eeprom_id']) for d in devices}

            self.logger.info(f"Successfully loaded {len(self.allowed_devices)} devices:")
            for serial_number, eeprom_id in self.allowed_devices:
                self.logger.info(f"Device: Serial Number = {serial_number}, EEPROM ID = {eeprom_id}")

        except (FileNotFoundError, json.JSONDecodeError) as e:
            self.logger.error(f"Failed to load allowed devices: {str(e)}")
            self.allowed_devices = set()

    def _start_bootstrap_phase(self):
        """Start the bootstrap phase for certificate enrollment"""
        self.config.BOOTSTRAP_START_TIME = datetime.now(timezone.utc)
        self.logger.info(f"Bootstrap phase started at {self.config.BOOTSTRAP_START_TIME}")
        self.logger.info(f"Bootstrap phase will end at {self.config.BOOTSTRAP_START_TIME + self.config.BOOTSTRAP_DURATION}")

    def setup_routes(self):
        @self.app.route('/request_certificate', methods=['POST'])
        def handle_cert_request():
            try:
                data = request.get_json()
                self.logger.info(f"Certificate request received from {request.remote_addr}")

                # Validate required fields
                serial_number = data.get('serial_number')
                eeprom_id = data.get('eeprom_id')
                csr_pem = data.get('csr')

                if not serial_number:
                    self.logger.warning("Certificate request missing serial_number")
                    return jsonify({'status': 'error', 'message': 'Missing serial_number field'}), 400

                if not eeprom_id:
                    self.logger.warning("Certificate request missing eeprom_id")
                    return jsonify({'status': 'error', 'message': 'Missing eeprom_id field'}), 400

                if not csr_pem:
                    self.logger.warning("Certificate request missing CSR")
                    return jsonify({'status': 'error', 'message': 'Missing CSR field'}), 400

                self.logger.info(f"Processing certificate request for device: {serial_number}, {eeprom_id[:8]}...")

                # Parse and verify CSR
                try:
                    csr = x509.load_pem_x509_csr(csr_pem.encode('utf-8'))
                except Exception as e:
                    self.logger.error(f"Failed to parse CSR: {str(e)}")
                    return jsonify({'status': 'error', 'message': f'Invalid CSR format: {str(e)}'}), 400

                # Skip verification if configured, otherwise verify device
                if not self.skip_verification:
                    try:
                        # Verify CSR signature
                        csr.public_key().verify(csr.signature, csr.tbs_certrequest_bytes, ec.ECDSA(hashes.SHA256()))
                    except Exception as e:
                        self.logger.error(f"CSR signature verification failed: {str(e)}")
                        return jsonify({'status': 'error', 'message': f'CSR signature verification failed: {str(e)}'}), 400

                    # Verify device identity
                    if not self.verify_device_identity(serial_number, eeprom_id):
                        self.logger.warning(f"Device identity verification failed for {serial_number}, {eeprom_id[:8]}...")
                        return jsonify({
                            'status': 'error',
                            'message': 'Identity verification failed. Device not in allowed list.',
                            'allowed_devices_count': len(self.allowed_devices)
                        }), 403
                else:
                    self.logger.info("Device verification skipped as per configuration")

                # Generate certificate
                cert = self.generate_certificate(csr, serial_number, eeprom_id)
                self.logger.info(f"Certificate generated successfully for device: {serial_number}")

                return jsonify({
                    'status': 'success',
                    'certificate': self.format_certificate_response(cert, serial_number, eeprom_id)
                }), 200

            except Exception as e:
                self.logger.error(f"Error processing certificate request: {str(e)}")
                return jsonify({'status': 'error', 'message': str(e)}), 500

        @self.app.route('/get_network_nodes', methods=['POST'])
        def get_network_nodes():
            try:
                data = request.get_json()
                requesting_drone_id = data.get('drone_id')
                auth_token = data.get('auth_token')  # This could be signed with the drone's private key

                # Verify the drone is a leader
                if not requesting_drone_id in self.leader_ids:
                    return jsonify({'status': 'error', 'message': 'Unauthorized - not a leader drone'}), 403

                # Return the list of nodes and their certificates
                return jsonify({
                    'status': 'success',
                    'nodes': self.get_network_node_list()
                }), 200

            except Exception as e:
                return jsonify({'status': 'error', 'message': str(e)}), 500

        @self.app.route('/check_crl/<certificate>', methods=['GET'])
        def check_certificate_revocation(certificate):
            try:
                self.logger.info(f"Received CRL check request for certificate: {certificate[:15]}...")

                # Validate the certificate parameter
                if not certificate:
                    return jsonify({'status': 'error', 'message': 'Certificate parameter is required'}), 400

                # Check if the certificate is revoked using the CRL manager
                is_revoked = self.crl_manager.is_cert_revoked(certificate)

                # Log the result
                self.logger.info(f"Certificate {certificate[:15]}... is {'revoked' if is_revoked else 'valid'}")

                # Return the result
                return jsonify({
                    'status': 'success',
                    'certificate': certificate[:15] + "...",  # Return truncated certificate for logs
                    'revoked': is_revoked,
                    'timestamp': datetime.now(timezone.utc).isoformat()
                }), 200

            except Exception as e:
                self.logger.error(f"Error checking certificate revocation: {str(e)}")
                return jsonify({'status': 'error', 'message': str(e)}), 500

        @self.app.route('/bulk_check_crl', methods=['POST'])
        def bulk_check_certificate_revocation():
            try:
                # Get the list of certificates from the request
                data = request.get_json()
                if not data or not isinstance(data, dict) or 'certificates' not in data:
                    return jsonify({'status': 'error', 'message': 'Invalid request format. Expected JSON with "certificates" array'}), 400

                certificates = data.get('certificates', [])
                if not certificates or not isinstance(certificates, list):
                    return jsonify({'status': 'error', 'message': 'Invalid or empty certificates list'}), 400

                self.logger.info(f"Received bulk CRL check request for {len(certificates)} certificates")

                # Check each certificate
                results = {}
                for cert in certificates:
                    results[cert] = self.crl_manager.is_cert_revoked(cert)

                # Return the results
                return jsonify({
                    'status': 'success',
                    'results': results,
                    'timestamp': datetime.now(timezone.utc).isoformat(),
                    'crl_last_update': self.crl_manager.last_update.isoformat()
                }), 200

            except Exception as e:
                self.logger.error(f"Error performing bulk CRL check: {str(e)}")
                return jsonify({'status': 'error', 'message': str(e)}), 500

        @self.app.route('/crl_status', methods=['GET'])
        def get_crl_status():
            try:
                # Get CRL status information
                status = self.crl_manager.get_crl_status()

                # Add additional information for the response
                status['total_issued_certificates'] = len(self.issued_certificates)
                status['revocation_percentage'] = (
                    (status['revoked_count'] / status['total_issued_certificates'] * 100)
                    if status['total_issued_certificates'] > 0 else 0
                )

                # Return the status
                return jsonify({
                    'status': 'success',
                    'crl_info': status
                }), 200

            except Exception as e:
                self.logger.error(f"Error retrieving CRL status: {str(e)}")
                return jsonify({'status': 'error', 'message': str(e)}), 500

    def is_leader_drone(self, drone_id: str, auth_token: str) -> bool:
        """Verify if the requesting drone is a leader"""
        # For basic implementation, just check if the drone ID is in our leader set
        # In a more secure implementation, validate the auth_token cryptographically
        return drone_id in self.leader_drones

    def get_network_node_list(self) -> dict:
        """Get the list of all nodes and their certificates"""
        return self.issued_certificates

    def _get_name_attribute(self, name: x509.Name, oid: NameOID) -> Optional[str]:
        """Safely extract name attribute from certificate subject/issuer"""
        try:
            return name.get_attributes_for_oid(oid)[0].value
        except (IndexError, ValueError):
            return None

    def _ensure_pki_infrastructure(self):
        """Ensure PKI infrastructure exists, create if it doesn't"""
        ca_cert_path = self.base_dir / "ca" / "ca_cert.pem"
        ca_key_path = self.base_dir / "private" / "ca_key.pem"
        password_path = self.base_dir / ".secure" / "ca_password.bin"

        # Check if any required files are missing
        if not all([ca_cert_path.exists(), ca_key_path.exists(), password_path.exists()]):
            self.logger.info("PKI infrastructure not complete. Initializing...")
            pki_setup = PKISetup(output_dir=str(self.base_dir))
            pki_setup.setup_pki()
            self.logger.info("PKI infrastructure initialized successfully")
        else:
            self.logger.info("Using existing PKI infrastructure")

    def _load_pki_materials(self):
        """Load PKI materials from files"""
        try:
            # Load CA certificate
            ca_cert_path = self.base_dir / "ca" / "ca_cert.pem"
            with open(ca_cert_path, 'rb') as f:
                ca_cert_data = f.read()
                self.ca_cert = x509.load_pem_x509_certificate(ca_cert_data)
                self.ca_public_key = self.ca_cert.public_key()

            # Load CA private key
            ca_key_path = self.base_dir / "private" / "ca_key.pem"
            password_path = self.base_dir / ".secure" / "ca_password.bin"

            # Read password
            password = PKISetup.read_password_file(password_path)

            # Load private key
            with open(ca_key_path, 'rb') as f:
                self.ca_private_key = serialization.load_pem_private_key(
                    f.read(),
                    password=password
                )

            # Initialize CRL Manager
            crl_path = self.base_dir / "crl" / "drone_crl.json"
            self.crl_manager = CRLManager(self.config)
            if crl_path.exists():
                self.crl_manager.load_crl_from_file(str(crl_path))
            else:
                self.logger.warning("CRL file not found, initializing empty CRL")
                self.crl_manager.initialize_empty_crl(str(crl_path))

        except Exception as e:
            self.logger.error(f"Failed to load PKI materials: {str(e)}")
            raise

    def verify_device_identity(self, serial_number: str, eeprom_id: str) -> bool:
        """Verify the device's identity against allowed devices"""
        return (serial_number, eeprom_id) in self.allowed_devices

    """""Uncomment lines if using inital boostrapping phase"""""
    # def add_allowed_device(self, serial_number: str, eeprom_id: str):
    #     self.allowed_devices.add((serial_number, eeprom_id))

    # def remove_allowed_device(self, serial_number: str, eeprom_id: str):
    #     self.allowed_devices.discard((serial_number, eeprom_id))

    def verify_drone_certificate(self, cert_data: bytes) -> bool:
        """Verify a drone's certificate"""
        try:
            # First verify the signature
            if not self.crypto_utils.verify_certificate_signature(cert_data, self.ca_public_key):
                self.logger.warning("Certificate signature verification failed")
                return False

            # Load certificate
            cert = x509.load_pem_x509_certificate(cert_data)

            # Check if revoked
            if self.crl_manager.is_cert_revoked(str(cert.serial_number)):
                self.logger.warning("Certificate is revoked")
                return False

            # Check validity period
            now = datetime.now(timezone.utc)
            if now < cert.not_valid_before_utc or now > cert.not_valid_after_utc:
                self.logger.warning("Certificate is not within its validity period")
                return False

            # Check key usage extension
            try:
                key_usage = cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE)
                if key_usage:
                    key_usage_value = key_usage.value
                    required_usages = {
                        'digital_signature': True,
                        'key_encipherment': True
                    }

                    for usage, required in required_usages.items():
                        if getattr(key_usage_value, usage) != required:
                            self.logger.warning(f"Certificate missing required key usage: {usage}")
                            return False
            except x509.ExtensionNotFound:
                self.logger.warning("Certificate missing key usage extension")
                return False

            return True

        except Exception as e:
            self.logger.error(f"Certificate verification failed: {str(e)}")
            return False

    def format_certificate_response(self, cert: x509.Certificate, serial_number: str, eeprom_id: str) -> Dict[str, Any]:
        key_usage = cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE).value
        return {
            'certificate_data': {
                'pem': cert.public_bytes(serialization.Encoding.PEM).decode('utf-8'),
                'serial_number': str(cert.serial_number),
                'public_key': cert.public_key().public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ).decode('utf-8'),
                'ca_public_key': self.ca_cert.public_bytes(
                    encoding=serialization.Encoding.PEM
                ).decode('utf-8')
            },
            'validity': {
                'not_before': cert.not_valid_before_utc.isoformat(),
                'not_after': cert.not_valid_after_utc.isoformat()
            },
            'subject': {
                'serial_number': serial_number,
                'eeprom_id': eeprom_id,
                'common_name': self._get_name_attribute(cert.subject, NameOID.COMMON_NAME)
            },
            'issuer': {
                'common_name': self._get_name_attribute(cert.issuer, NameOID.COMMON_NAME),
                'organization': self._get_name_attribute(cert.issuer, NameOID.ORGANIZATION_NAME)
            },
            'key_usage': {
                'digital_signature': key_usage.digital_signature,
                'key_encipherment': key_usage.key_encipherment
            },
            'metadata': {
                'issued_at': datetime.now(timezone.utc).isoformat(),
                'version': cert.version.name
            }
        }

    def register_leader(self, drone_id: str):
        self.leader_drones.add(drone_id)
        self.logger.info(f"Registered {drone_id} as a leader drone")

    def generate_certificate(self, csr: x509.CertificateSigningRequest, drone_id: str, manufacturer_id: str) -> x509.Certificate:
        builder = x509.CertificateBuilder()
        now = datetime.now(timezone.utc)
        builder = builder.serial_number(x509.random_serial_number())
        builder = builder.subject_name(csr.subject)
        builder = builder.issuer_name(self.ca_cert.subject)
        builder = builder.not_valid_before(now)
        builder = builder.not_valid_after(now + timedelta(minutes=self.cert_validity_minutes))
        builder = builder.public_key(csr.public_key())
        builder = builder.add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        builder = builder.add_extension(
            x509.KeyUsage(
                digital_signature=True, content_commitment=False,
                key_encipherment=True, data_encipherment=False,
                key_agreement=False, key_cert_sign=False,
                crl_sign=False, encipher_only=False,
                decipher_only=False
            ), critical=True)
        cert = builder.sign(private_key=self.ca_private_key, algorithm=hashes.SHA256())
        cert_data = {
            'certificate': cert.public_bytes(serialization.Encoding.PEM).decode('utf-8'),
            'drone_id': drone_id,
            'manufacturer_id': manufacturer_id,
            'issued_at': datetime.now(timezone.utc).isoformat(),
            'valid_until': (now + timedelta(minutes=self.cert_validity_minutes)).isoformat()
        }
        self.issued_certificates[drone_id] = cert_data

        return cert

    def run(self, host='0.0.0.0', port=5000):
        self.app.run(host=host, port=port)

    def stop(self):
        """Stop the GCS server and perform cleanup"""
        try:
            # Save current CRL state before shutdown
            crl_path = self.base_dir / "crl" / "drone_crl.json"
            self.crl_manager.save_crl_to_file(str(crl_path))
            self.logger.info("Saved CRL state")

            # Clear sensitive data from memory
            self.private_key = None
            self.public_key = None
            self.ca_private_key = None
            self.allowed_devices.clear()

            # Shut down Flask server
            func = request.environ.get('werkzeug.server.shutdown')
            if func is None:
                self.logger.warning("Not running with Werkzeug server, Flask shutdown may not be clean")
            else:
                func()
                self.logger.info("Flask server shutdown initiated")

            self.logger.info("GCS server stopped successfully")

        except Exception as e:
            self.logger.error(f"Error during GCS shutdown: {str(e)}")
            raise
