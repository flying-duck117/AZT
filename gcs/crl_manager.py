import json
import logging
import os
from datetime import datetime, timedelta
import threading
from typing import Set, Dict

class CRLManager:
    def __init__(self, config):
        self.config = config
        self.revoked_certificates = set()  
        self.last_update = datetime.utcnow()
        self._lock = threading.Lock()
        self.logger = logging.getLogger('CRL_Manager')
        
        # Ensure CRL directory exists
        crl_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'certs', 'crl')
        os.makedirs(crl_dir, exist_ok=True)
        
        # Default CRL file path
        self.crl_file_path = os.path.join(crl_dir, 'drone_crl.json')
        
        # Load existing CRL data if available
        if os.path.exists(self.crl_file_path):
            self.load_crl_from_file(self.crl_file_path)
        else:
            self.initialize_empty_crl(self.crl_file_path)
            
    def add_revoked_cert(self, serial_number: str) -> None:
        """Add a certificate to the revocation list"""
        with self._lock:
            self.revoked_certificates.add(serial_number)  
            self.last_update = datetime.utcnow()
            # Automatically save the updated CRL
            self.save_crl_to_file(self.crl_file_path)
            self.logger.info(f"Added certificate {serial_number[:15]}... to CRL")
    
    def is_cert_revoked(self, serial_number: str) -> bool:
        """Check if a certificate is revoked"""
        with self._lock:
            is_revoked = serial_number in self.revoked_certificates
            self.logger.debug(f"Certificate {serial_number[:15]}... revocation status: {is_revoked}")
            return is_revoked
    
    def get_all_revoked_certs(self) -> Set[str]:
        """Get all revoked certificates"""
        with self._lock:
            return self.revoked_certificates.copy()
    
    def load_crl_from_file(self, filepath: str) -> None:
        """Load CRL from a file"""
        try:
            with open(filepath, 'r') as f:
                data = json.load(f)
                with self._lock:
                    self.revoked_certificates = set(data.get('revoked_certificates', []))  
                    self.last_update = datetime.fromisoformat(data.get('last_update', datetime.utcnow().isoformat()))
            self.logger.info(f"Loaded CRL from {filepath} with {len(self.revoked_certificates)} entries")
        except Exception as e:
            self.logger.error(f"Failed to load CRL from {filepath}: {str(e)}")
    
    def save_crl_to_file(self, filepath: str) -> None:
        """Save CRL to a file"""
        try:
            with self._lock:
                data = {
                    'version': '1.0',
                    'last_update': self.last_update.isoformat(),
                    'next_update': (self.last_update + timedelta(days=1)).isoformat(),
                    'revoked_certificates': list(self.revoked_certificates)  
                }
                with open(filepath, 'w') as f:
                    json.dump(data, f, indent=4)
            self.logger.info(f"Saved CRL to {filepath} with {len(self.revoked_certificates)} entries")
        except Exception as e:
            self.logger.error(f"Failed to save CRL to {filepath}: {str(e)}")

    def initialize_empty_crl(self, filepath: str) -> None:
        """Create a new empty CRL file with correct format"""
        try:
            now = datetime.utcnow()
            crl_data = {
                'version': '1.0',
                'last_update': now.isoformat(),
                'next_update': (now + timedelta(days=1)).isoformat(),
                'revoked_certificates': []
            }
            
            with open(filepath, 'w') as f:
                json.dump(crl_data, f, indent=4)
            
            self.logger.info(f"Initialized empty CRL at {filepath}")
        except Exception as e:
            self.logger.error(f"Failed to initialize empty CRL at {filepath}: {str(e)}")
    
    def remove_cert_from_crl(self, serial_number: str) -> bool:
        """Remove a certificate from the CRL (e.g., for testing or if revoked by mistake)"""
        with self._lock:
            if serial_number in self.revoked_certificates:
                self.revoked_certificates.remove(serial_number)
                self.last_update = datetime.utcnow()
                self.save_crl_to_file(self.crl_file_path)
                self.logger.info(f"Removed certificate {serial_number[:15]}... from CRL")
                return True
            else:
                self.logger.warning(f"Certificate {serial_number[:15]}... not found in CRL")
                return False
    
    def get_crl_status(self) -> Dict:
        """Get current CRL status information"""
        with self._lock:
            return {
                'last_update': self.last_update.isoformat(),
                'next_update': (self.last_update + timedelta(days=1)).isoformat(),
                'revoked_count': len(self.revoked_certificates)
            }