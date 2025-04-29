#!/usr/bin/env python3
"""
Test script for verifying GCS connectivity and certificate setup
"""

import argparse
import json
import os
import sys
import requests
import logging
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from datetime import datetime, timezone
import socket

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('GCS_Test')

def parse_args():
    parser = argparse.ArgumentParser(description='GCS PKI Connection Tester')
    parser.add_argument('--host', default='localhost', help='GCS host address')
    parser.add_argument('--port', type=int, default=5000, help='GCS port number')
    parser.add_argument('--serial', default='TEST_SERIAL', help='Test device serial number')
    parser.add_argument('--eeprom', default='TEST_EEPROM', help='Test device EEPROM ID')
    parser.add_argument('--check-allowed', action='store_true', help='Check if the device is in the allowed list')
    parser.add_argument('--verbose', action='store_true', help='Enable verbose output')
    return parser.parse_args()

def test_network_connectivity(host, port):
    """Test basic network connectivity to the GCS server"""
    logger.info(f"Testing network connectivity to {host}:{port}...")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        result = s.connect_ex((host, port))
        s.close()

        if result == 0:
            logger.info(f"✓ Successfully connected to {host}:{port}")
            return True
        else:
            logger.error(f"✗ Failed to connect to {host}:{port}")
            return False
    except Exception as e:
        logger.error(f"✗ Connection error: {str(e)}")
        return False

def generate_test_csr(serial_number):
    """Generate a test CSR for certificate request testing"""
    # Generate a key pair
    private_key = ec.generate_private_key(ec.SECP256R1())

    # Create a CSR
    builder = x509.CertificateSigningRequestBuilder()

    # Add the common name
    name = x509.Name([
        x509.NameAttribute(x509.NameOID.COMMON_NAME, serial_number)
    ])
    builder = builder.subject_name(name)

    # Sign the CSR with the private key
    csr = builder.sign(private_key, hashes.SHA256())

    # Serialize to PEM format
    csr_pem = csr.public_bytes(encoding=serialization.Encoding.PEM).decode('utf-8')

    return csr_pem, private_key

def check_allowed_devices(device_serial, device_eeprom, host, port):
    """Send a test certificate request to see if the device is allowed"""
    logger.info(f"Testing if device {device_serial} is in the allowed list...")

    # Generate a test CSR
    csr_pem, _ = generate_test_csr(device_serial)

    # Prepare the request
    url = f"http://{host}:{port}/request_certificate"
    headers = {"Content-Type": "application/json"}
    payload = {
        "serial_number": device_serial,
        "eeprom_id": device_eeprom,
        "csr": csr_pem
    }

    try:
        response = requests.post(url, headers=headers, json=payload, timeout=5)

        if response.status_code == 200:
            logger.info(f"✓ Device {device_serial} is allowed! Certificate obtained successfully.")
            return True
        elif response.status_code == 403:
            logger.warning(f"✗ Device {device_serial} is NOT in the allowed list.")
            # Try to parse the error response
            try:
                error_data = response.json()
                if 'allowed_devices_count' in error_data:
                    logger.info(f"  GCS has {error_data['allowed_devices_count']} allowed devices.")
            except:
                pass
            return False
        else:
            logger.error(f"✗ Unexpected response: HTTP {response.status_code}")
            try:
                error_data = response.json()
                logger.error(f"  Error message: {error_data.get('message', 'Unknown error')}")
            except:
                logger.error(f"  Response: {response.text[:100]}")
            return False
    except Exception as e:
        logger.error(f"✗ Request failed: {str(e)}")
        return False

def check_allowed_devices_file(device_serial, device_eeprom):
    """Check if the device is in the allowed_devices.json file directly"""
    filename = "allowed_devices.json"
    if not os.path.exists(filename):
        logger.error(f"✗ File {filename} not found.")
        return False

    try:
        with open(filename, 'r') as f:
            devices = json.load(f)

        for device in devices:
            if device.get('serial_number') == device_serial and device.get('eeprom_id') == device_eeprom:
                logger.info(f"✓ Device {device_serial} is in the allowed_devices.json file.")
                return True

        logger.warning(f"✗ Device {device_serial} is NOT in the allowed_devices.json file.")
        logger.info(f"  The file contains {len(devices)} devices.")
        return False
    except Exception as e:
        logger.error(f"✗ Error reading allowed_devices.json: {str(e)}")
        return False

def main():
    args = parse_args()

    if args.verbose:
        logger.setLevel(logging.DEBUG)

    # Print test configuration
    logger.info("=== GCS PKI Connection Test ===")
    logger.info(f"Target: {args.host}:{args.port}")
    logger.info(f"Test device: Serial={args.serial}, EEPROM={args.eeprom}")

    # Check network connectivity
    if not test_network_connectivity(args.host, args.port):
        logger.error("✗ Network connectivity test failed. Please check if GCS server is running.")
        return 1

    # Check if device is in allowed list
    if args.check_allowed:
        # First check the file directly
        check_allowed_devices_file(args.serial, args.eeprom)

        # Then check via API
        if not check_allowed_devices(args.serial, args.eeprom, args.host, args.port):
            logger.warning(f"To add the device to the allowed list, edit allowed_devices.json:")
            logger.warning(f'  {"{"}"serial_number": "{args.serial}", "eeprom_id": "{args.eeprom}"{"}"}')
            return 1

    logger.info("=== All tests completed ===")
    return 0

if __name__ == "__main__":
    sys.exit(main())
