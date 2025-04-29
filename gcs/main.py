import logging
from gcs import GCS
import sys

PORT_NUMBER = 65456
BRDCST_PORT = 65467
ADHOC_IFACE = "wlan0"

def main():
    ADHOC_IP = "192.168.1.99"
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    logger = logging.getLogger('PKI_SERVER')
    
    try:
        gcs = GCS(base_dir="certs")
        logger.info("PKI server initialized")
        
        logger.info("Starting PKI server...")
        gcs.run(host='0.0.0.0', port=5000)
        
    except KeyboardInterrupt:
        logger.info("Shutting down PKI server...")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Fatal error: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()