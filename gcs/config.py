from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import List, Optional

@dataclass
class PKIConfig:
    """Configuration parameters for the PKI system"""
    VALID_KEY_USAGES = ['digitalSignature', 'keyEncipherment']
    MAX_CERT_VALIDITY_DAYS = 365
    MIN_KEY_SIZE = 256  # for ECDSA P-256
    SUPPORTED_ALGORITHMS = ['ES256']  # ECDSA with SHA-256
    CRL_UPDATE_INTERVAL = timedelta(hours=24)
    
    BOOTSTRAP_DURATION = timedelta(minutes=2)  # Duration of bootstrapping phase
    BOOTSTRAP_START_TIME: Optional[datetime] = None  # Will be set when PKI is initialized
    
    def is_in_bootstrap_phase(self) -> bool:
        """Check if current time is within bootstrap phase"""
        if self.BOOTSTRAP_START_TIME is None:
            return False
            
        now = datetime.now(timezone.utc)
        bootstrap_end = self.BOOTSTRAP_START_TIME + self.BOOTSTRAP_DURATION
        return self.BOOTSTRAP_START_TIME <= now <= bootstrap_end
    
    def get_bootstrap_remaining_time(self) -> Optional[timedelta]:
        """Get remaining time in bootstrap phase"""
        if self.BOOTSTRAP_START_TIME is None:
            return None
            
        now = datetime.now(timezone.utc)
        bootstrap_end = self.BOOTSTRAP_START_TIME + self.BOOTSTRAP_DURATION
        
        if now > bootstrap_end:
            return timedelta(0)
        return bootstrap_end - now