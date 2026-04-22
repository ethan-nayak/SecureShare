import logging
import json
import os
from datetime import datetime

os.makedirs("logs", exist_ok=True)

class SecurityLogger:
    def __init__(self):
        self.logger = logging.getLogger("security")
        self.logger.setLevel(logging.INFO)

        # Avoid adding duplicate handlers if reloaded
        if not self.logger.handlers:
            handler = logging.FileHandler("logs/security.log")
            formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)

    def log_event(self, event_type, user_id=None, details=None, severity="INFO"):
        entry = {
            "timestamp":  datetime.utcnow().isoformat(),
            "event_type": event_type,
            "user_id":    user_id,
            "details":    details or {}
        }
        msg = json.dumps(entry)

        if severity == "CRITICAL":
            self.logger.critical(msg)
        elif severity == "ERROR":
            self.logger.error(msg)
        elif severity == "WARNING":
            self.logger.warning(msg)
        else:
            self.logger.info(msg)

security_log = SecurityLogger()