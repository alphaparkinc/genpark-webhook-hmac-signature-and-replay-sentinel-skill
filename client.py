"""Enterprise Webhook HMAC-SHA256 Signature & Replay Attack Sentinel.
100% Python Standard Library.
"""

import hmac
import hashlib
import time

class WebhookReplaySentinel:
    """Verifies cryptographic HMAC signatures, prevents replay attacks by checking timestamp drift, and audits webhook integrity."""

    @staticmethod
    def verify_webhook(payload: str, secret: str, signature: str, timestamp: int, current_time: int = None, max_drift_sec: int = 300) -> dict:
        if current_time is None:
            current_time = int(time.time())

        drift = abs(current_time - timestamp)
        if drift > max_drift_sec:
            return {
                "valid": False,
                "reason": f"Timestamp drift {drift}s exceeds maximum allowed ceiling of {max_drift_sec}s (Replay Attack Alert)",
                "tamper_detected": True
            }

        signed_payload = f"{timestamp}.{payload}".encode("utf-8")
        expected_sig = hmac.new(secret.encode("utf-8"), signed_payload, hashlib.sha256).hexdigest()

        is_valid = hmac.compare_digest(expected_sig, signature)
        return {
            "valid": is_valid,
            "drift_seconds": drift,
            "tamper_detected": not is_valid,
            "status": "SIGNATURE_VERIFIED" if is_valid else "INVALID_SIGNATURE"
        }
