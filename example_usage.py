"""Example usage for Enterprise Webhook HMAC-SHA256 Signature & Replay Attack Sentinel."""
from client import WebhookReplaySentinel
import hmac, hashlib

if __name__ == "__main__":
    secret = "whsec_test_secret_123"
    t_now = 1760000000
    p = '{"event": "subscription.renewed"}'
    sig = hmac.new(secret.encode(), f"{t_now}.{p}".encode(), hashlib.sha256).hexdigest()
    res = WebhookReplaySentinel.verify_webhook(p, secret, sig, t_now, t_now)
    print("Webhook Valid:", res["valid"], "Status:", res["status"])
