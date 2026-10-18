"""MCP server for Enterprise Webhook HMAC-SHA256 Signature & Replay Attack Sentinel."""
import sys
import json
from client import WebhookReplaySentinel

def handle_request(req):
    method = req.get("method")
    if method == "tools/list":
        return {
            "tools": [{
                "name": "verify_webhook_signature",
                "description": "Verifies cryptographic HMAC-SHA256 signatures and checks timestamp drift to prevent replay attacks",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "payload": {"type": "string"},
                        "secret": {"type": "string"},
                        "signature": {"type": "string"},
                        "timestamp": {"type": "integer"}
                    },
                    "required": ["payload", "secret", "signature", "timestamp"]
                }
            }]
        }
    elif method == "tools/call":
        params = req.get("params", {})
        if params.get("name") == "verify_webhook_signature":
            args = params.get("arguments", {})
            res = WebhookReplaySentinel.verify_webhook(
                args.get("payload", ""),
                args.get("secret", ""),
                args.get("signature", ""),
                int(args.get("timestamp", 0))
            )
            return {"content": [{"type": "text", "text": json.dumps(res, indent=2)}]}
    return {"error": "Method not found"}

if __name__ == "__main__":
    for line in sys.stdin:
        if line.strip():
            print(json.dumps(handle_request(json.loads(line))))
            sys.stdout.flush()
