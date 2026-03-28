#!/usr/bin/env python3
"""jwt_decode - Decode JWT tokens (no verification)."""
import sys, json, base64
def b64d(s):
    s += "=" * (4 - len(s) % 4)
    return base64.urlsafe_b64decode(s)
def decode(token):
    parts = token.split(".")
    if len(parts) != 3: raise ValueError("Invalid JWT")
    header = json.loads(b64d(parts[0]))
    payload = json.loads(b64d(parts[1]))
    return header, payload
if __name__ == "__main__":
    if len(sys.argv) < 2: print("Usage: jwt_decode <token>"); sys.exit(1)
    h, p = decode(sys.argv[1])
    print("Header:", json.dumps(h, indent=2))
    print("Payload:", json.dumps(p, indent=2))
    if "exp" in p:
        from datetime import datetime, timezone
        print(f"Expires: {datetime.fromtimestamp(p['exp'], tz=timezone.utc)}")
