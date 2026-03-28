#!/usr/bin/env python3
"""JWT token decoder (no verification, decode only)."""
import sys, base64, json
from datetime import datetime

def b64decode_pad(s):
    s += '=' * (4 - len(s) % 4)
    return base64.urlsafe_b64decode(s)

def decode_jwt(token):
    parts = token.strip().split('.')
    if len(parts) != 3:
        print("Invalid JWT (expected 3 parts)"); return
    header = json.loads(b64decode_pad(parts[0]))
    payload = json.loads(b64decode_pad(parts[1]))
    return header, payload

def format_timestamp(ts):
    try: return datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
    except: return str(ts)

if __name__ == '__main__':
    if len(sys.argv) < 2: print("Usage: jwt_decode.py <token>"); sys.exit(1)
    token = sys.argv[1]
    result = decode_jwt(token)
    if not result: sys.exit(1)
    header, payload = result
    print("Header:")
    print(json.dumps(header, indent=2))
    print("\nPayload:")
    print(json.dumps(payload, indent=2))
    # Show timestamps
    for field in ['iat','exp','nbf']:
        if field in payload:
            print(f"\n  {field}: {format_timestamp(payload[field])}")
    if 'exp' in payload:
        import time
        remaining = payload['exp'] - time.time()
        print(f"  Status: {'EXPIRED' if remaining < 0 else f'Valid ({int(remaining)}s remaining)'}")
