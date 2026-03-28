#!/usr/bin/env python3
"""JWT decoder — base64url decode header+payload, check expiry."""
import sys, json, base64, time
def b64d(s):
    s += "=" * (4 - len(s) % 4)
    return json.loads(base64.urlsafe_b64decode(s))
def cli():
    if len(sys.argv) < 2: print("Usage: jwt_decode <token>"); sys.exit(1)
    parts = sys.argv[1].split(".")
    if len(parts) != 3: print("Invalid JWT"); sys.exit(1)
    header, payload = b64d(parts[0]), b64d(parts[1])
    print("Header:", json.dumps(header, indent=2))
    print("Payload:", json.dumps(payload, indent=2))
    if "exp" in payload:
        exp = payload["exp"]; now = time.time()
        print(f"Expires: {time.ctime(exp)} ({'EXPIRED' if exp < now else f'{int(exp-now)}s left'})")
    if "iat" in payload: print(f"Issued: {time.ctime(payload['iat'])}")
if __name__ == "__main__": cli()
