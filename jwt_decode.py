#!/usr/bin/env python3
"""jwt_decode - Decode JWT tokens."""
import sys, argparse, json, base64

def b64_decode(s):
    s += "=" * (4 - len(s) % 4)
    return base64.urlsafe_b64decode(s)

def decode_jwt(token):
    parts = token.split(".")
    if len(parts) != 3:
        return {"error": "Invalid JWT format"}
    header = json.loads(b64_decode(parts[0]))
    payload = json.loads(b64_decode(parts[1]))
    return {"header": header, "payload": payload, "signature": parts[2][:20] + "..."}

def main():
    p = argparse.ArgumentParser(description="JWT decoder")
    p.add_argument("token", help="JWT token")
    p.add_argument("--raw", action="store_true", help="Raw output")
    args = p.parse_args()
    result = decode_jwt(args.token)
    print(json.dumps(result, indent=2))

if __name__ == "__main__": main()
