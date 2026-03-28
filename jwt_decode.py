#!/usr/bin/env python3
"""JWT decoder (header + payload, no verification) from scratch."""
import sys,json

def b64url_decode(s):
    s += '=' * (4 - len(s) % 4)
    chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    lookup = {c:i for i,c in enumerate(chars)}
    out = []; i = 0
    while i < len(s):
        n = 0
        for j in range(4):
            n = (n << 6) | lookup.get(s[i+j] if i+j < len(s) else '=', 0)
        out.extend([(n>>16)&255, (n>>8)&255, n&255])
        i += 4
    # Remove padding bytes
    pad = s.count('=')
    return bytes(out[:len(out)-pad])

def decode_jwt(token):
    parts = token.strip().split('.')
    if len(parts) != 3:
        return None, None
    header = json.loads(b64url_decode(parts[0]))
    payload = json.loads(b64url_decode(parts[1]))
    return header, payload

def main():
    if "--demo" in sys.argv:
        # Example JWT (not secret, just for demo)
        token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        header, payload = decode_jwt(token)
        print("Header:", json.dumps(header, indent=2))
        print("Payload:", json.dumps(payload, indent=2))
    else:
        token = sys.argv[1] if len(sys.argv) > 1 else sys.stdin.read().strip()
        header, payload = decode_jwt(token)
        if header:
            print("Header:", json.dumps(header, indent=2))
            print("Payload:", json.dumps(payload, indent=2))
        else:
            print("Invalid JWT format")
if __name__=="__main__": main()
