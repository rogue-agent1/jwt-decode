#!/usr/bin/env python3
"""jwt_decode - Decode and inspect JWT tokens (no verification)."""
import sys,json,base64,time
def b64dec(s):
    s+="="*(4-len(s)%4);return base64.urlsafe_b64decode(s)
def decode(token):
    parts=token.split(".")
    if len(parts)!=3:raise ValueError("Invalid JWT")
    header=json.loads(b64dec(parts[0]));payload=json.loads(b64dec(parts[1]))
    return{"header":header,"payload":payload,"signature":parts[2]}
def check_expiry(payload):
    exp=payload.get("exp")
    if not exp:return"no expiry"
    now=time.time();remaining=exp-now
    if remaining<0:return f"EXPIRED {-remaining:.0f}s ago"
    return f"valid for {remaining:.0f}s"
if __name__=="__main__":
    if len(sys.argv)<2:print("Usage: jwt_decode.py <token>");sys.exit(1)
    token=sys.argv[1];d=decode(token)
    print("Header:");print(json.dumps(d["header"],indent=2))
    print("\nPayload:");print(json.dumps(d["payload"],indent=2))
    print(f"\nExpiry: {check_expiry(d['payload'])}")
    print(f"Signature: {d['signature'][:20]}...")
