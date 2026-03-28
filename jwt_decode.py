#!/usr/bin/env python3
"""jwt_decode — Decode and inspect JWT tokens without verification.

Parse header, payload, and signature. Check expiration. Pretty-print claims.

Usage:
    jwt_decode.py decode eyJhbGciOi...
    jwt_decode.py decode eyJhbGciOi... --verify-exp
    jwt_decode.py header eyJhbGciOi...
    jwt_decode.py claims eyJhbGciOi...
    echo "eyJ..." | jwt_decode.py decode -
"""

import sys
import json
import base64
import time
import argparse
from datetime import datetime, timezone


def b64url_decode(s: str) -> bytes:
    s += '=' * (4 - len(s) % 4)
    return base64.urlsafe_b64decode(s)


def decode_jwt(token: str) -> dict:
    token = token.strip()
    parts = token.split('.')
    if len(parts) != 3:
        raise ValueError(f'Invalid JWT: expected 3 parts, got {len(parts)}')
    
    header = json.loads(b64url_decode(parts[0]))
    payload = json.loads(b64url_decode(parts[1]))
    sig_bytes = b64url_decode(parts[2])
    
    return {
        'header': header,
        'payload': payload,
        'signature': sig_bytes.hex(),
        'signature_length': len(sig_bytes),
    }


def format_timestamp(ts):
    """Convert Unix timestamp to human-readable."""
    try:
        dt = datetime.fromtimestamp(ts, tz=timezone.utc)
        return dt.strftime('%Y-%m-%d %H:%M:%S UTC')
    except (TypeError, ValueError, OSError):
        return str(ts)


KNOWN_CLAIMS = {
    'iss': 'Issuer',
    'sub': 'Subject',
    'aud': 'Audience',
    'exp': 'Expiration',
    'nbf': 'Not Before',
    'iat': 'Issued At',
    'jti': 'JWT ID',
    'name': 'Name',
    'email': 'Email',
    'role': 'Role',
    'roles': 'Roles',
    'scope': 'Scope',
    'azp': 'Authorized Party',
    'nonce': 'Nonce',
    'at_hash': 'Access Token Hash',
    'c_hash': 'Code Hash',
    'auth_time': 'Auth Time',
    'acr': 'Auth Context Class',
    'amr': 'Auth Methods',
    'sid': 'Session ID',
}

TIME_CLAIMS = {'exp', 'nbf', 'iat', 'auth_time'}


def print_decoded(decoded: dict, verify_exp: bool = False):
    header = decoded['header']
    payload = decoded['payload']
    
    print('=== HEADER ===')
    print(json.dumps(header, indent=2))
    
    print('\n=== PAYLOAD ===')
    for key, value in payload.items():
        label = KNOWN_CLAIMS.get(key, key)
        if key in TIME_CLAIMS and isinstance(value, (int, float)):
            human = format_timestamp(value)
            print(f'  {label} ({key}): {value} → {human}')
        else:
            val_str = json.dumps(value) if isinstance(value, (dict, list)) else str(value)
            print(f'  {label} ({key}): {val_str}')
    
    print(f'\n=== SIGNATURE ===')
    print(f'  Algorithm: {header.get("alg", "unknown")}')
    print(f'  Length: {decoded["signature_length"]} bytes')
    print(f'  Hex: {decoded["signature"][:64]}{"..." if len(decoded["signature"]) > 64 else ""}')
    
    # Expiration check
    if 'exp' in payload:
        now = time.time()
        exp = payload['exp']
        if now > exp:
            elapsed = now - exp
            print(f'\n⚠️  EXPIRED {elapsed:.0f}s ago ({format_timestamp(exp)})')
            if verify_exp:
                sys.exit(1)
        else:
            remaining = exp - now
            if remaining < 300:
                print(f'\n⏳ Expires in {remaining:.0f}s')
            elif remaining < 3600:
                print(f'\n✅ Expires in {remaining/60:.0f}m')
            else:
                print(f'\n✅ Expires in {remaining/3600:.1f}h')
    
    if 'nbf' in payload:
        now = time.time()
        nbf = payload['nbf']
        if now < nbf:
            print(f'⏳ Not valid for another {nbf - now:.0f}s')


def read_token(args) -> str:
    if hasattr(args, 'token') and args.token:
        if args.token == '-':
            return sys.stdin.read().strip()
        return args.token
    return sys.stdin.read().strip()


def cmd_decode(args):
    token = read_token(args)
    decoded = decode_jwt(token)
    if args.json:
        print(json.dumps({'header': decoded['header'], 'payload': decoded['payload']}, indent=2))
    else:
        print_decoded(decoded, verify_exp=args.verify_exp)


def cmd_header(args):
    token = read_token(args)
    decoded = decode_jwt(token)
    print(json.dumps(decoded['header'], indent=2))


def cmd_claims(args):
    token = read_token(args)
    decoded = decode_jwt(token)
    print(json.dumps(decoded['payload'], indent=2))


def main():
    p = argparse.ArgumentParser(description='JWT token decoder and inspector')
    p.add_argument('--json', action='store_true')
    sub = p.add_subparsers(dest='cmd', required=True)

    sd = sub.add_parser('decode', help='Decode and display JWT')
    sd.add_argument('token', nargs='?', default='-')
    sd.add_argument('--verify-exp', action='store_true', help='Exit 1 if expired')
    sd.set_defaults(func=cmd_decode)

    sh = sub.add_parser('header', help='Show only header')
    sh.add_argument('token', nargs='?', default='-')
    sh.set_defaults(func=cmd_header)

    sc = sub.add_parser('claims', help='Show only payload claims')
    sc.add_argument('token', nargs='?', default='-')
    sc.set_defaults(func=cmd_claims)

    args = p.parse_args()
    args.func(args)


if __name__ == '__main__':
    main()
