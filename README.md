# jwt_decode

Decode and inspect JWT tokens without verification. Parse headers, claims, check expiration.

## Usage

```bash
# Decode a JWT
python3 jwt_decode.py decode eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c

# Just the header
python3 jwt_decode.py header <token>

# Just the claims
python3 jwt_decode.py claims <token>

# Pipe from stdin
echo "<token>" | python3 jwt_decode.py decode -

# Exit 1 if expired
python3 jwt_decode.py decode <token> --verify-exp
```

## Features
- Decodes header, payload, signature
- Human-readable timestamps for exp/iat/nbf
- Expiration warnings
- Known claim labels (iss, sub, aud, etc.)
- JSON output mode

## Zero dependencies. Single file. Python 3.8+.
