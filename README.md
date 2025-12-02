# JWT Decoder & Verifier (Bash)

Two Bash scripts to **decode and verify JWT tokens**, compatible with Linux and macOS.  
They support:

- HMAC algorithms: HS256, HS384, HS512  
- RSA algorithms: RS256, RS384, RS512  
- Verification via a local key or JWKS endpoint (OpenID Connect)  
- Pretty output using `jq`  

---

## Requirements

- **Bash 4+**
- **jq** for JSON parsing
- **curl** for fetching JWKS
- **openssl** for RSA verification
- **python3 + cryptography** for converting JWKS to PEM (optional, recommended for RS256)

On macOS, `base64 -d` or `openssl base64 -d` must work.

---

## Installation

Clone the repo or place the scripts on your system:

```bash
git clone <repo-url>
cd jwt-decode-bash
chmod +x jwt-linux.sh jwt-mac.sh
```

--- 

## Usage

### General Syntax

```bash
./jwt-<linux|mac>.sh <JWT> [options]
```

### Options

| Option                   | Description                                            |
| ------------------------ | ------------------------------------------------------ |
| `--key <file_or_secret>` | Secret key or file containing the key                  |
| `--pub`                  | Indicates the provided key is a public key (RSA)       |
| `--raw-key`              | Use the key text directly, not a file                  |
| `--jwks <url>`           | JWKS endpoint (OpenID Connect) to fetch the public key |
| `--no-verify`            | Decode only, skip signature verification               |
| `-h`, `--help`           | Show help message                                      |

--- 

## Examples

### 1. Decode a JWT without verification

```bash
./jwt-linux.sh eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...
```

### 2. Verify HMAC

```bash
./jwt-linux.sh <JWT> --key "mysecret"
```

### 3. Verify RSA locally

```bash
./jwt-linux.sh <JWT> --key /path/to/pub.pem --pub
```

### 4. Verify via OpenID Connect JWKS

```bash
./jwt-linux.sh <JWT> --jwks https://my-server/realms/master/protocol/openid-connect/certs
```

--- 

## Features

- Automatic cleaning of Base64URL segments (removes newlines, spaces) for macOS and Linux
- Safe decoding of header, payload, and signature
- Full JWKS support: fetches the public key matching the token kid
- Structured output with jq
- Security: constant-time comparison for HMAC signatures

--- 

## Notes

- macOS script uses base64 -d and OpenSSL compatible with BSD/GNU
- Linux script is compatible with standard GNU/Linux
- RS256 verification requires a PEM public key or JWKS
- Script will fail if the JWT is incomplete or malformed

--- 

## Example Output

```
=== JWT Decode ===
Header:
{
  "alg": "RS256",
  "typ": "JWT",
  "kid": "SwZpv0Hk0QeF3J7kjlFgSxiqVIlFa1zjiuRDFFQa1xQ"
}
Payload:
{
  "sub": "user123",
  "name": "John Doe",
  "iat": 1699999999,
  "exp": 1700003599
}
Signature: OK (RSA RS256)
```
