#!/usr/bin/env bash
set -euo pipefail

die(){ echo "ERROR: $*" >&2; exit 1; }

# ----------------- Helpers Base64URL -----------------
_b64url_pad() {
  local s="$1"
  local mod=$(( ${#s} % 4 ))
  case $mod in
    2) s="${s}==";;
    3) s="${s}=";;
    1) s="${s}===";;
  esac
  echo "$s"
}

b64url_decode_to_file(){
  local s="$1" out="$2"
  s="${s//-/+}"
  s="${s//_/\/}"
  s="$(_b64url_pad "$s")"
  base64 -d <<<"$s" > "$out"
}

b64url_to_bin(){
  local s="$1"; s="${s//-/+}"; s="${s//_/\/}"; s="$(_b64url_pad "$s")"
  base64 -d <<<"$s"
}

b64url_encode_from_file(){
  local file="$1"
  local b64
  b64=$(base64 -w 0 < "$file")
  b64="${b64//+/-}"
  b64="${b64//\//_}"
  b64="${b64//=}"
  echo "$b64"
}

safe_cmp(){
  local a="$1" b="$2"
  [[ "${#a}" -eq "${#b}" ]] || return 1
  local i res=0
  for ((i=0;i<${#a};i++)); do
    res=$(( res | ( $(printf '%d' "'${a:$i:1}") ^ $(printf '%d' "'${b:$i:1}") ) ))
  done
  (( res == 0 ))
}

# ----------------- Arguments -----------------
TOKEN=""
KEY=""
KEY_IS_PUB=false
RAW_KEY=false
DO_VERIFY=true
JWKS_URL=""

if [ "${1-}" = "-" ]; then
  TOKEN="$(tr -d '\n' <&0)"
  shift || true
elif [ "${1-}" != "" ] && [[ "${1-}" != --* ]]; then
  TOKEN="$1"; shift || true
else
  if [ ! -t 0 ]; then TOKEN="$(tr -d '\n' <&0)"; fi
fi

while (( "$#" )); do
  case "$1" in
    --key) KEY="$2"; shift 2;;
    --pub) KEY_IS_PUB=true; shift;;
    --raw-key) RAW_KEY=true; shift;;
    --jwks) JWKS_URL="$2"; shift 2;;
    --no-verify) DO_VERIFY=false; shift;;
    -h|--help)
      echo "Usage: $0 <jwt> [--key secret|pubkeyfile] [--pub] [--raw-key] [--jwks URL]"
      exit 0;;
    *) die "Unknown option $1";;
  esac
done

[ -n "$TOKEN" ] || die "No token provided"

IFS='.' read -r H64 P64 S64 <<< "$TOKEN" || die "Invalid JWT"

TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

b64url_decode_to_file "$H64" "$TMPDIR/header.json"
b64url_decode_to_file "$P64" "$TMPDIR/payload.json"
b64url_decode_to_file "$S64" "$TMPDIR/signature.bin"

ALG=$(jq -r '.alg // empty' < "$TMPDIR/header.json")
KID=$(jq -r '.kid // empty' < "$TMPDIR/header.json")

echo "=== JWT Decode ==="
echo "Header:"; jq . "$TMPDIR/header.json"; echo
echo "Payload:"; jq . "$TMPDIR/payload.json"; echo

[ "$DO_VERIFY" = true ] || { echo "Verification skipped"; exit 0; }

SIGNED="${H64}.${P64}"
printf "%s" "$SIGNED" > "$TMPDIR/signed.txt"

# ----------------- JWKS support -----------------
if [ -n "$JWKS_URL" ]; then
  echo "Fetching JWKS from: $JWKS_URL"
  curl -s "$JWKS_URL" -o "$TMPDIR/jwks.json" || die "Failed to fetch JWKS"
  [ -n "$KID" ] || die "JWT header missing kid"

  KEYOBJ=$(jq -r --arg kid "$KID" '.keys[] | select(.kid==$kid)' "$TMPDIR/jwks.json") || die "No key matching kid=$KID"
  KTY=$(jq -r '.kty' <<<"$KEYOBJ")
  N=$(jq -r '.n' <<<"$KEYOBJ")
  E=$(jq -r '.e' <<<"$KEYOBJ")
  [ "$KTY" = "RSA" ] || die "Only RSA keys supported"

  python3 - <<EOF
import base64, json
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

n = int.from_bytes(base64.urlsafe_b64decode("$N" + "=="), "big")
e = int.from_bytes(base64.urlsafe_b64decode("$E" + "=="), "big")
pub = rsa.RSAPublicNumbers(e, n).public_key()
pem = pub.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)
Path("$TMPDIR/pub.pem").write_bytes(pem)
EOF
  KEYFILE="$TMPDIR/pub.pem"
fi

# ----------------- Key from CLI -----------------
if [ -z "${KEYFILE-}" ]; then
  [ -n "$KEY" ] || die "No key provided"
  if $RAW_KEY; then
    printf "%s" "$KEY" > "$TMPDIR/hmac.key"; KEYFILE="$TMPDIR/hmac.key"
  elif $KEY_IS_PUB; then
    KEYFILE="$KEY"
  else
    if [ -f "$KEY" ]; then KEYFILE="$KEY"
    else printf "%s" "$KEY" > "$TMPDIR/hmac.key"; KEYFILE="$TMPDIR/hmac.key"; fi
  fi
fi

# ----------------- Verification -----------------
case "$ALG" in
  HS256|HS384|HS512)
    DIG="${ALG/HS/sha}"
    openssl dgst -"$DIG" -mac HMAC -macopt "key:$(cat "$KEYFILE")" -binary < "$TMPDIR/signed.txt" > "$TMPDIR/hmac.bin"
    CALC=$(b64url_encode_from_file "$TMPDIR/hmac.bin")
    if safe_cmp "$CALC" "$S64"; then echo "Signature: OK (HMAC $ALG)"
    else echo "Signature: INVALID (HMAC $ALG)"; exit 1; fi
    ;;
  RS256|RS384|RS512)
    DIG="-sha${ALG:2}"
    if openssl dgst "$DIG" -verify "$KEYFILE" -signature "$TMPDIR/signature.bin" "$TMPDIR/signed.txt" >/dev/null 2>&1
    then echo "Signature: OK (RSA $ALG)"
    else echo "Signature: INVALID (RSA $ALG)"; exit 1; fi
    ;;
  *)
    die "Unsupported alg: $ALG"
    ;;
esac
