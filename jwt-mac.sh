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

##########################################################
#                    JWKS SUPPORT (MAC)
##########################################################
if [ -n "$JWKS_URL" ]; then
  echo "Fetching JWKS from: $JWKS_URL"
  curl -s "$JWKS_URL" -o "$TMPDIR/jwks.json" || die "Failed to fetch JWKS"
  [ -n "$KID" ] || die "JWT header missing kid"

  KEYOBJ=$(jq -r --arg kid "$KID" '.keys[] | select(.kid==$kid)' "$TMPDIR/jwks.json") || die "No key matching kid=$KID"
  KTY=$(jq -r '.kty' <<<"$KEYOBJ")
  N=$(jq -r '.n' <<<"$KEYOBJ")
  E=$(jq -r '.e' <<<"$KEYOBJ")
  [ "$KTY" = "RSA" ] || die "Only RSA keys supported"

  # ---- decode n,e into binary ----
  b64url_to_bin "$N" > "$TMPDIR/mod.bin"
  b64url_to_bin "$E" > "$TMPDIR/exp.bin"

  # ---- ASN.1 helpers ----
  asn1_len() {
    local L=$1
    if (( L < 128 )); then printf "%02X" "$L"
    else
      local hex=$(printf "%X" "$L")
      local nb=$(( ${#hex} / 2 ))
      printf "%02X%s" $((0x80 + nb)) "$hex"
    fi
  }

  asn1_int() {
    local file="$1"
    local size=$(wc -c < "$file" | tr -d ' ')
    printf "02%s" "$(asn1_len "$size")"
    xxd -p "$file" | tr -d '\n'
  }

  # ---- Build RSAPublicKey = SEQUENCE { modulus, exponent } ----
  MOD_HEX=$(asn1_int "$TMPDIR/mod.bin")
  EXP_HEX=$(asn1_int "$TMPDIR/exp.bin")
  SEQ_CONTENT="${MOD_HEX}${EXP_HEX}"
  SEQ_LEN=$(( ${#SEQ_CONTENT} / 2 ))
  RSAPUB_HEX="30$(asn1_len "$SEQ_LEN")${SEQ_CONTENT}"

  echo "$RSAPUB_HEX" | xxd -r -p > "$TMPDIR/rsapub.der"

  # ---- Build SPKI wrapper ----
  RSA_OID="300D06092A864886F70D0101010500"
  RSAPUB_HEX=$(xxd -p "$TMPDIR/rsapub.der" | tr -d '\n')
  BITSTR="03$(asn1_len $(( ${#RSAPUB_HEX}/2 + 1 )))00${RSAPUB_HEX}"

  SPKI_CONTENT="${RSA_OID}${BITSTR}"
  SPKI_HEX="30$(asn1_len $(( ${#SPKI_CONTENT}/2 )))${SPKI_CONTENT}"

  echo "$SPKI_HEX" | xxd -r -p > "$TMPDIR/pub.pem.der"

  # convert DER → PEM (macOS OK)
  openssl pkey -inform DER -pubin -in "$TMPDIR/pub.pem.der" -out "$TMPDIR/pub.pem" \
    || die "Failed to load DER public key"

  KEYFILE="$TMPDIR/pub.pem"
fi

##########################################################
#               Key from CLI
##########################################################
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

##########################################################
#               Verification
##########################################################
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
