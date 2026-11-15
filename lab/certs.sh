#!/bin/sh
# Lab PKI for zh_lab: Lab CA + site1..8.lab, a renewed site3 key, and the Interceptor CA with forged certs.
# Idempotent: keys must stay stable across runs so a learned baseline stays valid.
set -e
out=$1
[ -f "$out/done" ] && exit 0
OSSL=/opt/homebrew/opt/openssl@3/bin/openssl  # macOS /usr/bin/openssl is LibreSSL
mkdir -p "$out"
cd "$out"

ca() {  # file CN
  $OSSL req -x509 -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 3650 \
    -keyout "$1.key" -out "$1.crt" -subj "/CN=$2" 2>/dev/null
}
leaf() {  # file host ca-file   (new key every time)
  $OSSL req -x509 -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 3650 \
    -keyout "$1.key" -out "$1.crt" -subj "/CN=$2" -CA "$3.crt" -CAkey "$3.key" \
    -addext "subjectAltName=DNS:$2" -addext "basicConstraints=critical,CA:FALSE" 2>/dev/null
}

ca lab-ca "Lab CA"
ca int-ca "Interceptor CA"
for n in 1 2 3 4 5 6 7 8; do
  leaf "site$n" "site$n.lab" lab-ca
  leaf "int-site$n" "site$n.lab" int-ca
done
leaf site3-renewed site3.lab lab-ca
touch done
