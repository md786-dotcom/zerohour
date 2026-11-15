#!/bin/sh
# Multiple benign changes, before and after calibration. Run from this folder: ./demo3.sh
# multichange.pcap: 3 of 8 sites change between visits, one per check:
#   site2 server upgraded its TLS stack -> A (new JA4S)
#   site3 renewed its certificate       -> B (new key, still issued by "Lab CA")
#   site6 route changed                 -> D (TTL moved by 7)
# 1. plan model (../zerohour.conf)      2. calibrate theta0/theta1, write them into ./zerohour.conf
# 3. benign + attack runs with ./zerohour.conf. 4. dashboard with ./zerohour.conf on port 8767 (PORT=...).
# State in ./.zerohour3 and ./.zerohour3-web, so it runs beside demo.sh (8765) / demo2.sh (8766).
set -e
cd "$(dirname "$0")"
cmake -S .. -B ../build -DCMAKE_BUILD_TYPE=Release >/dev/null
cmake --build ../build -j >/dev/null
P=../lab/pcaps
[ -f $P/multichange.pcap ] || cmake --build ../build --target pcaps >/dev/null
rm -rf .zerohour3 && mkdir .zerohour3
zh() { ../build/zerohour "$@" -b .zerohour3/baseline.tsv -l .zerohour3/alerts.log; }
fail=0
check() {  # label conf pcap want(alert|no-alert)
  out=$(zh run $P/$3.pcap -c "$2")
  echo "$out"
  peak=$(echo "$out" | awk 'BEGIN {m=-99} $1~/^[0-9]+$/ {if ($6+0>m) m=$6+0} END {printf "%+.2f", m}')
  got=no-alert; echo "$out" | grep -q '^ALERT' && got=alert
  if [ $got = "$4" ]; then echo "PASS $1: $got, highest score $peak"; else echo "FAIL $1: want $4, got $got"; fail=1; fi
}

echo "== What changed (lab manifest: learn vs multichange) =="
printf '%-12s %-10s %-30s %-9s %-7s %s\n' scenario site cipher alpn issuer ttl
awk -F'\t' '$1=="learn"||$1=="multichange" {printf "%-12s %-10s %-30s %-9s %-7s %s\n",$1,$2,$4,$6,$7,$8}' $P/manifest.txt

echo; echo "== Learn baseline (clean network) =="
zh learn $P/learn.pcap

echo; echo "== 1. Plan model ../zerohour.conf: 3 benign changes =="
check "plan model, benign" ../zerohour.conf multichange no-alert

echo; echo "== 2. Calibrate: theta0 from the benign revisit, theta1 from the attack capture =="
cal=$(../build/zerohour calibrate $P/learn.pcap $P/multichange.pcap $P/attack.pcap -c ../zerohour.conf)
echo "$cal" | sed -n '/^benign/,/^model/p;/^  mismatch/,/^  E\[N/p'
t0=$(echo "$cal" | awk '/^theta0 = / {print $3}')
t1=$(echo "$cal" | awk '/^theta1 = / {print $3}')
sed -e "s/^theta0 = [0-9.]*/theta0 = $t0/" -e "s/^theta1 = [0-9.]*/theta1 = $t1/" zerohour.conf > zerohour.conf.new
mv zerohour.conf.new zerohour.conf
echo "wrote ./zerohour.conf:"; grep '^theta' zerohour.conf

echo; echo "== 3a. Calibrated model ./zerohour.conf: same 3 benign changes =="
check "calibrated, benign" zerohour.conf multichange no-alert
echo; echo "== 3b. Calibrated model ./zerohour.conf: interceptor =="
check "calibrated, attack" zerohour.conf attack alert
[ $fail = 0 ] || exit 1

PORT=${PORT:-8767}
rm -rf .zerohour3-web
echo; echo "== 4. Dashboard with the calibrated ./zerohour.conf =="
[ -z "$NO_OPEN" ] && (sleep 1; open "http://127.0.0.1:$PORT/") &
exec ../build/zerohour serve --port "$PORT" --state .zerohour3-web -c zerohour.conf
