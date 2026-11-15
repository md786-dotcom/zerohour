#!/bin/sh
# Wireshark as independent ground truth for the sensor. For every lab capture, tshark's own dissection must agree
# with `zerohour show` handshake by handshake (SNI, client JA4, server TTL), and the certificate issuers Wireshark
# reads must match the sensor's verdict: "Interceptor CA" certificates <=> alert. Artifact: e2e/artifacts/wireshark.txt
set -e
cd "$(dirname "$0")/.."
T=${TSHARK:-$(command -v tshark || echo /Applications/Wireshark.app/Contents/MacOS/tshark)}
OUT=e2e/artifacts/wireshark.txt
mkdir -p e2e/artifacts
"$T" --version | head -1 > $OUT
fail=0
for s in learn normal onechange multichange attack busylearn busy; do
  f=lab/pcaps/$s.pcap
  ws=$("$T" -r $f -Y "tls.handshake.type == 1" -T fields -E separator=' ' -e tls.handshake.extensions_server_name -e tls.handshake.ja4)
  wsttl=$("$T" -r $f -Y "tls.handshake.type == 2" -T fields -e ip.ttl)
  zh=$(./build/zerohour show $f | awk 'NR > 1 {print $1, $3}')
  zhttl=$(./build/zerohour show $f | awk 'NR > 1 {print $6}')
  issuers=$("$T" -r $f -Y "tls.handshake.type == 11" -T fields -e x509sat.uTF8String | cut -d, -f1 | sort | uniq -c | awk '{$1=$1; print}')
  L=lab/pcaps/learn.pcap; case $s in busy*) L=lab/pcaps/busylearn.pcap;; esac
  alert=$(./build/zerohour learn $L -b /tmp/zh-ws-$$.tsv >/dev/null &&
          ./build/zerohour run $f -b /tmp/zh-ws-$$.tsv -c zerohour.tuned.conf -l /tmp/zh-ws-$$.log | grep -c '^ALERT' || true)
  rm -f /tmp/zh-ws-$$.tsv /tmp/zh-ws-$$.log
  forged=$(echo "$issuers" | grep -c 'Interceptor CA' || true)
  printf '\n### %s\nWireshark issuers: %s\nsensor alerts: %s\n' $s "$(echo $issuers)" $alert >> $OUT
  r=PASS
  [ "$ws" = "$zh" ] || { r=FAIL; printf 'JA4/SNI differ\nwireshark:\n%s\nsensor:\n%s\n' "$ws" "$zh" | tee -a $OUT; }
  [ "$wsttl" = "$zhttl" ] || r=FAIL
  if [ "$forged" -gt 0 ] && [ "$alert" -eq 0 ]; then r=FAIL; fi
  if [ "$forged" -eq 0 ] && [ "$alert" -gt 0 ]; then r=FAIL; fi
  [ $r = PASS ] || fail=1
  echo "$r $s: $(echo "$ws" | wc -l | tr -d ' ') handshakes, JA4 + SNI + TTL agree with Wireshark, issuers [$(echo $issuers)], sensor alerts $alert" | tee -a $OUT
done
exit $fail
