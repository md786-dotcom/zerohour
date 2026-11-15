#!/bin/sh
# E2E for `zerohour calibrate` on the lab PCAPs. Artifact: e2e/artifacts/calibrate.txt (full output of each run).
set -e
cd "$(dirname "$0")/.."
P=lab/pcaps OUT=e2e/artifacts/calibrate.txt
[ -f $P/multichange.pcap ] || cmake --build build --target pcaps >/dev/null
: > $OUT
fail=0
expect() {  # revisit theta0 theta1 [attack]
  out=$(./build/zerohour calibrate $P/learn.pcap $P/$1.pcap ${4:+$P/$4.pcap})
  printf '### calibrate learn %s %s\n%s\n\n' "$1" "$4" "$out" >> $OUT
  if echo "$out" | grep -qx "theta0 = $2" && echo "$out" | grep -qx "theta1 = $3"; then echo "PASS $1: theta0 $2, theta1 $3"
  else echo "FAIL $1: want theta0 $2, theta1 $3"; fail=1; fi
}
expect normal      0.9000 0.1000 attack   # 8/8 match -> (8+1)/(8+2); attack 0/8 -> (0+1)/(8+2)
expect onechange   0.8000 0.1000 attack   # 7/8
expect multichange 0.5000 0.1000 attack   # 4/8
expect onechange   0.8000 0.2000          # no attack capture: theta1 from zerohour.conf
# Attack capture given as the benign revisit: theta1 >= theta0 must be refused.
if ./build/zerohour calibrate $P/learn.pcap $P/attack.pcap $P/normal.pcap >/dev/null 2>&1; then echo "FAIL swapped: accepted"; fail=1
else echo "PASS swapped: refused"; fi
echo "artifact: $OUT"
exit $fail
