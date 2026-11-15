#!/bin/sh
# demo.sh + Wireshark, on its own port and state so it runs beside the demo.sh server (8765, .zerohour).
# Wireshark shows the raw evidence (attack.pcap, Certificate messages: issuer "Interceptor CA"), the dashboard the decision.
set -e
cd "$(dirname "$0")"
PORT=${PORT:-8766}
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release >/dev/null
cmake --build build -j >/dev/null
# Only make PCAPs when missing: the demo.sh server reads the same lab/pcaps files.
[ -f lab/pcaps/attack.pcap ] || cmake --build build --target pcaps >/dev/null
rm -rf .zerohour2
# One window per PCAP; issuer column reads "Lab CA,siteN.lab" (learn) vs "Interceptor CA,siteN.lab" (attack).
for p in learn attack; do
  open -n -a Wireshark --args -r "$PWD/lab/pcaps/$p.pcap" -Y "tls.handshake.type == 11" \
    -o 'gui.column.format:"No.","%m","Source","%s","Certificate (issuer, site)","%Cus:x509sat.uTF8String:0:R","Info","%i"'
done
[ -z "$NO_OPEN" ] && (sleep 1; open "http://127.0.0.1:$PORT/") &
exec ./build/zerohour serve --port "$PORT" --state .zerohour2
