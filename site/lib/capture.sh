#!/bin/bash
# Runs as root inside a Vercel Sandbox VM made by site/scripts/snapshot.mjs (tcpdump, mitmproxy, zerohour).
#   capture.sh direct|mitm host...
# A client lives in its own network namespace (10.9.0.2) and uses this VM as its gateway (10.9.0.1).
# tcpdump records the client's side of the link, as a sensor on the client's network would.
#   pass 1 -> learn.pcap: the client visits each host directly (the baseline)
#   pass 2 -> test.pcap:  the client visits each host again; with "mitm" the gateway sends port 443 to mitmproxy
# Then the C++ sensor parses both: learn.json, test.json (zerohour show --json).
set -u
mode=$1; shift
out=/vercel/sandbox/out
mkdir -p $out

ip netns add victim
ip link add vh type veth peer name vc
ip link set vc netns victim
ip addr add 10.9.0.1/24 dev vh && ip link set vh up
ip netns exec victim sh -c 'ip addr add 10.9.0.2/24 dev vc && ip link set vc up && ip link set lo up && ip route add default via 10.9.0.1'
sysctl -qw net.ipv4.ip_forward=1
iface=$(ip route | awk '/^default/ {print $5}')
iptables -t nat -A POSTROUTING -s 10.9.0.0/24 -o "$iface" -j MASQUERADE
mkdir -p /etc/netns/victim && cp /etc/resolv.conf /etc/netns/victim/

visit() {  # $1 = pcap; one HEAD request per host from the client. -k: the handshake is recorded even if the name check fails.
  local pcap=$1; shift
  ip netns exec victim tcpdump -i vc --immediate-mode -U -s 0 -w "$pcap" 'ip and tcp port 443' 2>"$pcap.err" & local pid=$!
  for _ in $(seq 100); do grep -q 'listening on' "$pcap.err" && break; sleep 0.1; done  # a cold VM can take seconds
  for h in "$@"; do
    code=$(ip netns exec victim curl -4 -skI --max-time 8 -o /dev/null -w '%{http_code}' "https://$h/")
    echo "$pcap $h $code"
  done
  sleep 0.5; kill -INT $pid; wait $pid 2>/dev/null
}

visit $out/learn.pcap "$@"

if [ "$mode" = mitm ]; then
  # The interceptor: mitmproxy in transparent mode on the gateway, with its own CA (made once, in the snapshot).
  mitmdump --mode transparent --listen-port 8080 --set confdir=/opt/mitm --set ssl_insecure=true -q >$out/mitm.log 2>&1 &
  for _ in $(seq 50); do ss -ltn | grep -q ':8080 ' && break; sleep 0.1; done
  iptables -t nat -A PREROUTING -i vh -p tcp --dport 443 -j REDIRECT --to-port 8080
fi

visit $out/test.pcap "$@"

zerohour show $out/learn.pcap --json >$out/learn.json
zerohour show $out/test.pcap --json >$out/test.json
echo done
