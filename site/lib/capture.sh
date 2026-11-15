#!/bin/bash
# Runs as root in the live-capture VM (a Vercel Sandbox made from the snapshot of site/scripts/snapshot.mjs).
# The client lives in its own network namespace (10.9.0.2) and uses this VM as its gateway (10.9.0.1).
# tcpdump records the client's side of the link, as a sensor on the client's network would. One subcommand per call:
#   setup host...        build the client network; pin each host to one IPv4 address for every later visit
#   start <pcap>         start tcpdump on the client's link, in the background
#   visit <host> <pcap>  one HTTPS request from the client; prints the HTTP code, then the sensor's parse of <pcap> so far
#   stop                 stop tcpdump (the PCAP is complete after this)
#   route [ip...]        port 443 to these IPs goes to mitmproxy on the gateway; no IP = every site direct
#   lock / unlock        one test at a time in this VM (a lock older than 3 minutes is from a killed request)
set -u
out=/vercel/sandbox/out
cmd=$1; shift
case $cmd in
setup)
  mkdir -p $out /etc/netns/victim
  ip netns add victim
  ip link add vh type veth peer name vc
  ip link set vc netns victim
  ip addr add 10.9.0.1/24 dev vh && ip link set vh up
  ip netns exec victim sh -c 'ip addr add 10.9.0.2/24 dev vc && ip link set vc up && ip link set lo up && ip route add default via 10.9.0.1'
  sysctl -qw net.ipv4.ip_forward=1
  iptables -t nat -A POSTROUTING -s 10.9.0.0/24 -o "$(ip route | awk '/^default/ {print $5}')" -j MASQUERADE
  cp /etc/resolv.conf /etc/netns/victim/
  echo '127.0.0.1 localhost' >/etc/netns/victim/hosts
  for h in "$@"; do  # one address per host, so the learn and test visits reach the same server
    if [[ $h =~ ^[0-9.]+$ ]]; then ip=$h; else ip=$(getent ahostsv4 "$h" | awk 'NR==1 {print $1}'); [ -n "$ip" ] && echo "$ip $h" >>/etc/netns/victim/hosts; fi
    echo "$h ${ip:--}"
  done ;;
start)
  setsid nohup ip netns exec victim tcpdump -i vc --immediate-mode -U -s 0 -w "$1" 'ip and tcp port 443' >/dev/null 2>"$1.err" </dev/null &
  for _ in $(seq 100); do grep -q 'listening on' "$1.err" && exit 0; sleep 0.1; done  # a cold VM can take seconds
  echo 'tcpdump did not start' >&2; exit 1 ;;
visit)  # -k: the handshake is recorded even when the name check fails (an IP address, or mitmproxy's certificate)
  ip netns exec victim curl -4 -skI --max-time 8 -o /dev/null -w '%{http_code}\n' "https://$1/"
  sleep 0.2  # tcpdump writes each packet at once (-U); give the last packets time to land
  zerohour show "$2" --json ;;
stop)
  pkill -INT -x tcpdump
  for _ in $(seq 50); do pgrep -x tcpdump >/dev/null || exit 0; sleep 0.1; done ;;
route)
  iptables -t nat -F PREROUTING
  [ $# -eq 0 ] && exit 0
  # The interceptor: mitmproxy in transparent mode with its own CA (made once, in the snapshot).
  # Only the redirected command goes to the background: a backgrounded "a || b" list keeps this call's output open.
  if ! pgrep -f 'mitmdump --mode transparent' >/dev/null; then
    setsid nohup mitmdump --mode transparent --listen-port 8080 --set confdir=/opt/mitm --set ssl_insecure=true -q >$out/mitm.log 2>&1 </dev/null &
  fi
  for _ in $(seq 100); do ss -ltn | grep -q ':8080 ' && break; sleep 0.1; done
  ss -ltn | grep -q ':8080 ' || { tail -5 $out/mitm.log >&2; echo 'mitmproxy did not start' >&2; exit 1; }
  for ip in "$@"; do iptables -t nat -A PREROUTING -i vh -p tcp -d "$ip" --dport 443 -j REDIRECT --to-port 8080; done ;;
lock)
  [ -n "$(find $out/lock -maxdepth 0 -mmin +3 2>/dev/null)" ] && rmdir $out/lock
  mkdir $out/lock 2>/dev/null || { echo 'A test is running in this VM.' >&2; exit 3; } ;;
unlock) rmdir $out/lock 2>/dev/null; true ;;
*) echo "unknown subcommand $cmd" >&2; exit 2 ;;
esac
