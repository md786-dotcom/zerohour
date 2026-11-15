#!/bin/sh
# Records TLS handshakes from this machine for `zerohour calibrate`. Needs sudo (tcpdump). Ctrl-C stops it.
#   1. sh lab/capture.sh real-learn.pcap    then visit your usual sites (20+; more sites = narrower theta0 range)
#   2. a day or more later, on the same clean network:
#      sh lab/capture.sh real-revisit.pcap  then visit the same sites again
#   3. ./build/zerohour calibrate real-learn.pcap real-revisit.pcap lab/pcaps/attack.pcap
# The sensor reads IPv4 over TCP only: HTTP/3 (QUIC, UDP) and IPv6 connections are not counted.
# Quit and reopen the browser before each capture, so it opens new connections instead of reusing old ones.
set -e
[ -n "$1" ] || { echo "usage: sh lab/capture.sh <out.pcap> [interface]"; exit 2; }
iface=${2:-$(route -n get default | awk '/interface:/ {print $2}')}
echo "capturing IPv4 TCP 443 on $iface to $1 (Ctrl-C to stop)"
exec sudo tcpdump -i "$iface" -w "$1" 'ip and tcp port 443'
