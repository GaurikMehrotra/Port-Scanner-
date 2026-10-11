#!/bin/sh
set -eu
iptables -A INPUT -p tcp --dport 81 -j DROP
iptables -A INPUT -p udp --dport 81 -j DROP
exec python /service/server.py
