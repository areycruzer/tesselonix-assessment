#!/bin/sh
# Router/firewall for the lab. Runs as root inside its own network namespace
# with one interface in each subnet. All rules are idempotent so restarts are safe.
set -e

# net.ipv4.ip_forward is set via the compose `sysctls:` key (Docker whitelists
# this namespaced sysctl and applies it at container creation). /proc/sys is
# mounted read-only inside the container, so `sysctl -w` fails — verify instead.
echo "[router] verifying IPv4 forwarding"
if [ "$(cat /proc/sys/net/ipv4/ip_forward)" = "1" ]; then
    echo "[router] ip_forward=1 (applied via compose sysctls)"
else
    echo "[router] FATAL: ip_forward is 0; set net.ipv4.ip_forward=1 in compose sysctls"
    exit 1
fi

echo "[router] installing deny-by-default FORWARD policy"
iptables -P FORWARD DROP
iptables -F FORWARD

# Allow replies to permitted connections
iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# INTENDED ACCESS: kanboard (172.28.10.10) may reach mariadb (172.28.20.10) on MySQL port only
iptables -A FORWARD -s 172.28.10.10 -d 172.28.20.10 -p tcp --dport 3306 -j ACCEPT

# Everything else forwarded between subnets is dropped (rate-limited logging for evidence)
iptables -A FORWARD -m limit --limit 5/min -j LOG --log-prefix "RT-DROP " || true

echo "[router] rules installed:"
iptables -L FORWARD -n -v --line-numbers

echo "[router] starting dnsmasq (UDP DNS demo on ${APPNET_IP:-172.28.10.254}:53)"
dnsmasq --conf-file=/etc/dnsmasq.conf --no-daemon &
DNSMASQ_PID=$!

sleep 2
echo "[router] routing table:"
ip route

# Keep the container alive; log dropped packets to dmesg
wait $DNSMASQ_PID
