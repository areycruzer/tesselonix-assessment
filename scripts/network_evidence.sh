#!/bin/sh
# Networking evidence capture for the Kanboard audit lab.
#
# Bring up exactly one variant first (scripts/lab_up.sh vulnerable|fixed), then:
#   NET_TAG=vulnerable scripts/network_evidence.sh
#   NET_TAG=fixed     scripts/network_evidence.sh
#
# Captures into evidence/03-networking/$NET_TAG/:
#   - host-level port exposure (the network finding: published DB port)
#   - interfaces, routes and listening sockets of every container
#   - firewall counters before/after the active tests + kernel drop log
#   - packet captures for the five behaviours:
#       TCP allowed (client->kanboard:80), TCP refused (closed port -> RST),
#       TCP filtered (client->mariadb:3306 dropped by the router),
#       UDP allowed (DNS), UDP closed (ICMP port-unreachable back)
#   - nmap TCP/UDP scans of the lab from the client container
#   - DNS inventory (positive answer, NXDOMAIN, reverse, external isolation)
#
# tcpdump note: captures use -U (packet-buffered) so the .pcap file is usable
# while the process runs; the capture is stopped with SIGTERM (clean flush)
# BEFORE the readback, otherwise the file reads back as 0 bytes.
set -u
cd "$(dirname "$0")/.." || exit 1
TAG="${NET_TAG:-vulnerable}"
OUT="evidence/03-networking/$TAG"
mkdir -p "$OUT"

say() { printf '\n[%s] %s\n' "$1" "$2"; }

capture() {
  # capture <name> <container> <iface> <max-packets> <filter> -- <command...>
  name=$1; c=$2; iface=$3; n=$4; filter=$5
  shift 5; [ "$1" = "--" ] && shift
  docker exec -d "$c" tcpdump -U -i "$iface" -nn -c "$n" -w "/tmp/$name.pcap" "$filter"
  sleep 1
  {
    echo "# packets captured on $c ($iface), filter: $filter"
    "$@" 2>&1
    echo
    echo '--- tcpdump readback ---'
  } > "$OUT/$name.txt"
  sleep 2
  docker exec "$c" pkill -x tcpdump >/dev/null 2>&1 || true
  sleep 1
  docker exec "$c" tcpdump -nn -r "/tmp/$name.pcap" >> "$OUT/$name.txt" 2>&1
  docker cp "$c:/tmp/$name.pcap" "$OUT/$name.pcap" >/dev/null 2>&1 || true
  docker exec "$c" rm -f "/tmp/$name.pcap" >/dev/null 2>&1 || true
}

say host "published port mappings"
{
  docker ps --filter name=lab- --format 'table {{.Names}}\t{{.Image}}\t{{.Ports}}\t{{.Status}}'
  echo
  echo '--- docker port lab-mariadb ---'
  docker port lab-mariadb 2>&1 || true
  echo '--- docker port lab-kanboard ---'
  docker port lab-kanboard 2>&1 || true
} > "$OUT/host-published-ports.txt"

say host "is the database reachable from the host network stack?"
{
  lsof -nP -iTCP:3306 -sTCP:LISTEN 2>/dev/null || echo '(no host process listens on 3306)'
  echo
  nc -z -w 2 localhost 3306 \
    && echo 'host -> localhost:3306 : CONNECTED (database exposed on the host)' \
    || echo 'host -> localhost:3306 : REFUSED (database not published)'
} > "$OUT/host-db-reachability.txt"

say router "firewall counters BEFORE the tests"
docker exec lab-router iptables -L -v -n > "$OUT/firewall-before.txt" 2>&1

say router "interfaces, routes and sockets"
docker exec lab-router sh -c 'ip -br addr; echo; ip route; echo; ss -tulpn' > "$OUT/router-net-state.txt" 2>&1

say client "interfaces, routes and sockets"
docker exec lab-client sh -c 'ip -br addr; echo; ip route; echo; ss -tulpn' > "$OUT/client-net-state.txt" 2>&1

say app "kanboard net state and listening sockets"
docker exec lab-kanboard sh -c 'ip -br addr 2>/dev/null; echo; ip route 2>/dev/null || cat /proc/net/route; echo; ss -tulpn 2>/dev/null || netstat -tulpn 2>/dev/null || cat /proc/net/tcp' > "$OUT/kanboard-net-state.txt" 2>&1

say db "mariadb net state, listening sockets and bind address"
docker exec lab-mariadb sh -c 'ip -br addr 2>/dev/null; echo; ip route 2>/dev/null || cat /proc/net/route; echo; ss -tulpn 2>/dev/null || netstat -tulpn 2>/dev/null || cat /proc/net/tcp' > "$OUT/mariadb-net-state.txt" 2>&1
docker exec lab-mariadb mariadb -uroot -plabrootpw -N -B -e "SHOW VARIABLES LIKE 'bind_address'" > "$OUT/mariadb-bind-address.txt" 2>&1 || true

say docker "network inventory"
NETS=$(docker inspect lab-router -f '{{range $k, $v := .NetworkSettings.Networks}}{{$k}} {{end}}')
docker network inspect $NETS > "$OUT/network-inspect.txt" 2>&1

say test "TCP allowed: client -> kanboard:80"
capture tcp-allowed lab-client eth0 10 'host 172.28.10.10 and tcp port 80' -- \
  docker exec lab-client curl -s -o /dev/null -w 'HTTP %{http_code} from %{remote_ip}:%{remote_port}\n' http://172.28.10.10/

say test "TCP refused (no listener): client -> kanboard:9999"
capture tcp-refused lab-client eth0 8 'host 172.28.10.10 and tcp port 9999' -- \
  docker exec lab-client sh -c 'curl -s -m 5 telnet://172.28.10.10:9999 </dev/null; echo "curl exit=$? (7 = connection refused, RST received)"'

say test "TCP filtered (firewall drop): client -> mariadb:3306, capture on the router"
capture tcp-filtered lab-router any 12 'port 3306' -- \
  docker exec lab-client sh -c 'curl -s -m 8 telnet://172.28.20.10:3306 </dev/null; echo "curl exit=$? (28 = timeout, packets silently dropped)"'

say test "UDP allowed: DNS query client -> router:53, capture on the router"
capture udp-dns lab-router any 8 'port 53' -- \
  docker exec lab-client sh -c 'dig @172.28.10.254 +short kanboard.lab.internal; dig @172.28.10.254 +short mariadb.lab.internal'

say test "UDP to closed port: client -> router:9999, ICMP port-unreachable expected"
capture udp-unreachable lab-router any 10 'udp port 9999 or icmp' -- \
  docker exec lab-client sh -c 'printf probe | nc -u -w 2 172.28.10.254 9999; echo "nc exit=$? (packet sent; router should answer ICMP port-unreachable)"'

say scan "nmap TCP matrix from the client"
docker exec lab-client nmap -Pn -n -p 22,53,80,443,3306,8060,8080,9999 172.28.10.10 172.28.10.254 172.28.20.10 172.28.20.254 > "$OUT/nmap-tcp-matrix.txt" 2>&1

say scan "nmap UDP scan of the router"
docker exec lab-client nmap -sU -Pn -n -p 53,123,161,514,5353,9999 172.28.10.254 > "$OUT/nmap-udp-router.txt" 2>&1

say dns "DNS inventory (queries aimed at the lab resolver 172.28.10.254)"
{
  echo '--- A kanboard.lab.internal (positive) ---';        docker exec lab-client dig @172.28.10.254 +noall +answer +authority kanboard.lab.internal
  echo '--- A mariadb.lab.internal (positive) ---';     docker exec lab-client dig @172.28.10.254 +noall +answer +authority mariadb.lab.internal
  echo '--- A nonexistent.lab.internal (NXDOMAIN) ---'; docker exec lab-client dig @172.28.10.254 +noall +comments +answer nonexistent.lab.internal
  echo '--- PTR 172.28.10.10 (reverse: not configured, by design) ---'; docker exec lab-client dig @172.28.10.254 +noall +comments +answer -x 172.28.10.10
  echo '--- A example.com (external isolation check) ---'
  docker exec lab-client dig @172.28.10.254 +noall +answer +comments example.com
} > "$OUT/dns-inventory.txt" 2>&1

say router "firewall counters AFTER the tests (compare firewall-before.txt)"
docker exec lab-router iptables -L -v -n > "$OUT/firewall-after.txt" 2>&1

say router "kernel drop log (LOG rule output for packets the tests just sent)"
if docker exec lab-router dmesg >/dev/null 2>&1; then
  docker exec lab-router dmesg 2>/dev/null | grep "RT-DROP" | tail -20 > "$OUT/router-droplog.txt"
else
  {
    echo "(kernel log not readable inside the container — dmesg requires CAP_SYSLOG,"
    echo " which Docker does not grant the container; the drop evidence is the"
    echo " LOG-rule packet counter delta between firewall-before.txt and"
    echo " firewall-after.txt: the counters show the test SYNs hitting the rule.)"
  } > "$OUT/router-droplog.txt"
fi

echo
echo "captured files in $OUT:"
ls -la "$OUT"
