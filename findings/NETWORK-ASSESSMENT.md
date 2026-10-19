# Network Assessment — topology, inventory, and evidence

**Scope:** everything below was captured by `scripts/network_evidence.sh` (`NET_TAG=vulnerable|fixed`) against the running lab; raw outputs live in `evidence/03-networking/<tag>/` and are referenced by name throughout.

## Topology

```
                          host (macOS)
                          published :8080 -> 80   (both builds)
                          published :3306 -> 3306 (VULNERABLE baseline only)
                                 |
        -------------------------+--------------------------
        |                   Docker                           |
        |                                                  |
   appnet 172.28.10.0/24                    dbnet 172.28.20.0/24
   .10  kanboard (web, 80+443)               .10  mariadb (3306, bind *)
   .20  client (attacker box, tools)         .254 router (eth1, no services)
   .254 router (eth0) + dnsmasq :53
        |                                          |
        +--- iptables FORWARD (deny by default) --+
             allow: 172.28.10.10 -> 172.28.20.10:3306
             allow: ESTABLISHED,RELATED
             log+drop everything else (RT-DROP, rate-limited)
```

Two Docker bridge networks joined by a router container (one interface in each). Docker's own isolation already prevents container-to-container traffic across bridges — the router exists to make the routing and firewalling *observable and enforceable in one place* (a real DMZ pattern), and the sidecar route-init containers install the routes Docker will not create on its own (see "Design notes").

## Addressing plan

| Host | appnet | dbnet | Role |
|---|---|---|---|
| lab-kanboard | 172.28.10.10 | — | web app (v1.2.44 stock or patched image) |
| lab-client | 172.28.10.20 | — | attacker workstation: nmap, dig, curl, tcpdump |
| lab-router | 172.28.10.254 | 172.28.20.254 | iptables firewall + dnsmasq DNS |
| lab-mariadb | — | 172.28.20.10 | database |

## Port / protocol inventory (from the nmap matrix and per-container net state)

| Target | Port | Protocol | State from client | Evidence |
|---|---|---|---|---|
| kanboard 172.28.10.10 | 80 | TCP | open (HTTP; 302 to login) | `nmap-tcp-matrix.txt`, `tcp-allowed.txt` |
| kanboard 172.28.10.10 | 443 | TCP | open (stock image's Apache also listens TLS) | `nmap-tcp-matrix.txt` |
| kanboard 172.28.10.10 | 22, 53, 3306, 8080, 9999 | TCP | closed (RST — host reachable, no listener) | `nmap-tcp-matrix.txt` |
| router 172.28.10.254 | 53 | UDP+TCP | open (dnsmasq, appnet address only) | `nmap-udp-router.txt`, `router-net-state.txt` |
| router 172.28.10.254 | 9999 etc. | UDP | closed (ICMP port-unreachable) | `nmap-udp-router.txt`, `udp-unreachable.txt` |
| mariadb 172.28.20.10 | 3306 | TCP | **filtered** (no response — firewall drop) | `nmap-tcp-matrix.txt`, `tcp-filtered.txt` |
| host (macOS) | 3306 | TCP | **CONNECTED on vulnerable build / REFUSED on fixed** | `host-db-reachability.txt` |
| host (macOS) | 8080 | TCP | open (kanboard published) | `host-published-ports.txt` |

Key distinction the evidence demonstrates: **closed** = RST comes back (reachable host, no listener); **filtered** = no response at all (something dropped the packet — here the router's FORWARD policy). The nmap matrix shows every port on 172.28.20.10 filtered from the client while same-subnet hosts answer with RSTs — that contrast is the firewall doing its job.

## Routing (who knows which way to send)

| Namespace | Route | How it got there |
|---|---|---|
| client | 172.28.20.0/24 via 172.28.10.254 | compose `command:` at container start |
| kanboard | 172.28.20.0/24 via 172.28.10.254 | `kanboard-route-init` sidecar (shares the netns) |
| mariadb | 172.28.10.0/24 via 172.28.20.254 | `mariadb-route-init` sidecar (return path) |
| router | both subnets directly connected | container attachment |

The mariadb sidecar matters: Docker drops cross-bridge return traffic at the host bridge, so without an explicit return route the *allowed* flow (kanboard→mariadb:3306) would blackhole its own replies. Verified live: migrations and page loads traverse the router (ESTABLISHED counter ≈ 2000 packets after boot).

## Firewall access matrix (router FORWARD chain)

| # | Source | Destination | Port | Result | Evidence |
|---|---|---|---|---|---|
| 1 | any | any | any | ACCEPT if ESTABLISHED,RELATED | `firewall-*.txt` (rule 1) |
| 2 | kanboard .10 | mariadb .10 | 3306/tcp | ACCEPT (the one intended flow) | rule 2 + live traffic |
| 3 | client .20 | mariadb .10 | 3306/tcp | **dropped** — SYN retransmits 7×, no RST, curl exit 28 (timeout) | `tcp-filtered.txt` + LOG counter 0→7 |
| 4 | client .20 | anything else in dbnet | any | dropped (policy) | `nmap-tcp-matrix.txt` (all filtered) |

Same-subnet flows (client→kanboard:80, client→router:53) never traverse FORWARD — they are direct Ethernet, which is why rule 2 can be so narrow.

## UDP and DNS

Three distinct, deliberately demonstrable behaviours from the lab resolver (dnsmasq, authoritative for `lab.internal`):

1. **Positive answer** — `kanboard.lab.internal` → 172.28.10.10, `mariadb.lab.internal` → 172.28.20.10 (`udp-dns.txt` shows query and response packets on the router; `dns-inventory.txt` shows the answers).
2. **NXDOMAIN** — `nonexistent.lab.internal` (unknown name *inside* the authoritative zone) → `status: NXDOMAIN`.
3. **REFUSED** — `example.com` (outside the zone) → `status: REFUSED`; no upstream resolvers are configured, so the lab cannot resolve or be resolved beyond itself. Isolation, demonstrated rather than asserted.

Closed UDP ports are not silent: a probe to router:9999/udp draws an **ICMP port-unreachable** back (`udp-unreachable.txt` — UDP in on eth0, ICMP out), which is why nmap reports them `closed` instead of `open|filtered`.

## The finding, before and after

| Evidence | Vulnerable baseline | Fixed build |
|---|---|---|
| `host-published-ports.txt` | `3306/tcp -> 0.0.0.0:3306` (and `[::]`) | no mapping for mariadb |
| `host-db-reachability.txt` | host process listening on `*:3306`; connect succeeds | nothing listens; connect REFUSED |
| internal path (app) | unchanged — kanboard reaches mariadb via the router | unchanged |

The mitigation is one stanza removed from compose; the database is still fully usable by the application and unreachable from the host network stack.

## Design notes (lessons captured during the build, all visible in commit history)

- **`ip_forward` via compose `sysctls`, not `sysctl -w`:** `/proc/sys` is read-only in containers; the entrypoint *verifies* the compose-applied value instead (`eb82ea5`).
- **dnsmasq binds by address, not interface:** Docker assigns eth0/eth1 in nondeterministic attach order — `listen-address=172.28.10.254` is order-proof (`0dfc34f`).
- **Two compose projects cannot share subnets:** switching variants requires tearing down both projects first — encoded in `scripts/lab_up.sh` (the failure mode was "Pool overlaps with other one on this address space").
- **tcpdump needs `-U` for live-readable captures:** detached `-w` captures buffer until exit and read back as 0 bytes otherwise.
- **dig must target the lab resolver explicitly:** container `/etc/resolv.conf` points at Docker's embedded DNS (127.0.0.11), which knows nothing about lab records.
- **`lab.internal`, not `.local`:** `.local` is reserved for Multicast DNS (RFC 6762); `.internal` is reserved for private use.
- **Kernel logs need `CAP_SYSLOG`:** `dmesg` inside the router is `Operation not permitted`, so drop proof is the iptables counter delta, not log lines (`router-droplog.txt` records this).

## Evidence index

`evidence/03-networking/{vulnerable,fixed}/`: `host-db-reachability.txt` (the finding), `host-published-ports.txt`, `nmap-tcp-matrix.txt`, `nmap-udp-router.txt`, `tcp-allowed.txt/.pcap`, `tcp-refused.txt/.pcap`, `tcp-filtered.txt/.pcap`, `udp-dns.txt/.pcap`, `udp-unreachable.txt/.pcap`, `dns-inventory.txt`, `firewall-before.txt`, `firewall-after.txt`, `router-droplog.txt`, `*-net-state.txt`, `network-inspect.txt`.
