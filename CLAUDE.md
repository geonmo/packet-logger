# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Purpose

This is an eBPF firewall testbed that demonstrates ACK flood attack detection and mitigation by comparing two firewall implementations side-by-side:

- **Node 1 (Stateless)**: nftables netdev ingress hook — allows ACK-only packets (vulnerable)
- **Node 2 (Stateful)**: zfw eBPF with TC hook and BPF map connection tracking — blocks ACK-only packets (secure)

An attack server orchestrates attacks and shows comparative results via a web dashboard; a guest client performs legitimate TCP connections to validate normal traffic passes through both nodes.

## Build & Deployment

There is no Makefile. The project uses **Ansible for deployment** and **Podman/Quadlet for containerization**.

```bash
# Deploy the full 4-node testbed
ansible-playbook -i ansible/inventory.ini ansible/playbook.yml

# Build individual container images (run from repo root)
podman build --tag packet-logger:latest --file src/Containerfile ./src
podman build --tag attack-server:latest --file attack-server/src/Containerfile ./attack-server/src
podman build --tag guest-client:latest --file guest-client/src/Containerfile ./guest-client/src

# Manage services on deployed nodes
systemctl status packet-logger.service
systemctl restart packet-logger.service
systemctl status fw-init.service     # Node 2 only
systemctl status zfw-rules.service   # Node 2 only

# Verify firewall state on nodes
nft list ruleset                     # Node 1 — nftables
tc filter show dev eth0 ingress      # Node 2 — TC/eBPF
/usr/sbin/zfw -L                     # Node 2 — zfw rules
```

## Architecture

### 4-Node Network Layout (IPVLAN L2, 192.168.100.0/24)

| Node | IP | Role |
|------|-----|------|
| Node 1 | 192.168.100.7 | packet-logger + nftables (stateless, vulnerable) |
| Node 2 | 192.168.100.8 | packet-logger + zfw eBPF (stateful, secure) |
| Attack Server | 192.168.100.5 | ACK flood generator + web dashboard (:8000) |
| Guest Client | 192.168.100.6 | Legitimate TCP tester (:7070) |

### Application Components

**`src/packet_logger.py`** — runs on both Node 1 and Node 2
- Passive packet sniffer using scapy (libpcap) with BPF filter
- Multi-threaded: separate sniff thread + Flask REST API thread
- Tracks TCP flags: SYN, ACK-only, SYN-ACK, RST, FIN
- `ack_only` stat is the key attack indicator — ACK without prior SYN
- REST API on port 9090

**`attack-server/src/attack_server.py`** — runs on the attack server
- Web dashboard (port 8000) for orchestrating attacks
- Sends raw ACK-only packets (flags='A', no SYN) via scapy to both nodes
- Polls both packet-logger APIs and the guest-client API to compare results
- Shows the difference: Node 1 counts ACK-only packets, Node 2 drops them

**`guest-client/src/guest_client.py`** — runs on the guest client
- Performs real TCP 3-way handshakes to both nodes every 5 seconds
- REST API on port 7070 reports success/refused/timeout per node
- Validates that normal traffic is not blocked by either firewall

### Firewall Comparison

| Aspect | Node 1 (nftables) | Node 2 (zfw eBPF) |
|--------|-------------------|-------------------|
| Hook point | netdev ingress | TC ingress |
| Connection tracking | None | BPF map |
| ACK-only packets | **Allowed** (vulnerable) | **Dropped** (secure) |
| Normal SYN→SYN-ACK→ACK | Allowed | Allowed |

## Configuration

All deployment variables are in `ansible/inventory.ini`. Key environment variables per component:

**packet-logger** (Nodes 1 & 2):
- `LISTEN_PORT=8080`, `API_PORT=9090`, `NODE_NAME`, `INTERFACE`
- `BUFFER_SIZE=500`, `LOG_FILE`, `MAX_LOG_SIZE_MB=100`

**attack-server**:
- `NODE1_IP`, `NODE2_IP`, `NODE1_API`, `NODE2_API`, `GUEST_API`
- `TARGET_PORT=8080`, `WEB_PORT=8000`

**guest-client**:
- `NODE1_IP`, `NODE2_IP`, `TARGET_PORT=8080`, `API_PORT=7070`
- `TEST_INTERVAL=5.0`, `CONNECT_TIMEOUT=2.0`

## REST API Reference

**Packet Logger** (`http://<node>:9090`):
- `GET /api/health` — health check
- `GET /api/packets?since_id=0&limit=100` — packet buffer
- `GET /api/stats` — counters: total, syn, ack_only, syn_ack, rst, fin

**Attack Server** (`http://<attack-server>:8000`):
- `POST /api/attack` — start attack `{targets, port, duration, count, rate}`
- `DELETE /api/attack` — stop attack
- `GET /api/attack/status` — current state
- `GET /api/nodes` — both nodes status
- `GET /api/guest` — guest client results

**Guest Client** (`http://<guest>:7070`):
- `GET /api/results?since_id=0&limit=50` — test results per node
- `GET /api/summary` — success/refused/timeout/error counts

## Key Requirements

- **Kernel**: Linux 5.8+ (project runs on 5.14.0-378.el9); needs `CONFIG_NET_CLS_BPF`, `CONFIG_NET_ACT_BPF`
- **Container runtime**: Podman with Quadlet (rootful containers required for `CAP_NET_RAW` + `CAP_NET_ADMIN`)
- **zfw version**: v0.9.22 (from netfoundry/zfw); install path `/usr/sbin/zfw`
- **Network mode**: IPVLAN L2 — required for raw packet capture and crafting from containers
- **Python deps**: scapy, flask, flask-cors, requests (see `requirements.txt` in each component dir)
