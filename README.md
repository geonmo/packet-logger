# packet-logger — Stateless vs Stateful 방화벽 비교 테스트베드

nftables(Stateless)와 zfw eBPF(Stateful) 방화벽에 대한 ACK Flood 공격 감지·차단 효과를 실시간으로 비교하는 4노드 테스트베드입니다.

## 개요

| 구분 | Node 1 (취약) | Node 2 (안전) |
|------|--------------|--------------|
| 방화벽 엔진 | nftables | zfw eBPF |
| 훅 포인트 | netdev ingress | TC ingress |
| 연결 상태 추적 | 없음 (포트 번호만 검사) | BPF 맵으로 TCP 상태 추적 |
| ACK-only 패킷 | **통과** (취약) | **차단** (안전) |
| 정상 SYN→SYN-ACK→ACK | 허용 | 허용 |

**ACK Flood 공격 원리**: SYN 없이 ACK 플래그만 있는 패킷을 대량 전송합니다. Stateless 방화벽은 포트 번호만 보므로 통과시키지만, Stateful 방화벽은 선행 SYN 없는 ACK를 BPF 맵으로 탐지해 차단합니다.

## 아키텍처

```
                   IPVLAN L2  192.168.100.0/24
  ┌──────────────────────────────────────────────────────────┐
  │                                                          │
  │  Node 1 (192.168.100.3)       Node 2 (192.168.100.4)   │
  │  ┌─────────────────────┐      ┌─────────────────────┐  │
  │  │  packet-logger :8080│      │  packet-logger :8080│  │
  │  │  REST API      :9090│      │  REST API      :9090│  │
  │  │  [nftables]         │      │  [zfw eBPF / TC]    │  │
  │  │  IPVLAN: .100.7     │      │  IPVLAN: .100.8     │  │
  │  └─────────────────────┘      └─────────────────────┘  │
  │                                                          │
  │  Attack Server (192.168.100.5)  Guest Client (.100.6)   │
  │  ┌─────────────────────┐      ┌─────────────────────┐  │
  │  │  Web Dashboard :8000│      │  TCP 접속 테스터    │  │
  │  │  ACK Flood 생성기   │      │  REST API      :7070│  │
  │  │  결과 집계          │      │  정상 트래픽 검증   │  │
  │  └─────────────────────┘      └─────────────────────┘  │
  └──────────────────────────────────────────────────────────┘
```

### 컴포넌트 역할

- **packet-logger** (`src/packet_logger.py`): Node 1·2에서 동작. scapy로 패킷을 패시브 캡처하고 TCP 플래그별 통계를 REST API로 제공. `ack_only` 카운터가 0보다 크면 공격 패킷이 방화벽을 통과한 것.
- **attack-server** (`attack-server/src/attack_server.py`): ACK-only 패킷(SYN 없음)을 두 노드에 동시 발송. 웹 대시보드에서 두 노드의 결과를 실시간 비교.
- **guest-client** (`guest-client/src/guest_client.py`): 5초 간격으로 두 노드에 정상 TCP 3-way 핸드셰이크를 수행해 정상 트래픽이 차단되지 않는지 검증.

## 사전 요구사항

| 항목 | 요구 사항 |
|------|-----------|
| OS | RHEL 9 / CentOS Stream 9 (커널 5.8 이상) |
| 컨테이너 런타임 | Podman + Quadlet (rootful 실행 필요) |
| 네트워크 | IPVLAN L2 — 패킷 캡처·생성에 필요 |
| Node 2 전용 | zfw v0.9.22 RPM (`netfoundry/zfw`) |
| Ansible | ansible-core 2.14 이상 |
| Python 패키지 | scapy, flask, flask-cors, requests |

> 컨테이너에 `CAP_NET_RAW` + `CAP_NET_ADMIN` 권한이 필요합니다 (Quadlet unit에 설정됨).

## 배포

### 1. 인벤토리 설정

`ansible/inventory.ini`에서 각 노드의 실제 호스트 IP를 수정합니다:

```ini
[stateless_node]
node1 ansible_host=<Node1_호스트_IP> ansible_user=root

[stateful_node]
node2 ansible_host=<Node2_호스트_IP> ansible_user=root

[attack_node]
attacker ansible_host=<공격서버_IP> ansible_user=root

[guest_node]
guest ansible_host=<클라이언트_IP> ansible_user=root
```

### 2. Ansible 플레이북 실행

```bash
# 전체 4노드 배포
ansible-playbook -i ansible/inventory.ini ansible/playbook.yml

# 특정 역할만 배포
ansible-playbook -i ansible/inventory.ini ansible/playbook.yml --tags packet_logger
ansible-playbook -i ansible/inventory.ini ansible/playbook.yml --tags attack_server
ansible-playbook -i ansible/inventory.ini ansible/playbook.yml --tags guest_client
```

### 3. 컨테이너 이미지 수동 빌드 (선택 사항)

```bash
podman build --tag packet-logger:latest  --file src/Containerfile           ./src
podman build --tag attack-server:latest  --file attack-server/src/Containerfile  ./attack-server/src
podman build --tag guest-client:latest   --file guest-client/src/Containerfile   ./guest-client/src
```

## 사용 방법

배포 완료 후 브라우저에서 웹 대시보드에 접속합니다:

```
http://<공격서버_IP>:8000
```

대시보드에서 **공격 시작** 버튼을 누르면:
1. ACK-only 패킷이 두 노드로 동시 전송됩니다.
2. Node 1의 `ack_only` 카운터가 증가합니다 — 공격 패킷이 방화벽을 통과.
3. Node 2의 `ack_only` 카운터는 0에 가깝게 유지됩니다 — eBPF가 차단.
4. Guest Client 패널에서 두 노드 모두 정상 접속이 유지되는지 확인합니다.

### 서비스 상태 확인 (노드에서 직접)

```bash
# 서비스 상태
systemctl status packet-logger.service
systemctl status fw-init.service      # Node 2 전용
systemctl status zfw-rules.service    # Node 2 전용

# 방화벽 규칙 확인
nft list ruleset                      # Node 1
tc filter show dev eth0 ingress       # Node 2
/usr/sbin/zfw -L                      # Node 2
```

## 환경 변수

### packet-logger (Node 1·2)

| 변수 | 기본값 | 설명 |
|------|--------|------|
| `LISTEN_PORT` | `8080` | 모니터링할 TCP 포트 |
| `INTERFACE` | (전체) | 캡처 인터페이스. 비어 있으면 전체 |
| `API_PORT` | `9090` | REST API 포트 |
| `BUFFER_SIZE` | `500` | 메모리 내 패킷 버퍼 크기 |
| `NODE_NAME` | `unknown` | 노드 식별자 |
| `LOG_FILE` | `/var/log/packet-logger/packets.log` | 로그 파일 경로 |
| `MAX_LOG_SIZE_MB` | `100` | 로그 파일 최대 크기 (MB) |

### attack-server

| 변수 | 기본값 | 설명 |
|------|--------|------|
| `NODE1_IP` / `NODE2_IP` | `192.168.100.7/8` | 공격 대상 IP |
| `NODE1_API` / `NODE2_API` | `http://<IP>:9090` | 패킷 로거 API URL |
| `GUEST_API` | `http://192.168.100.6:7070` | 손님 클라이언트 API |
| `TARGET_PORT` | `8080` | 공격 대상 포트 |
| `WEB_PORT` | `8000` | 웹 대시보드 포트 |

### guest-client

| 변수 | 기본값 | 설명 |
|------|--------|------|
| `NODE1_IP` / `NODE2_IP` | `192.168.100.7/8` | 접속 테스트 대상 IP |
| `TARGET_PORT` | `8080` | 접속 포트 |
| `API_PORT` | `7070` | REST API 포트 |
| `TEST_INTERVAL` | `5.0` | 접속 테스트 주기 (초) |
| `CONNECT_TIMEOUT` | `2.0` | TCP 연결 타임아웃 (초) |

## REST API

### packet-logger (포트 9090)

```
GET /api/health               # 헬스 체크
GET /api/stats                # 통계: total, syn, ack_only, syn_ack, rst, fin
GET /api/packets?since_id=0&limit=100   # 패킷 버퍼 조회
```

> `ack_only` 값이 0보다 크면 ACK Flood 공격 패킷이 방화벽을 통과한 것입니다.

### attack-server (포트 8000)

```
POST   /api/attack            # 공격 시작 {targets, port, duration, count, rate}
DELETE /api/attack            # 공격 중지
GET    /api/attack/status     # 현재 공격 상태
GET    /api/nodes             # 두 노드 실시간 통계
GET    /api/nodes/<id>/packets # 노드별 패킷 목록
GET    /api/guest             # 손님 클라이언트 접속 결과
GET    /api/config            # 현재 설정 조회
```

### guest-client (포트 7070)

```
GET /api/health               # 헬스 체크
GET /api/results?since_id=0&limit=50   # 노드별 접속 결과
GET /api/summary              # success / refused / timeout / error 집계
```

## 디렉토리 구조

```
packet-logger/
├── ansible/
│   ├── inventory.ini             # 4노드 호스트·변수 정의
│   ├── playbook.yml              # 전체 배포 진입점
│   └── roles/
│       ├── packet_logger/        # Node 1·2 공통 (방화벽 분기 포함)
│       ├── attack_server/        # 공격 서버 배포
│       └── guest_client/         # 손님 클라이언트 배포
├── src/                          # packet-logger 애플리케이션
│   ├── packet_logger.py
│   ├── Containerfile
│   └── requirements.txt
├── attack-server/src/            # attack-server 애플리케이션
│   ├── attack_server.py
│   ├── static/index.html         # 웹 대시보드
│   ├── Containerfile
│   └── requirements.txt
├── guest-client/src/             # guest-client 애플리케이션
│   ├── guest_client.py
│   ├── Containerfile
│   └── requirements.txt
├── quadlet/                      # Quadlet unit 참조 파일
└── CLAUDE.md                     # Claude Code 가이드
```
