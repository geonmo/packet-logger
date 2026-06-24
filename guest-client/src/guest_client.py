#!/usr/bin/env python3
"""
Guest Client — 정상 사용자 접속 테스터
완전한 TCP 3-way handshake(SYN→SYN+ACK→ACK)로 두 노드에 접속 시도.
Stateless/Stateful 방화벽 모두 정상 연결은 허용해야 함을 검증.
"""

import os
import sys
import time
import socket
import threading
import logging
from collections import deque
from itertools import count as itercount

try:
    from flask import Flask, jsonify, request
    from flask_cors import CORS
except ImportError:
    print("ERROR: pip install flask flask-cors", file=sys.stderr)
    sys.exit(1)

# ── 설정 ──────────────────────────────────────────────────────────────────────
NODE1_IP    = os.environ.get('NODE1_IP',    '192.168.100.7')  # stateless 컨테이너
NODE2_IP    = os.environ.get('NODE2_IP',    '192.168.100.8')  # stateful 컨테이너
TARGET_PORT = int(os.environ.get('TARGET_PORT', '8080'))
API_PORT    = int(os.environ.get('API_PORT',    '7070'))
INTERVAL    = float(os.environ.get('TEST_INTERVAL', '5.0'))   # 접속 주기(초)
TIMEOUT     = float(os.environ.get('CONNECT_TIMEOUT', '2.0')) # TCP 타임아웃

NODES = {
    'node1': {'label': 'Node 1 — Stateless FW', 'ip': NODE1_IP, 'fw': 'stateless'},
    'node2': {'label': 'Node 2 — Stateful FW',  'ip': NODE2_IP, 'fw': 'stateful'},
}

# ── 공유 상태 ──────────────────────────────────────────────────────────────────
_id_gen   = itercount(1)
results   = {nid: deque(maxlen=100) for nid in NODES}
summary   = {nid: {'success': 0, 'refused': 0, 'timeout': 0, 'error': 0}
             for nid in NODES}
res_lock  = threading.Lock()
running   = True


def tcp_connect_test(node_id, ip, port, timeout):
    """
    정상 TCP 연결 시도: 실제 소켓을 열어 3-way handshake 수행.
    - 성공: 포트가 열려있어 연결됨 (ESTABLISHED)
    - refused: 포트에 아무도 안 듣고 있어 RST 수신 (패킷은 도달함)
    - timeout: 방화벽이 패킷을 DROP (도달 못함)
    - error: 기타 오류
    """
    start  = time.time()
    status = 'error'
    detail = ''

    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            status = 'success'
            detail = 'TCP 연결 성공 (ESTABLISHED)'
            sock.close()
    except ConnectionRefusedError:
        # RST 수신 → 패킷은 노드에 도달했으나 수신 프로세스 없음
        # Stateless/Stateful 모두 이 결과가 정상
        status = 'refused'
        detail = 'Connection refused (RST 수신 — 패킷 도달 확인됨)'
    except socket.timeout:
        # 패킷이 DROP됨 → 방화벽이 차단
        status = 'timeout'
        detail = f'연결 타임아웃 ({timeout}s) — 패킷이 차단됐을 가능성'
    except OSError as exc:
        status = 'error'
        detail = str(exc)

    elapsed = (time.time() - start) * 1000  # ms
    ts      = time.time()

    entry = {
        'id':      next(_id_gen),
        'ts':      ts,
        'ts_str':  time.strftime('%H:%M:%S', time.localtime(ts))
                   + f".{int((ts % 1) * 1000):03d}",
        'node_id': node_id,
        'ip':      ip,
        'port':    port,
        'status':  status,
        'detail':  detail,
        'ms':      round(elapsed, 1),
    }

    with res_lock:
        results[node_id].append(entry)
        summary[node_id][status] = summary[node_id].get(status, 0) + 1

    return entry


def test_loop():
    """백그라운드 테스트 루프."""
    global running
    logger = logging.getLogger('guest')
    logger.info(f"접속 테스트 루프 시작 (간격: {INTERVAL}s)")

    while running:
        for nid, cfg in NODES.items():
            entry = tcp_connect_test(nid, cfg['ip'], TARGET_PORT, TIMEOUT)
            icon  = {'success': '✓', 'refused': '⚡', 'timeout': '✗', 'error': '?'}
            logger.info(
                f"{icon.get(entry['status'], '?')} [{cfg['fw']:10s}] "
                f"{cfg['ip']}:{TARGET_PORT} → {entry['status']:8s} "
                f"({entry['ms']}ms) {entry['detail']}"
            )
        time.sleep(INTERVAL)


# ── Flask REST API ─────────────────────────────────────────────────────────────
app = Flask(__name__)
CORS(app)


@app.route('/api/health')
def health():
    return jsonify({'status': 'ok', 'interval': INTERVAL})


@app.route('/api/results')
def get_results():
    since_id = request.args.get('since_id', type=int, default=0)
    limit    = request.args.get('limit',    type=int, default=50)
    out = {}
    with res_lock:
        for nid in NODES:
            items = [r for r in results[nid] if r['id'] > since_id]
            out[nid] = {
                'label':    NODES[nid]['label'],
                'ip':       NODES[nid]['ip'],
                'fw_type':  NODES[nid]['fw'],
                'items':    items[-limit:],
                'summary':  dict(summary[nid]),
            }
    return jsonify(out)


@app.route('/api/summary')
def get_summary():
    with res_lock:
        return jsonify({
            nid: {**summary[nid], 'label': NODES[nid]['label'], 'fw': NODES[nid]['fw']}
            for nid in NODES
        })


# ── 메인 ───────────────────────────────────────────────────────────────────────
def main():
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s | %(levelname)s | %(message)s',
        datefmt='%Y-%m-%dT%H:%M:%S',
    )
    logging.getLogger('werkzeug').setLevel(logging.WARNING)
    logger = logging.getLogger('guest')

    logger.info("=" * 60)
    logger.info("정상 사용자 접속 테스터 시작")
    logger.info(f"  Node 1 (stateless): {NODE1_IP}:{TARGET_PORT}")
    logger.info(f"  Node 2 (stateful) : {NODE2_IP}:{TARGET_PORT}")
    logger.info(f"  테스트 간격       : {INTERVAL}s")
    logger.info(f"  REST API 포트     : {API_PORT}")
    logger.info("=" * 60)

    t = threading.Thread(target=test_loop, daemon=True)
    t.start()

    app.run(host='0.0.0.0', port=API_PORT, threaded=True)


if __name__ == '__main__':
    main()
