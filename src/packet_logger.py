#!/usr/bin/env python3
"""
TCP Packet Logger with REST API
scapy로 패시브 캡처 + Flask REST API 제공
두 스레드로 동작: sniff 스레드 + Flask HTTP 스레드
"""

import os
import sys
import signal
import logging
import logging.handlers
import threading
import time
from collections import deque
from itertools import count as itercount

try:
    from scapy.all import sniff, TCP, IP, IPv6
except ImportError:
    print("ERROR: pip install scapy", file=sys.stderr)
    sys.exit(1)

try:
    from flask import Flask, jsonify, request
    from flask_cors import CORS
except ImportError:
    print("ERROR: pip install flask flask-cors", file=sys.stderr)
    sys.exit(1)

# ── 설정 ──────────────────────────────────────────────────────────────────────
LISTEN_PORT     = int(os.environ.get('LISTEN_PORT',     '8080'))
INTERFACE       = os.environ.get('INTERFACE')  or None   # 빈 문자열 → None
LOG_FILE        = os.environ.get('LOG_FILE',   '/var/log/packet-logger/packets.log')
LOG_LEVEL       = os.environ.get('LOG_LEVEL',  'INFO')
MAX_LOG_SIZE_MB = int(os.environ.get('MAX_LOG_SIZE_MB',    '100'))
LOG_BACKUP_CNT  = int(os.environ.get('LOG_BACKUP_COUNT',   '5'))
API_PORT        = int(os.environ.get('API_PORT',           '9090'))
BUFFER_SIZE     = int(os.environ.get('BUFFER_SIZE',        '500'))
NODE_NAME       = os.environ.get('NODE_NAME', 'unknown')

# ── 공유 상태 ──────────────────────────────────────────────────────────────────
_id_gen       = itercount(1)
packet_buffer = deque(maxlen=BUFFER_SIZE)
buf_lock      = threading.Lock()

stats = {
    'total':    0,
    'syn':      0,
    'ack_only': 0,   # SYN 없는 ACK - 공격 패킷 카운트
    'syn_ack':  0,
    'rst':      0,
    'fin':      0,
}

TCP_FLAGS = [
    (0x001, 'FIN'),
    (0x002, 'SYN'),
    (0x004, 'RST'),
    (0x008, 'PSH'),
    (0x010, 'ACK'),
    (0x020, 'URG'),
    (0x040, 'ECE'),
    (0x080, 'CWR'),
]


# ── 로깅 설정 ──────────────────────────────────────────────────────────────────
def setup_logging():
    log_dir = os.path.dirname(LOG_FILE)
    if log_dir:
        os.makedirs(log_dir, exist_ok=True)

    fmt = logging.Formatter(
        '%(asctime)s.%(msecs)03d | %(levelname)s | %(message)s',
        datefmt='%Y-%m-%dT%H:%M:%S'
    )
    logger = logging.getLogger('packet_logger')
    logger.setLevel(getattr(logging, LOG_LEVEL.upper(), logging.INFO))

    ch = logging.StreamHandler(sys.stdout)
    ch.setFormatter(fmt)
    logger.addHandler(ch)

    fh = logging.handlers.RotatingFileHandler(
        LOG_FILE,
        maxBytes=MAX_LOG_SIZE_MB * 1024 * 1024,
        backupCount=LOG_BACKUP_CNT,
    )
    fh.setFormatter(fmt)
    logger.addHandler(fh)
    return logger


def flags_to_str(f):
    parts = [name for bit, name in TCP_FLAGS if f & bit]
    return '|'.join(parts) if parts else 'NONE'


# ── 패킷 핸들러 ────────────────────────────────────────────────────────────────
def make_handler(logger):
    def handle(pkt):
        try:
            if TCP not in pkt:
                return

            tcp = pkt[TCP]
            f   = int(tcp.flags)
            flags_str = flags_to_str(f)

            if IP in pkt:
                ip  = pkt[IP]
                src = f"{ip.src}:{tcp.sport}"
                dst = f"{ip.dst}:{tcp.dport}"
                ver = "IPv4"
            elif IPv6 in pkt:
                ip6 = pkt[IPv6]
                src = f"[{ip6.src}]:{tcp.sport}"
                dst = f"[{ip6.dst}]:{tcp.dport}"
                ver = "IPv6"
            else:
                return

            direction = "INBOUND" if tcp.dport == LISTEN_PORT else "OUTBOUND"
            payload   = len(bytes(tcp.payload))
            ts        = time.time()

            entry = {
                'id':        next(_id_gen),
                'ts':        ts,
                'ts_str':    time.strftime('%H:%M:%S', time.localtime(ts))
                             + f".{int((ts % 1) * 1000):03d}",
                'version':   ver,
                'direction': direction,
                'src':       src,
                'dst':       dst,
                'flags':     flags_str,
                'seq':       tcp.seq,
                'ack':       tcp.ack,
                'window':    tcp.window,
                'payload_len': payload,
            }

            syn = bool(f & 0x002)
            ack = bool(f & 0x010)
            rst = bool(f & 0x004)
            fin = bool(f & 0x001)

            with buf_lock:
                packet_buffer.append(entry)
                stats['total'] += 1
                if syn and ack:
                    stats['syn_ack'] += 1
                elif syn:
                    stats['syn'] += 1
                elif ack and not syn and direction == "INBOUND":
                    stats['ack_only'] += 1   # 공격 패킷 (인바운드만)
                if rst:
                    stats['rst'] += 1
                if fin:
                    stats['fin'] += 1

            logger.info(
                f"{ver} TCP {direction} | {src} -> {dst} | "
                f"flags=[{flags_str}] seq={tcp.seq} ack={tcp.ack} len={payload}"
            )
        except Exception as exc:
            logger.error(f"패킷 파싱 오류: {exc}")

    return handle


# ── Flask REST API ─────────────────────────────────────────────────────────────
flask_app = Flask(__name__)
CORS(flask_app)


@flask_app.route('/api/health')
def health():
    return jsonify({
        'status':      'ok',
        'node':        NODE_NAME,
        'listen_port': LISTEN_PORT,
        'api_port':    API_PORT,
    })


@flask_app.route('/api/packets')
def get_packets():
    since_id = request.args.get('since_id', type=int, default=0)
    limit    = request.args.get('limit',    type=int, default=100)
    with buf_lock:
        result = [p for p in packet_buffer if p['id'] > since_id]
    return jsonify(result[-limit:])


@flask_app.route('/api/stats')
def get_stats():
    with buf_lock:
        return jsonify({
            **stats,
            'node':        NODE_NAME,
            'listen_port': LISTEN_PORT,
        })


def run_api(logger):
    import logging as _log
    _log.getLogger('werkzeug').setLevel(_log.WARNING)
    logger.info(f"REST API 리슨: 0.0.0.0:{API_PORT}")
    flask_app.run(host='0.0.0.0', port=API_PORT, threaded=True)


# ── 메인 ───────────────────────────────────────────────────────────────────────
def main():
    logger  = setup_logging()
    bpf     = f"tcp port {LISTEN_PORT}"
    iface_s = INTERFACE if INTERFACE else "all interfaces"

    logger.info("=" * 60)
    logger.info(f"TCP Packet Logger 시작  [Node: {NODE_NAME}]")
    logger.info(f"  모니터링 포트 : {LISTEN_PORT}")
    logger.info(f"  인터페이스    : {iface_s}")
    logger.info(f"  BPF 필터      : {bpf}")
    logger.info(f"  REST API 포트 : {API_PORT}")
    logger.info("=" * 60)

    api_thread = threading.Thread(target=run_api, args=(logger,), daemon=True)
    api_thread.start()

    def shutdown(sig, _):
        logger.info(f"신호({sig}) 수신, 종료합니다")
        sys.exit(0)

    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT,  shutdown)

    try:
        sniff(
            iface=INTERFACE,
            filter=bpf,
            prn=make_handler(logger),
            store=False,
        )
    except PermissionError:
        logger.error("권한 거부 - CAP_NET_RAW 필요")
        sys.exit(1)
    except Exception as exc:
        logger.error(f"치명적 오류: {exc}")
        sys.exit(1)


if __name__ == '__main__':
    main()
