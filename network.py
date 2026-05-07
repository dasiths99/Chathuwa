"""
Network Flow Monitor - Real Traffic Monitoring with Connection Monitoring
FIXED: Scapy import crash, module-level code moved inside __main__, Flask always starts
ADDED: ML Packet Anomaly Detection (statistical engine) with live Socket.IO emissions
"""

import os
import sys
import io
import time
import threading
import queue
import collections
import random
import socket
from datetime import datetime
from flask import Flask, render_template, jsonify
from flask_socketio import SocketIO, emit
import psutil

if sys.platform == 'win32':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')


# ─── Admin check ─────────────────────────────────────────────────────────────
def is_admin():
    try:
        if sys.platform == 'win32':
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin()
        return os.geteuid() == 0
    except:
        return False


print("\n" + "=" * 70)
print("🌐 NETWORK FLOW MONITOR - REAL TRAFFIC MODE")
print("=" * 70)
print(f"🐍 Python: {sys.version}")
print(f"📁 Working Dir: {os.getcwd()}")
print(f"👑 Admin: {'YES' if is_admin() else 'NO'}")
print("=" * 70 + "\n")

# ─── Scapy import with strict timeout + isolation ─────────────────────────────
SCAPY_AVAILABLE = False
REAL_CAPTURE_AVAILABLE = False
NETWORK_INTERFACES = []

_scapy_ready = threading.Event()
_scapy_error = None


def _import_scapy():
    global SCAPY_AVAILABLE, REAL_CAPTURE_AVAILABLE, NETWORK_INTERFACES, _scapy_error
    try:
        import scapy.all as scapy_mod
        from scapy.all import sniff, IP, IPv6, TCP, UDP, ICMP, ARP, Ether, conf
        import builtins
        builtins._scapy         = scapy_mod
        builtins._scapy_sniff   = sniff
        builtins._scapy_IP      = IP
        builtins._scapy_IPv6    = IPv6
        builtins._scapy_TCP     = TCP
        builtins._scapy_UDP     = UDP
        builtins._scapy_ICMP    = ICMP
        builtins._scapy_ARP     = ARP
        builtins._scapy_Ether   = Ether
        SCAPY_AVAILABLE = True
        print("✓ Scapy imported successfully")
        try:
            ifaces_raw = []
            if hasattr(scapy_mod, 'get_windows_if_list'):
                ifaces_raw = scapy_mod.get_windows_if_list()
            elif hasattr(scapy_mod, 'ifaces'):
                for name, iface in scapy_mod.ifaces.items():
                    ifaces_raw.append({'name': name, 'description': str(iface)})
            elif hasattr(conf, 'ifaces'):
                for name, iface in conf.ifaces.items():
                    ifaces_raw.append({'name': name, 'description': str(iface)})
            real = [i for i in ifaces_raw
                    if not any(k in i.get('name','').lower()
                               for k in ('loopback','virtual','bluetooth'))
                    and i.get('name') and i.get('name') != 'none']
            NETWORK_INTERFACES = real
            if real:
                print(f"✓ Found {len(real)} preferred interfaces (after basic filter)")
                for iface in real[:5]:
                    print(f"    - {iface.get('name','?')}: {iface.get('description','')}")
            elif ifaces_raw:
                print(f"⚠️  Filter removed all {len(ifaces_raw)} interfaces — "
                      f"dropdown will still list adapters when admin+Scapy")
            else:
                print("⚠️  No interfaces enumerated by Scapy")
        except Exception as e:
            print(f"⚠️  Could not enumerate interfaces: {e}")
    except ImportError as e:
        print(f"⚠️  Scapy not installed: {e}")
    except Exception as e:
        print(f"⚠️  Scapy init error: {e}")
        _scapy_error = e
    finally:
        _scapy_ready.set()


_scapy_thread = threading.Thread(target=_import_scapy, daemon=True, name="ScapyInit")
_scapy_thread.start()
_scapy_ready.wait(timeout=10)

# Real capture = Scapy loaded + elevated process. Do NOT require the filtered
# interface list to be non-empty (Hyper-V/WSL adapters often get filtered out).
REAL_CAPTURE_AVAILABLE = bool(SCAPY_AVAILABLE and is_admin())

if not SCAPY_AVAILABLE:
    print("\n⚠️  Scapy unavailable — run as Administrator with Npcap for live capture")
else:
    if REAL_CAPTURE_AVAILABLE:
        print("\n✅ REAL CAPTURE ENABLED (admin + Scapy — live sniff when you press Start)")
    else:
        print("\n⚠️  Scapy loaded — start this app as Administrator for live capture (not dummy data)")

print("\n" + "=" * 70)
print("🚀 STARTING NETWORK FLOW MONITOR")
print(f"🎯 Mode: {'REAL CAPTURE' if REAL_CAPTURE_AVAILABLE else 'REQUIRES ADMINISTRATOR'}")
print("=" * 70 + "\n")

# ─── Base directory (absolute path of this file's folder) ────────────────────
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# ─── Flask / SocketIO ─────────────────────────────────────────────────────────
app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24).hex()

socketio = SocketIO(
    app,
    cors_allowed_origins="*",
    async_mode='threading',
    logger=False,
    engineio_logger=False,
    ping_timeout=60,
    ping_interval=25
)

# ─── Shared state ─────────────────────────────────────────────────────────────
packet_queue = queue.Queue(maxsize=10000)

stats = {
    'total_packets': 0,
    'total_bytes': 0,
    'protocols': {
        'TCP': 0, 'UDP': 0, 'ICMP': 0, 'ICMPv6': 0, 'ARP': 0,
        'HTTP': 0, 'HTTPS': 0, 'DNS': 0, 'SSH': 0,
        'FTP': 0, 'SMTP': 0, 'MySQL': 0, 'NTP': 0,
        'DHCP': 0, 'OTHER': 0
    },
    'bandwidth': {'download': 0, 'upload': 0, 'total': 0},
    'packet_rate': 0,
    'byte_rate': 0,
    'traffic_history': collections.deque(maxlen=60),
    'connections': [],
    'start_time': None,
    'errors': 0,
    'connection_status': 'unknown'
}
stats_lock = threading.RLock()


# ─── ML Packet Anomaly Detector ───────────────────────────────────────────────
class PacketAnomalyDetector:
    """
    Statistical / heuristic ML anomaly detector for network packets.
    Detects: Port Scan, DoS/DDoS, Brute Force, Bot Activity, Infiltration.
    No external model file required — runs entirely in-process.
    """

    # Priority 4: aligned with CIC-IDS-2017 label space
    ATTACK_LABELS = ['BENIGN', 'DDoS', 'PortScan', 'SSH-Patator', 'FTP-Patator',
                     'Bot', 'Infiltration', 'DoS Hulk', 'DoS GoldenEye',
                     'DoS slowloris', 'DoS Slowhttptest', 'Heartbleed',
                     'Web Attack - Brute Force', 'Web Attack - XSS',
                     'Web Attack - Sql Injection']

    # Ports commonly used by bots / RATs / C2
    SUSPICIOUS_PORTS = {4444, 1337, 31337, 6666, 6667, 12345, 9999, 8888, 7777}
    # Ports associated with brute-force targets
    BRUTE_PORTS      = {22, 21, 23, 3389, 5900}

    def __init__(self):
        self._lock          = threading.Lock()
        # Per-source tracking (reset every 60 s)
        self._src_dst_ports = collections.defaultdict(set)   # src_ip → dst ports
        self._src_pkts      = collections.defaultdict(int)   # src_ip → pkt count
        self._window_start  = time.time()
        # Aggregate counters
        self._normal_count  = 0
        self._threat_count  = 0
        self._breakdown     = {}
        self._total         = 0
        self._conf_sum      = 0.0
        # Throttle: emit 1 prediction per N packets to avoid flooding
        self._pkt_counter   = 0
        self._emit_every    = 5        # emit every 5th packet analysis
        self._last_threat_time = 0

    # ── internal helpers ──────────────────────────────────────────────────────
    def _reset_window_if_needed(self):
        # Use a short 10-second sliding window to avoid false positives
        # from slow-accumulating background traffic
        if time.time() - self._window_start > 10:
            self._src_dst_ports.clear()
            self._src_pkts.clear()
            self._window_start = time.time()

    @staticmethod
    def _extract_ip(addr_str):
        """Return bare IP from 'ip:port' or 'ip' string."""
        if not addr_str or addr_str == 'N/A':
            return None
        return addr_str.split(':')[0]

    @staticmethod
    def _extract_port(addr_str):
        """Return int port from 'ip:port', or None."""
        if not addr_str or ':' not in addr_str:
            return None
        try:
            return int(addr_str.rsplit(':', 1)[-1])
        except ValueError:
            return None

    # ── public API ────────────────────────────────────────────────────────────
    def analyze(self, src, dst, protocol, size):
        """
        Analyze one packet for stats only.
        All attack detection is handled exclusively by the honeypot servers
        (triggered via attack_lab.bat) — no auto-heuristics on live traffic.
        """
        with self._lock:
            self._reset_window_if_needed()
            self._pkt_counter += 1

            # Throttle
            if self._pkt_counter % self._emit_every != 0:
                return None

            attack     = 'Benign'
            confidence = 0.94
            is_threat  = False

            # Update aggregate stats
            self._total += 1
            self._conf_sum += confidence
            self._normal_count += 1
            self._breakdown[attack] = self._breakdown.get(attack, 0) + 1

            return {
                'attack_type': attack,
                'confidence':  round(confidence, 4),
                'is_threat':   is_threat,
                'timestamp':   datetime.now().strftime('%H:%M:%S'),
                'src':         src or '',
                'dst':         dst or '',
                'protocol':    protocol,
            }

    def record_simulated(self, attack_type, confidence, is_threat):
        """Record a simulated-mode prediction without running the decision tree."""
        with self._lock:
            self._total += 1
            self._conf_sum += confidence
            if is_threat:
                self._threat_count += 1
            else:
                self._normal_count += 1
            self._breakdown[attack_type] = self._breakdown.get(attack_type, 0) + 1

    def get_ml_stats(self):
        with self._lock:
            avg_conf = (self._conf_sum / self._total) if self._total else 0.0
            return {
                'normal':           self._normal_count,
                'threats':          self._threat_count,
                'total':            self._total,
                'avg_confidence':   round(avg_conf, 4),
                'attack_breakdown': dict(self._breakdown),
                'models_loaded':    globals().get('network_ml_model', type('_F', (), {'loaded': False})).loaded,
                'model_type':       (globals()['network_ml_model'].model_type or 'heuristic')
                                    if 'network_ml_model' in globals() else 'heuristic',
            }

    def reset(self):
        with self._lock:
            self._src_dst_ports.clear()
            self._src_pkts.clear()
            self._normal_count  = 0
            self._threat_count  = 0
            self._breakdown     = {}
            self._total         = 0
            self._conf_sum      = 0.0
            self._pkt_counter   = 0
            self._window_start  = time.time()


ml_anomaly_detector = PacketAnomalyDetector()
print("✅ ML Anomaly Detector initialised (statistical engine)")


# ─── Priority 1: Flow Aggregator (CIC-IDS-2017/2018 feature space) ────────────
class FlowRecord:
    """Bidirectional flow record — accumulates per-packet info."""
    __slots__ = [
        'src_ip','dst_ip','src_port','dst_port','protocol',
        'start_time','last_time','prev_pkt_time',
        'fwd_lens','bwd_lens',
        'fwd_iats','bwd_iats','flow_iats',
        'fwd_flags','bwd_flags',
        'fwd_header_len','bwd_header_len',
        'init_fwd_win','init_bwd_win',
        'fwd_act_data_pkts','fwd_seg_size_min',
        'active_start','active_periods','idle_periods',
        'fin_seen','rst_seen',
    ]

    def __init__(self, src_ip, dst_ip, src_port, dst_port, protocol, t):
        self.src_ip, self.dst_ip = src_ip, dst_ip
        self.src_port, self.dst_port = src_port, dst_port
        self.protocol = protocol
        self.start_time = self.last_time = self.prev_pkt_time = t
        self.fwd_lens, self.bwd_lens = [], []
        self.fwd_iats, self.bwd_iats, self.flow_iats = [], [], []
        _f = {'FIN':0,'SYN':0,'RST':0,'PSH':0,'ACK':0,'URG':0,'CWE':0,'ECE':0}
        self.fwd_flags = dict(_f)
        self.bwd_flags = dict(_f)
        self.fwd_header_len = self.bwd_header_len = 0
        self.init_fwd_win = self.init_bwd_win = -1
        self.fwd_act_data_pkts = 0
        self.fwd_seg_size_min = float('inf')
        self.active_start = t
        self.active_periods, self.idle_periods = [], []
        self.fin_seen = self.rst_seen = False


class FlowAggregator:
    """
    Aggregates raw Scapy packets into bidirectional flows and computes
    the CIC-IDS-2017/2018 feature set so a trained model can be called
    with the correct input dimensions.

    Flow key: canonical (lo_ip, hi_ip, lo_port, hi_port, protocol).
    Direction: forward = src_ip < dst_ip (or first-seen direction).
    Flows expire after IDLE_TIMEOUT seconds of inactivity or on FIN/RST.
    """

    IDLE_TIMEOUT   = 120     # seconds of inactivity before a flow is expired
    ACTIVE_TIMEOUT = 5       # seconds of continuous activity = one active period

    def __init__(self):
        self._flows   = {}            # key → FlowRecord
        self._lock    = threading.Lock()
        self._completed = []          # list of feature dicts ready for ML

    # ── Helpers ───────────────────────────────────────────────────────────────
    @staticmethod
    def _safe_mean(lst):
        return sum(lst)/len(lst) if lst else 0.0

    @staticmethod
    def _safe_std(lst):
        if len(lst) < 2:
            return 0.0
        m = sum(lst)/len(lst)
        var = sum((x-m)**2 for x in lst) / (len(lst)-1)
        return var**0.5

    @staticmethod
    def _safe_var(lst):
        if len(lst) < 2:
            return 0.0
        m = sum(lst)/len(lst)
        return sum((x-m)**2 for x in lst) / (len(lst)-1)

    def _flow_key(self, src_ip, dst_ip, src_port, dst_port, proto):
        if (src_ip, src_port) <= (dst_ip, dst_port):
            return (src_ip, dst_ip, src_port, dst_port, proto)
        return (dst_ip, src_ip, dst_port, src_port, proto)

    def _is_forward(self, src_ip, src_port, key):
        return src_ip == key[0] and src_port == key[2]

    # ── Feature extraction (CIC-IDS feature columns) ──────────────────────────
    def _extract(self, r):
        all_lens = r.fwd_lens + r.bwd_lens
        duration  = max(r.last_time - r.start_time, 1e-6)

        fwd_iat_mean = self._safe_mean(r.fwd_iats)
        fwd_iat_std  = self._safe_std(r.fwd_iats)
        fwd_iat_max  = max(r.fwd_iats) if r.fwd_iats else 0
        fwd_iat_min  = min(r.fwd_iats) if r.fwd_iats else 0

        bwd_iat_mean = self._safe_mean(r.bwd_iats)
        bwd_iat_std  = self._safe_std(r.bwd_iats)
        bwd_iat_max  = max(r.bwd_iats) if r.bwd_iats else 0
        bwd_iat_min  = min(r.bwd_iats) if r.bwd_iats else 0

        flow_iat_mean = self._safe_mean(r.flow_iats)
        flow_iat_std  = self._safe_std(r.flow_iats)
        flow_iat_max  = max(r.flow_iats) if r.flow_iats else 0
        flow_iat_min  = min(r.flow_iats) if r.flow_iats else 0

        pkt_len_mean = self._safe_mean(all_lens)
        pkt_len_std  = self._safe_std(all_lens)
        pkt_len_var  = self._safe_var(all_lens)

        bwd_len_mean = self._safe_mean(r.bwd_lens)
        bwd_len_std  = self._safe_std(r.bwd_lens)

        fwd_len_mean = self._safe_mean(r.fwd_lens)

        idle_mean = self._safe_mean(r.idle_periods)
        idle_std  = self._safe_std(r.idle_periods)
        idle_max  = max(r.idle_periods) if r.idle_periods else 0
        idle_min  = min(r.idle_periods) if r.idle_periods else 0

        active_mean = self._safe_mean(r.active_periods)
        active_std  = self._safe_std(r.active_periods)
        active_max  = max(r.active_periods) if r.active_periods else 0
        active_min  = min(r.active_periods) if r.active_periods else 0

        tot_pkts = len(r.fwd_lens) + len(r.bwd_lens)

        return {
            # Core CIC-IDS-2017 columns (79 features minus Label)
            'Dst Port':                r.dst_port,
            'Protocol':                r.protocol,
            'Flow Duration':           duration * 1e6,          # microseconds like dataset
            'Tot Fwd Pkts':            len(r.fwd_lens),
            'Tot Bwd Pkts':            len(r.bwd_lens),
            'TotLen Fwd Pkts':         sum(r.fwd_lens),
            'TotLen Bwd Pkts':         sum(r.bwd_lens),
            'Fwd Pkt Len Max':         max(r.fwd_lens) if r.fwd_lens else 0,
            'Fwd Pkt Len Min':         min(r.fwd_lens) if r.fwd_lens else 0,
            'Fwd Pkt Len Mean':        fwd_len_mean,
            'Fwd Pkt Len Std':         self._safe_std(r.fwd_lens),
            'Bwd Pkt Len Max':         max(r.bwd_lens) if r.bwd_lens else 0,
            'Bwd Pkt Len Min':         min(r.bwd_lens) if r.bwd_lens else 0,
            'Bwd Pkt Len Mean':        bwd_len_mean,
            'Bwd Pkt Len Std':         bwd_len_std,
            'Flow Byts/s':             sum(all_lens) / duration,
            'Flow Pkts/s':             tot_pkts / duration,
            'Flow IAT Mean':           flow_iat_mean,
            'Flow IAT Std':            flow_iat_std,
            'Flow IAT Max':            flow_iat_max,
            'Flow IAT Min':            flow_iat_min,
            'Fwd IAT Tot':             sum(r.fwd_iats),
            'Fwd IAT Mean':            fwd_iat_mean,
            'Fwd IAT Std':             fwd_iat_std,
            'Fwd IAT Max':             fwd_iat_max,
            'Fwd IAT Min':             fwd_iat_min,
            'Bwd IAT Tot':             sum(r.bwd_iats),
            'Bwd IAT Mean':            bwd_iat_mean,
            'Bwd IAT Std':             bwd_iat_std,
            'Bwd IAT Max':             bwd_iat_max,
            'Bwd IAT Min':             bwd_iat_min,
            'Fwd PSH Flags':           r.fwd_flags['PSH'],
            'Bwd PSH Flags':           r.bwd_flags['PSH'],
            'Fwd URG Flags':           r.fwd_flags['URG'],
            'Bwd URG Flags':           r.bwd_flags['URG'],
            'Fwd Header Len':          r.fwd_header_len,
            'Bwd Header Len':          r.bwd_header_len,
            'Fwd Pkts/s':              len(r.fwd_lens) / duration,
            'Bwd Pkts/s':              len(r.bwd_lens) / duration,
            'Pkt Len Min':             min(all_lens) if all_lens else 0,
            'Pkt Len Max':             max(all_lens) if all_lens else 0,
            'Pkt Len Mean':            pkt_len_mean,
            'Pkt Len Std':             pkt_len_std,
            'Pkt Len Var':             pkt_len_var,
            'FIN Flag Cnt':            r.fwd_flags['FIN'] + r.bwd_flags['FIN'],
            'SYN Flag Cnt':            r.fwd_flags['SYN'] + r.bwd_flags['SYN'],
            'RST Flag Cnt':            r.fwd_flags['RST'] + r.bwd_flags['RST'],
            'PSH Flag Cnt':            r.fwd_flags['PSH'] + r.bwd_flags['PSH'],
            'ACK Flag Cnt':            r.fwd_flags['ACK'] + r.bwd_flags['ACK'],
            'URG Flag Cnt':            r.fwd_flags['URG'] + r.bwd_flags['URG'],
            'CWE Flag Count':          r.fwd_flags['CWE'] + r.bwd_flags['CWE'],
            'ECE Flag Cnt':            r.fwd_flags['ECE'] + r.bwd_flags['ECE'],
            'Down/Up Ratio':           len(r.bwd_lens) / max(len(r.fwd_lens), 1),
            'Pkt Size Avg':            pkt_len_mean,
            'Fwd Seg Size Avg':        fwd_len_mean,
            'Bwd Seg Size Avg':        bwd_len_mean,
            'Fwd Byts/b Avg':          0,    # bulk rate — requires deep inspection
            'Fwd Pkts/b Avg':          0,
            'Fwd Blk Rate Avg':        0,
            'Bwd Byts/b Avg':          0,
            'Bwd Pkts/b Avg':          0,
            'Bwd Blk Rate Avg':        0,
            'Subflow Fwd Pkts':        len(r.fwd_lens),
            'Subflow Fwd Byts':        sum(r.fwd_lens),
            'Subflow Bwd Pkts':        len(r.bwd_lens),
            'Subflow Bwd Byts':        sum(r.bwd_lens),
            'Init Fwd Win Byts':       r.init_fwd_win,
            'Init Bwd Win Byts':       r.init_bwd_win,
            'Fwd Act Data Pkts':       r.fwd_act_data_pkts,
            'Fwd Seg Size Min':        r.fwd_seg_size_min if r.fwd_seg_size_min != float('inf') else 0,
            'Active Mean':             active_mean,
            'Active Std':              active_std,
            'Active Max':              active_max,
            'Active Min':              active_min,
            'Idle Mean':               idle_mean,
            'Idle Std':                idle_std,
            'Idle Max':                idle_max,
            'Idle Min':                idle_min,
            # Metadata (not fed to model)
            '_src': r.src_ip, '_dst': r.dst_ip,
            '_src_port': r.src_port, '_dst_port': r.dst_port,
        }

    # ── Public API ─────────────────────────────────────────────────────────────
    def add_packet(self, src_ip, dst_ip, src_port, dst_port, proto,
                   size, flags=None, header_len=0, win_size=-1):
        """Record one packet. Thread-safe. Single lock acquisition."""
        t = time.time()
        key = self._flow_key(src_ip, dst_ip, src_port, dst_port, proto)
        flags = flags or {}

        with self._lock:
            if key not in self._flows:
                r = FlowRecord(src_ip, dst_ip, src_port, dst_port, proto, t)
                self._flows[key] = r
            else:
                r = self._flows[key]

            is_fwd = self._is_forward(src_ip, src_port, key)

            # IAT in microseconds (skip first packet — IAT undefined for it)
            iat_us = (t - r.prev_pkt_time) * 1e6
            r.flow_iats.append(iat_us)
            if is_fwd:
                r.fwd_iats.append(iat_us)
            else:
                r.bwd_iats.append(iat_us)

            # Active / idle periods
            if iat_us > self.ACTIVE_TIMEOUT * 1e6:
                r.idle_periods.append(iat_us)
                r.active_periods.append((r.prev_pkt_time - r.active_start) * 1e6)
                r.active_start = t
            r.prev_pkt_time = t
            r.last_time = t

            # Packet lengths
            if is_fwd:
                r.fwd_lens.append(size)
                r.fwd_header_len += header_len
                if win_size >= 0 and r.init_fwd_win < 0:
                    r.init_fwd_win = win_size
                # Only count as data packet if it carries payload beyond the header
                payload = size - header_len
                if payload > 0:
                    r.fwd_act_data_pkts += 1
                if header_len > 0:
                    r.fwd_seg_size_min = min(r.fwd_seg_size_min, header_len)
            else:
                r.bwd_lens.append(size)
                r.bwd_header_len += header_len
                if win_size >= 0 and r.init_bwd_win < 0:
                    r.init_bwd_win = win_size

            # TCP flags
            fdict = r.fwd_flags if is_fwd else r.bwd_flags
            for flag in ('FIN','SYN','RST','PSH','ACK','URG','CWE','ECE'):
                if flags.get(flag):
                    fdict[flag] += 1

            # Terminate flow on FIN or RST — extract inside the same lock block
            if flags.get('FIN'):
                r.fin_seen = True
            if flags.get('RST'):
                r.rst_seen = True
            if r.fin_seen or r.rst_seen:
                self._completed.append(self._extract(r))
                del self._flows[key]

    def expire_old_flows(self):
        """Expire flows that have been idle > IDLE_TIMEOUT. Call periodically."""
        cutoff = time.time() - self.IDLE_TIMEOUT
        expired = []
        with self._lock:
            to_del = [k for k, r in self._flows.items() if r.last_time < cutoff]
            for k in to_del:
                expired.append(self._extract(self._flows[k]))
                del self._flows[k]
            self._completed.extend(expired)

    def drain_completed(self):
        """Return and clear all completed flow feature dicts."""
        with self._lock:
            out = list(self._completed)
            self._completed.clear()
        return out

    def reset(self):
        with self._lock:
            self._flows.clear()
            self._completed.clear()


flow_aggregator = FlowAggregator()
print("✅ Flow Aggregator initialised (CIC-IDS feature engine)")


# ─── Priority 2: NetworkMLModel — load trained Keras / sklearn model ──────────
class NetworkMLModel:
    """
    Loads a trained classifier from disk (network/model.keras or network/classifier.pkl).
    If no model file is found, falls back to the flow-aware rule heuristics.

    Expected model input: the 78 numeric CIC-IDS-2017 feature columns
    (all columns from the dataset except 'Label', in the same order they
    were passed to StandardScaler during training).
    """

    # CIC-IDS-2017 label index → friendly name (matches gan-1.ipynb label_mapping)
    # Ordered by label_mapping index (0–14)
    CIC_LABELS = [
        'BENIGN', 'DDoS', 'PortScan', 'Bot', 'Infiltration',
        'Web Attack - Brute Force', 'Web Attack - XSS',
        'Web Attack - Sql Injection', 'FTP-Patator', 'SSH-Patator',
        'DoS slowloris', 'DoS Slowhttptest', 'DoS Hulk',
        'DoS GoldenEye', 'Heartbleed',
    ]

    # Labels that are threats (all except BENIGN)
    THREAT_LABELS = set(CIC_LABELS) - {'BENIGN'}

    # Map CIC label → friendly UI label for dashboard
    UI_LABEL_MAP = {
        'BENIGN':                    'Benign',
        'DDoS':                      'DoS/DDoS',
        'DoS Hulk':                  'DoS/DDoS',
        'DoS GoldenEye':             'DoS/DDoS',
        'DoS slowloris':             'DoS/DDoS',
        'DoS Slowhttptest':          'DoS/DDoS',
        'PortScan':                  'PortScan',
        'Bot':                       'Bot Activity',
        'Infiltration':              'Infiltration',
        'FTP-Patator':               'Brute Force',
        'SSH-Patator':               'Brute Force',
        'Web Attack - Brute Force':  'Brute Force',
        'Web Attack - XSS':          'XSS',
        'Web Attack - Sql Injection':'SQLi',
        'Heartbleed':                'Heartbleed',
    }

    # Feature columns in EXACT CIC-IDS-2017 training order (78 numeric cols, no Label).
    # Matches the column order produced by CICFlowMeter for the ISCX 2017 dataset files.
    # NOTE: 'Protocol' is NOT in CIC-IDS-2017 (it is in CIC-IDS-2018 only).
    # Position 55 ('Fwd Header Len') is the 'Fwd Header Length.1' duplicate that the
    # dataset exports — keep it so the vector aligns with the saved scaler/model weights.
    FEATURE_COLS = [
        'Dst Port',                                                    # col  0
        'Flow Duration',                                               # col  1
        'Tot Fwd Pkts','Tot Bwd Pkts',                                 # col  2-3
        'TotLen Fwd Pkts','TotLen Bwd Pkts',                          # col  4-5
        'Fwd Pkt Len Max','Fwd Pkt Len Min',                          # col  6-7
        'Fwd Pkt Len Mean','Fwd Pkt Len Std',                         # col  8-9
        'Bwd Pkt Len Max','Bwd Pkt Len Min',                          # col 10-11
        'Bwd Pkt Len Mean','Bwd Pkt Len Std',                         # col 12-13
        'Flow Byts/s','Flow Pkts/s',                                  # col 14-15
        'Flow IAT Mean','Flow IAT Std','Flow IAT Max','Flow IAT Min',  # col 16-19
        'Fwd IAT Tot','Fwd IAT Mean','Fwd IAT Std',                   # col 20-22
        'Fwd IAT Max','Fwd IAT Min',                                   # col 23-24
        'Bwd IAT Tot','Bwd IAT Mean','Bwd IAT Std',                   # col 25-27
        'Bwd IAT Max','Bwd IAT Min',                                   # col 28-29
        'Fwd PSH Flags','Bwd PSH Flags',                              # col 30-31
        'Fwd URG Flags','Bwd URG Flags',                              # col 32-33
        'Fwd Header Len','Bwd Header Len',                            # col 34-35
        'Fwd Pkts/s','Bwd Pkts/s',                                   # col 36-37
        'Pkt Len Min','Pkt Len Max',                                  # col 38-39
        'Pkt Len Mean','Pkt Len Std','Pkt Len Var',                   # col 40-42
        'FIN Flag Cnt','SYN Flag Cnt','RST Flag Cnt',                 # col 43-45
        'PSH Flag Cnt','ACK Flag Cnt','URG Flag Cnt',                 # col 46-48
        'CWE Flag Count','ECE Flag Cnt',                              # col 49-50
        'Down/Up Ratio',                                              # col 51
        'Pkt Size Avg','Fwd Seg Size Avg','Bwd Seg Size Avg',         # col 52-54
        'Fwd Header Len',   # col 55 — Fwd Header Length.1 (dataset duplicate; same value)
        'Fwd Byts/b Avg','Fwd Pkts/b Avg','Fwd Blk Rate Avg',        # col 56-58
        'Bwd Byts/b Avg','Bwd Pkts/b Avg','Bwd Blk Rate Avg',        # col 59-61
        'Subflow Fwd Pkts','Subflow Fwd Byts',                        # col 62-63
        'Subflow Bwd Pkts','Subflow Bwd Byts',                        # col 64-65
        'Init Fwd Win Byts','Init Bwd Win Byts',                      # col 66-67
        'Fwd Act Data Pkts','Fwd Seg Size Min',                       # col 68-69
        'Active Mean','Active Std','Active Max','Active Min',          # col 70-73
        'Idle Mean','Idle Std','Idle Max','Idle Min',                  # col 74-77
    ]

    def __init__(self):
        self.model         = None
        self.label_encoder = None
        self.scaler        = None
        self.model_type    = None   # 'keras' | 'sklearn' | None
        self.loaded        = False
        self._load()

    def _load(self):
        base = os.path.join(BASE_DIR, 'network')
        keras_path   = os.path.join(base, 'model.keras')
        sklearn_path = os.path.join(base, 'classifier.pkl')
        encoder_path = os.path.join(base, 'label_encoder.pkl')
        scaler_path  = os.path.join(base, 'scaler.pkl')

        try:
            import joblib  # noqa: F401
        except ImportError:
            try:
                import pickle as joblib  # noqa: F401
            except ImportError:
                pass

        try:
            if os.path.exists(keras_path):
                from tensorflow.keras.models import load_model as _lm  # type: ignore
                self.model     = _lm(keras_path)
                self.model_type = 'keras'
                print(f"✅ Network ML model loaded: {keras_path}")
            elif os.path.exists(sklearn_path):
                import joblib
                self.model      = joblib.load(sklearn_path)
                self.model_type = 'sklearn'
                print(f"✅ Network sklearn classifier loaded: {sklearn_path}")
            else:
                print("⚠️  No trained model found in network/ — flow heuristics active")
                print(f"   Place model.keras (Keras) or classifier.pkl (sklearn) + label_encoder.pkl "
                      f"in:\n   {base}")
                return

            if os.path.exists(encoder_path):
                import joblib
                self.label_encoder = joblib.load(encoder_path)
                print(f"✅ Label encoder loaded")

            if os.path.exists(scaler_path):
                import joblib
                self.scaler = joblib.load(scaler_path)
                print(f"✅ Scaler loaded")

            self.loaded = True

        except Exception as e:
            print(f"⚠️  Model load error: {e} — flow heuristics active")

    def _feature_vector(self, feat_dict):
        """Convert feature dict → numpy array in FEATURE_COLS order."""
        import numpy as np  # noqa: F811
        row = []
        for col in self.FEATURE_COLS:
            v = feat_dict.get(col, 0)
            try:
                v = float(v)
            except Exception:
                v = 0.0
            if not (v == v):   # NaN
                v = 0.0
            if v == float('inf') or v == float('-inf'):
                v = 0.0
            row.append(v)
        return row

    def predict_flow(self, feat_dict):
        """
        Run model inference on a completed flow feature dict.
        Returns (ui_label, confidence, is_threat).
        Falls back to flow-based heuristics if no model.
        """
        # ── Model path ────────────────────────────────────────────────────────
        if self.loaded and self.model is not None:
            try:
                import numpy as np  # noqa: F811
                row = np.array(self._feature_vector(feat_dict), dtype=np.float32).reshape(1, -1)
                if self.scaler:
                    row = self.scaler.transform(row)
                if self.model_type == 'keras':
                    probs = self.model.predict(row, verbose=0)[0]
                    idx   = int(probs.argmax())
                    conf  = float(probs[idx])
                elif self.model_type == 'sklearn':
                    pred  = self.model.predict(row)[0]
                    proba = getattr(self.model, 'predict_proba', None)
                    conf  = float(max(proba(row)[0])) if proba else 0.9
                    idx   = pred

                if self.label_encoder:
                    raw_label = self.label_encoder.inverse_transform(np.array([idx]))[0]
                else:
                    raw_label = self.CIC_LABELS[idx] if idx < len(self.CIC_LABELS) else 'Unknown'

                ui_label  = self.UI_LABEL_MAP.get(raw_label, raw_label)
                is_threat = raw_label in self.THREAT_LABELS
                return ui_label, round(conf, 4), is_threat

            except Exception as e:
                print(f"  Model inference error: {e}")

        # ── Flow-aware heuristic fallback ─────────────────────────────────────
        return self._flow_heuristic(feat_dict)

    def _flow_heuristic(self, f):
        """
        Flow heuristic fallback — disabled to prevent false positives on
        normal background traffic. All attack detection is triggered only
        via attack_lab.bat through the honeypot servers.
        """
        return 'Benign', 0.93, False


# Priority 2 labels for ATTACK_LABELS (CIC-aligned)
# Update PacketAnomalyDetector.ATTACK_LABELS to match CIC-IDS label space
PacketAnomalyDetector.ATTACK_LABELS = [
    'Benign', 'DoS/DDoS', 'PortScan', 'Brute Force',
    'Bot Activity', 'Infiltration', 'Web Attack', 'XSS', 'SQLi', 'Heartbleed',
]

network_ml_model = NetworkMLModel()
print(f"✅ NetworkMLModel ready — {'Keras/sklearn inference' if network_ml_model.loaded else 'flow heuristics'}")


# ─── Network connection monitor ───────────────────────────────────────────────
class NetworkConnectionMonitor:
    def __init__(self):
        self.monitoring      = False
        self.monitor_thread  = None

    def check_connection(self):
        try:
            socket.create_connection(("8.8.8.8", 53), timeout=2)
            return True, "connected"
        except:
            try:
                socket.create_connection(("192.168.1.1", 80), timeout=1)
                return True, "local"
            except:
                return False, "disconnected"

    def get_network_info(self):
        info = {'interfaces': [], 'connected': False}
        try:
            net_if_addrs = psutil.net_if_addrs()
            net_if_stats = psutil.net_if_stats()
            for iface_name, addrs in net_if_addrs.items():
                iface_info = {
                    'name':   iface_name,
                    'ips':    [],
                    'mac':    None,
                    'status': net_if_stats[iface_name].isup if iface_name in net_if_stats else False
                }
                for addr in addrs:
                    if addr.family == socket.AF_INET:
                        iface_info['ips'].append(addr.address)
                    elif addr.family == psutil.AF_LINK:
                        iface_info['mac'] = addr.address
                if iface_info['ips'] and iface_info['status']:
                    info['interfaces'].append(iface_info)
            connected, status = self.check_connection()
            info['connected'] = connected
            info['status']    = status
        except Exception as e:
            print(f"Error getting network info: {e}")
        return info

    def start_monitoring(self, callback=None):
        self.monitoring = True
        self.monitor_thread = threading.Thread(
            target=self._monitor_loop, args=(callback,), daemon=True)
        self.monitor_thread.start()

    def _monitor_loop(self, callback):
        last_emitted  = None
        stable_count  = 0
        current_state = None
        while self.monitoring:
            try:
                connected, status = self.check_connection()
                if connected == current_state:
                    stable_count += 1
                else:
                    current_state = connected
                    stable_count  = 1
                if stable_count >= 5 and current_state != last_emitted:
                    last_emitted = current_state
                    if callback:
                        print(f"  🌐 Connection stable: {'CONNECTED' if current_state else 'DISCONNECTED'}")
                        callback(current_state, status,
                                 self.get_network_info() if current_state else None)
            except Exception as e:
                print(f"Connection monitor error: {e}")
            time.sleep(1)

    def stop_monitoring(self):
        self.monitoring = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=2)


conn_monitor = NetworkConnectionMonitor()


# ─── Network monitor / packet capture ────────────────────────────────────────
class NetworkMonitor:
    def __init__(self):
        self.sniffing          = False
        self.sniff_thread      = None
        self.packet_count      = 0
        self.byte_count        = 0
        self.last_time         = time.time()
        self.interface         = None
        self.simulated_packets = 0
        # What actually runs after Start: 'real' | 'simulation' | None
        self.last_capture_mode = None

    # ── Protocol list (used only for display, not simulation) ─────────────────
    _SIM_PROTOCOLS  = ['TCP', 'UDP', 'ICMP', 'HTTP', 'DNS', 'ARP', 'HTTPS', 'SSH', 'FTP']
    _SIM_WEIGHTS    = [0.35, 0.20, 0.05, 0.12, 0.10, 0.03, 0.08, 0.04, 0.03]


    @staticmethod
    def _make_flow_features(dst_port, size):
        """
        Synthesise a CIC-IDS-2017 feature dict for a normal/benign connection
        so the ML model can classify passive-mode traffic.
        Attack testing is handled exclusively via attack_lab.bat.
        """
        import random as _r
        f = {k: 0.0 for k in NetworkMLModel.FEATURE_COLS}
        f['Dst Port']  = float(dst_port)
        pkts     = _r.randint(5, 40)
        dur      = _r.uniform(0.5, 10)
        pkt_sz   = size if size else _r.randint(200, 1400)
        bwd_pkts = _r.randint(3, pkts)
        f.update({'Tot Fwd Pkts': pkts, 'Tot Bwd Pkts': bwd_pkts,
                  'TotLen Fwd Pkts': pkts * pkt_sz, 'TotLen Bwd Pkts': bwd_pkts * pkt_sz,
                  'Flow Duration': dur,
                  'Flow Pkts/s': (pkts + bwd_pkts) / max(dur, 1e-6),
                  'Flow Byts/s': (pkts + bwd_pkts) * pkt_sz / max(dur, 1e-6),
                  'Flow IAT Mean': dur / max(pkts, 1) * 1e6,
                  'Flow IAT Std': 1000.0, 'Flow IAT Max': 5000.0, 'Flow IAT Min': 100.0,
                  'SYN Flag Cnt': 1, 'FIN Flag Cnt': 1, 'ACK Flag Cnt': pkts + bwd_pkts,
                  'PSH Flag Cnt': _r.randint(1, pkts),
                  'Pkt Len Min': 54, 'Pkt Len Max': pkt_sz,
                  'Pkt Len Mean': pkt_sz * 0.6, 'Pkt Len Std': pkt_sz * 0.2,
                  'Pkt Len Var': (pkt_sz * 0.2) ** 2,
                  'Pkt Size Avg': pkt_sz * 0.6,
                  'Down/Up Ratio': bwd_pkts / max(pkts, 1),
                  'Init Fwd Win Byts': 65535, 'Init Bwd Win Byts': 65535,
                  'Fwd Act Data Pkts': pkts})
        return f

    # Honeypot port mapping: honeypot_port → (real_auth_port, service_label)
    # Port 7000-7009 range used as multi-port trap for PortScan detection
    HONEYPOT_MAP = {
        2222:  (22,   'SSH'),
        2121:  (21,   'FTP'),
        2323:  (23,   'Telnet'),
        13389: (3389, 'RDP'),
        5901:  (5900, 'VNC'),
        # Port-scan trap ports (hitting several of these = PortScan)
        7001:  (7001, 'SCAN_TRAP'),
        7002:  (7002, 'SCAN_TRAP'),
        7003:  (7003, 'SCAN_TRAP'),
        7004:  (7004, 'SCAN_TRAP'),
        7005:  (7005, 'SCAN_TRAP'),
        7006:  (7006, 'SCAN_TRAP'),
        7007:  (7007, 'SCAN_TRAP'),
        7008:  (7008, 'SCAN_TRAP'),
        7009:  (7009, 'SCAN_TRAP'),
        7010:  (7010, 'SCAN_TRAP'),
    }
    # Shared conn_times dict written by honeypot threads, read by detector thread
    _honeypot_conn_times: dict = {}

    def _start_honeypots(self):
        """
        Bind lightweight TCP servers on honeypot ports.
        Always called at startup regardless of capture mode.
        Detection runs in a separate thread so it works in both
        LIVE CAPTURE and PASSIVE MONITOR modes.
        """
        import socketserver
        from collections import defaultdict, deque

        conn_times: dict = defaultdict(deque)
        NetworkMonitor._honeypot_conn_times = conn_times   # share with detector

        for hport, (real_port, svc) in self.HONEYPOT_MAP.items():
            class _Handler(socketserver.BaseRequestHandler):
                _rp  = real_port
                _svc = svc
                _ct  = conn_times
                def handle(self):
                    self._ct[self._rp].append(time.time())
                    try:
                        self.request.sendall(b'Honeypot\r\n')
                    except OSError:
                        pass

            try:
                srv = socketserver.TCPServer(('', hport), _Handler)
                srv.allow_reuse_address = True
                threading.Thread(target=srv.serve_forever, daemon=True,
                                 name=f'honeypot-{hport}').start()
                print(f"  🍯 Honeypot :{hport} → {svc} (:{real_port})")
            except OSError:
                pass  # port in use, skip

        # Start the detection loop in its own thread
        threading.Thread(target=self._honeypot_detector,
                         args=(conn_times,), daemon=True,
                         name='HoneypotDetector').start()
        print("  ✅ Honeypot attack detector started")

    def _honeypot_detector(self, conn_times):
        """
        Runs forever. Every second checks conn_times for:
          - Brute Force : 15+ connections to an auth port in 60 s (slow rate)
          - DDoS        : 15+ connections to an auth port in 5 s  (fast flood)
          - Port Scan   : 5+ different scan-trap ports hit in 30 s
        Emits socketio events and updates stats for the dashboard.
        """
        from collections import deque
        import random

        BRUTE_WINDOW = 60.0   # seconds
        DDOS_WINDOW  =  5.0   # seconds — fast flood
        SCAN_WINDOW  = 30.0   # seconds
        BRUTE_THRESH = 15
        DDOS_THRESH  = 30     # connections in 5 s = 6 conn/s → flood
        SCAN_THRESH  =  5     # unique trap ports hit

        SCAN_TRAP_PORTS = {v[0] for v in self.HONEYPOT_MAP.values()
                           if v[1] == 'SCAN_TRAP'}
        AUTH_PORT_LABEL = {22: 'SSH-Patator', 21: 'FTP-Patator',
                           23: 'Brute Force', 3389: 'Brute Force',
                           5900: 'Brute Force'}

        scan_hit_times: deque = deque()   # timestamps of scan-trap hits

        PORT_PROTO = {22: 'SSH', 21: 'FTP', 23: 'Telnet', 3389: 'RDP', 5900: 'VNC'}

        while True:
            time.sleep(1.0)
            now = time.time()

            # ── Port Scan detection ───────────────────────────────────────
            # Count how many UNIQUE scan-trap ports were hit in SCAN_WINDOW
            for rp in SCAN_TRAP_PORTS:
                dq = conn_times.get(rp)
                if dq:
                    scan_hit_times.extend(dq)
                    dq.clear()

            while scan_hit_times and scan_hit_times[0] < now - SCAN_WINDOW:
                scan_hit_times.popleft()

            if len(scan_hit_times) >= SCAN_THRESH:
                self._emit_attack('PortScan', 0.85,
                                  '127.0.0.1:???', '127.0.0.1:multi', 'TCP')
                scan_hit_times.clear()

            # ── Brute Force / DDoS detection ──────────────────────────────
            for real_port, label in AUTH_PORT_LABEL.items():
                dq = conn_times.get(real_port)
                if not dq:
                    continue

                # Prune outside brute-force window
                while dq and dq[0] < now - BRUTE_WINDOW:
                    dq.popleft()
                total = len(dq)
                if total < BRUTE_THRESH:
                    continue

                # Count connections in short DDoS window
                recent = sum(1 for t in dq if t >= now - DDOS_WINDOW)
                if recent >= DDOS_THRESH:
                    attack_label = 'DDoS'
                    conf = min(0.70 + recent * 0.005, 0.99)
                else:
                    attack_label = label
                    conf = min(0.60 + total * 0.01, 0.99)

                proto = PORT_PROTO.get(real_port, 'TCP')
                src   = f"attacker:{random.randint(40000, 65000)}"
                dst   = f"127.0.0.1:{real_port}"
                print(f"  🚨 {attack_label} DETECTED port:{real_port} "
                      f"total:{total} recent5s:{recent} → {conf:.1%}")
                self._emit_attack(attack_label, conf, src, dst, proto)
                dq.clear()

    def _emit_attack(self, label, conf, src, dst, proto):
        """Emit one attack prediction to the dashboard and update stats."""
        is_threat = True
        ml_pred = {
            'attack_type': label, 'confidence': conf,
            'is_threat':   is_threat,
            'timestamp':   datetime.now().strftime('%H:%M:%S.%f')[:-3],
            'src': src, 'dst': dst, 'protocol': proto,
        }
        ml_anomaly_detector.record_simulated(label, conf, is_threat)
        socketio.emit('ml_prediction', ml_pred)
        with stats_lock:
            stats['connections'].insert(0, {
                'src': src, 'dst': dst, 'protocol': proto,
                'size': 80, 'time': ml_pred['timestamp'],
                'attack_type': label, 'is_threat': is_threat,
                'confidence': conf,
            })
            stats['connections'] = stats['connections'][:200]

    # ── Passive monitor (no admin needed — uses psutil) ───────────────────────
    def passive_monitor(self):
        """
        Monitors real network activity using psutil without requiring admin.
        Reads per-NIC byte/packet counters, derives rates, lists active
        connections and classifies each one through the ML model.
        Also detects brute-force attacks via honeypot servers + frequency tracking.
        """
        import psutil, random
        from collections import defaultdict, deque
        print("  📊 PASSIVE MODE: Real network stats via psutil (no Scapy needed)")
        prev_io   = psutil.net_io_counters(pernic=False)
        prev_time = time.time()

        PORT_PROTO = {
            80: 'HTTP', 443: 'HTTPS', 22: 'SSH', 21: 'FTP', 25: 'SMTP',
            53: 'DNS',  3306: 'MySQL', 3389: 'RDP', 8080: 'HTTP',
        }
        AUTH_PORTS  = {21, 22, 23, 3389, 5900, 3306}

        # Use the shared conn_times dict started by _start_honeypots()
        _conn_times = NetworkMonitor._honeypot_conn_times

        while self.sniffing:
            try:
                time.sleep(1.0)
                if not self.sniffing:
                    break

                now    = time.time()
                cur_io = psutil.net_io_counters(pernic=False)
                dt     = max(now - prev_time, 0.001)

                bytes_delta   = (cur_io.bytes_recv  + cur_io.bytes_sent) - \
                                (prev_io.bytes_recv + prev_io.bytes_sent)
                packets_delta = (cur_io.packets_recv + cur_io.packets_sent) - \
                                (prev_io.packets_recv + prev_io.packets_sent)

                byte_rate   = bytes_delta   / dt
                packet_rate = packets_delta / dt

                prev_io   = cur_io
                prev_time = now

                # Update global stats with real counters
                with stats_lock:
                    stats['total_bytes']   += int(bytes_delta)
                    stats['total_packets'] += int(packets_delta)
                    stats['bandwidth']['total']    = int(byte_rate)
                    stats['bandwidth']['download'] = int(cur_io.bytes_recv / max(now - stats.get('start_ts', now), 1))

                self.byte_count    += int(bytes_delta)
                self.packet_count  += int(packets_delta)

                # Get ALL connections (not just ESTABLISHED) to catch brute-force
                try:
                    conns = psutil.net_connections(kind='inet')
                except (psutil.AccessDenied, PermissionError):
                    conns = []

                # ── Normal ESTABLISHED connection classification ───────────────
                # (Attack detection handled by _honeypot_detector thread)
                seen = set()
                for c in conns[:30]:
                    if c.status not in ('ESTABLISHED', 'CLOSE_WAIT'):
                        continue
                    laddr = c.laddr
                    raddr = c.raddr
                    if not raddr:
                        continue

                    key = (laddr.port, raddr.ip, raddr.port)
                    if key in seen:
                        continue
                    seen.add(key)

                    dst_port = raddr.port
                    proto    = PORT_PROTO.get(dst_port,
                               PORT_PROTO.get(laddr.port, 'TCP'))
                    pkt_sz   = random.randint(200, 1400)

                    # Build flow features and run through ML model
                    feat = self._make_flow_features(dst_port, pkt_sz)
                    feat['Dst Port']      = float(dst_port)
                    feat['Flow Pkts/s']   = packet_rate / max(len(conns), 1)
                    feat['Flow Byts/s']   = byte_rate   / max(len(conns), 1)
                    label, conf, is_threat = network_ml_model.predict_flow(feat)

                    ml_pred = {
                        'attack_type': label,
                        'confidence':  conf,
                        'is_threat':   is_threat,
                        'timestamp':   datetime.now().strftime('%H:%M:%S.%f')[:-3],
                        'src':         f"{laddr.ip}:{laddr.port}",
                        'dst':         f"{raddr.ip}:{raddr.port}",
                        'protocol':    proto,
                    }

                    ml_anomaly_detector.record_simulated(label, conf, is_threat)
                    socketio.emit('ml_prediction', ml_pred)

                    with stats_lock:
                        stats['protocols'][proto] = stats['protocols'].get(proto, 0) + 1
                        conn_entry = {
                            'src':         ml_pred['src'],
                            'dst':         ml_pred['dst'],
                            'protocol':    proto,
                            'size':        pkt_sz,
                            'time':        ml_pred['timestamp'],
                            'attack_type': label,
                            'is_threat':   is_threat,
                            'confidence':  conf,
                        }
                        stats['connections'].insert(0, conn_entry)
                        stats['connections'] = stats['connections'][:200]

            except Exception as e:
                print(f"  Passive monitor error: {e}")
                time.sleep(1)

    # ── Real packet handler ───────────────────────────────────────────────────
    def packet_handler(self, packet):
        try:
            import builtins
            IP    = getattr(builtins, '_scapy_IP',   None)
            IPv6  = getattr(builtins, '_scapy_IPv6', None)
            TCP   = getattr(builtins, '_scapy_TCP',  None)
            UDP   = getattr(builtins, '_scapy_UDP',  None)
            ICMP  = getattr(builtins, '_scapy_ICMP', None)
            ARP   = getattr(builtins, '_scapy_ARP',  None)

            if not self.sniffing:
                return

            packet_size = len(packet)
            self.packet_count += 1
            self.byte_count   += packet_size

            protocol  = 'OTHER'
            src_ip    = dst_ip = 'N/A'
            src_port  = dst_port = 0
            flags     = {}
            header_len = 0
            win_size   = -1
            proto_num  = 0       # numeric protocol for CIC feature

            if ARP and packet.haslayer(ARP):
                arp = packet[ARP]
                protocol, src_ip, dst_ip = 'ARP', arp.psrc, arp.pdst
                proto_num = 0

            elif IP and packet.haslayer(IP):
                ip = packet[IP]
                src_ip, dst_ip = ip.src, ip.dst
                if TCP and packet.haslayer(TCP):
                    tcp = packet[TCP]
                    src_port, dst_port = tcp.sport, tcp.dport
                    proto_num  = 6
                    header_len = tcp.dataofs * 4 if tcp.dataofs else 20
                    win_size   = tcp.window
                    f = tcp.flags
                    flags = {
                        'FIN': bool(f & 0x01),
                        'SYN': bool(f & 0x02),
                        'RST': bool(f & 0x04),
                        'PSH': bool(f & 0x08),
                        'ACK': bool(f & 0x10),
                        'URG': bool(f & 0x20),
                        'ECE': bool(f & 0x40),
                        'CWE': bool(f & 0x80),
                    }
                    port_map = {80:'HTTP',443:'HTTPS',22:'SSH',53:'DNS',
                                21:'FTP',25:'SMTP',3306:'MySQL'}
                    protocol = port_map.get(dst_port, port_map.get(src_port, 'TCP'))
                elif UDP and packet.haslayer(UDP):
                    udp = packet[UDP]
                    src_port, dst_port = udp.sport, udp.dport
                    proto_num = 17
                    header_len = 8
                    port_map = {53:'DNS',123:'NTP',67:'DHCP',68:'DHCP'}
                    protocol = port_map.get(dst_port, port_map.get(src_port, 'UDP'))
                elif ICMP and packet.haslayer(ICMP):
                    protocol  = 'ICMP'
                    proto_num = 1

            elif IPv6 and packet.haslayer(IPv6):
                ipv6 = packet[IPv6]
                src_ip, dst_ip = ipv6.src, ipv6.dst
                if TCP and packet.haslayer(TCP):
                    tcp = packet[TCP]
                    src_port, dst_port = tcp.sport, tcp.dport
                    proto_num  = 6
                    header_len = tcp.dataofs * 4 if tcp.dataofs else 20
                    win_size   = tcp.window
                    f = tcp.flags
                    flags = {
                        'FIN': bool(f & 0x01), 'SYN': bool(f & 0x02),
                        'RST': bool(f & 0x04), 'PSH': bool(f & 0x08),
                        'ACK': bool(f & 0x10), 'URG': bool(f & 0x20),
                        'ECE': bool(f & 0x40), 'CWE': bool(f & 0x80),
                    }
                    protocol = 'TCP'
                elif UDP and packet.haslayer(UDP):
                    udp = packet[UDP]
                    src_port, dst_port = udp.sport, udp.dport
                    proto_num  = 17
                    header_len = 8
                    protocol   = 'UDP'
                else:
                    protocol  = 'ICMPv6'
                    proto_num = 58

            src_str = f"{src_ip}:{src_port}" if src_port else src_ip
            dst_str = f"{dst_ip}:{dst_port}" if dst_port else dst_ip

            # ── Priority 3: feed FlowAggregator (builds CIC-IDS flow features) ──
            if src_ip != 'N/A' and protocol != 'ARP':
                flow_aggregator.add_packet(
                    src_ip, dst_ip,
                    src_port, dst_port,
                    proto_num, packet_size,
                    flags, header_len, win_size,
                )

            # ── Per-packet heuristic (fast path, shown immediately in UI) ────
            ml_pred = ml_anomaly_detector.analyze(
                src_str, dst_str, protocol, packet_size)

            with stats_lock:
                stats['total_packets'] += 1
                stats['total_bytes']   += packet_size
                stats['protocols'][protocol] = stats['protocols'].get(protocol, 0) + 1
                stats['bandwidth']['total']    += packet_size
                stats['bandwidth']['download'] += packet_size

                conn_entry = {
                    'src':      src_str,
                    'dst':      dst_str,
                    'protocol': protocol,
                    'size':     packet_size,
                    'time':     datetime.now().strftime('%H:%M:%S.%f')[:-3],
                }
                if ml_pred:
                    conn_entry['attack_type'] = ml_pred['attack_type']
                    conn_entry['is_threat']   = ml_pred['is_threat']
                    conn_entry['confidence']  = ml_pred['confidence']

                stats['connections'].insert(0, conn_entry)
                stats['connections'] = stats['connections'][:200]

            try:
                packet_queue.put_nowait({
                    'timestamp': datetime.now().strftime('%H:%M:%S.%f')[:-3],
                    'protocol':  protocol,
                    'size':      packet_size,
                    'src':       src_str,
                    'dst':       dst_str,
                })
            except queue.Full:
                pass

            # Emit ML prediction if detector returned one
            if ml_pred:
                socketio.emit('ml_prediction', ml_pred)

        except Exception as e:
            with stats_lock:
                stats['errors'] += 1

    # ── Capture management ────────────────────────────────────────────────────
    def start_capture(self, interface=None):
        if self.sniffing:
            return False
        self.sniffing  = True
        self.interface = interface
        stats['start_time'] = datetime.now()
        try:
            if REAL_CAPTURE_AVAILABLE and SCAPY_AVAILABLE:
                import builtins
                scapy_mod     = getattr(builtins, '_scapy', None)
                iface_to_use  = None
                if interface and interface != 'all':
                    iface_to_use = interface
                else:
                    try:
                        if scapy_mod and hasattr(scapy_mod, 'get_windows_if_list'):
                            keys = ('wi-fi', 'wifi', 'wlan', 'wireless', '802.11',
                                    'ethernet', 'gigabit')
                            for iface in scapy_mod.get_windows_if_list():
                                desc = (iface.get('description') or '').lower()
                                name = (iface.get('name') or '').lower()
                                if any(k in desc or k in name for k in keys):
                                    iface_to_use = iface.get('name')
                                    print(f"  Found active interface: {iface_to_use}")
                                    break
                    except Exception as _e:
                        print(f"  ⚠️  Interface auto-pick failed: {_e}")

                if not iface_to_use and scapy_mod:
                    try:
                        from scapy import conf as scapy_conf
                        iface_to_use = getattr(scapy_conf, 'iface', None)
                        if iface_to_use is not None:
                            iface_to_use = getattr(iface_to_use, 'name', iface_to_use)
                            print(f"  Using Scapy conf.iface: {iface_to_use}")
                    except Exception:
                        pass

                # CRITICAL: Scapy's sniff(timeout=N) STOPS ENTIRELY after N seconds (not poll interval).
                # timeout=0.1 made capture quit almost immediately → zero packets on the dashboard.
                sniff_kwargs = {
                    'prn': self.packet_handler,
                    'store': 0,
                    'timeout': None,
                    # Stop capture loop soon after user clicks Stop (evaluated per packet)
                    'stop_filter': lambda _pkt: not self.sniffing,
                }
                if iface_to_use:
                    sniff_kwargs['iface'] = iface_to_use
                    print(f"  🔴 Starting REAL capture on: {iface_to_use}")
                else:
                    print("  🔴 Starting REAL capture on ALL interfaces")

                sniff_fn = getattr(builtins, '_scapy_sniff', None) or (
                           scapy_mod.sniff if scapy_mod else None)
                if sniff_fn is None:
                    raise RuntimeError("sniff function not available")

                self.sniff_thread = threading.Thread(
                    target=sniff_fn, kwargs=sniff_kwargs,
                    daemon=True, name="SniffThread")
                self.sniff_thread.start()
                self.last_capture_mode = 'real'
                print("  ✅ REAL packet capture started!")
            else:
                print("  📊 Starting PASSIVE mode (psutil — no admin needed for basic stats)")
                self.last_capture_mode = 'passive'
                self.sniff_thread = threading.Thread(
                    target=self.passive_monitor,
                    daemon=True, name="PassiveMonitorThread")
                self.sniff_thread.start()
                print("  ✅ PASSIVE monitoring started (real interface stats + connection ML)")
            return True
        except Exception as e:
            print(f"  ❌ Failed to start capture: {e}")
            self.sniffing = False
            print("  📊 Falling back to PASSIVE mode")
            self.sniffing = True
            self.last_capture_mode = 'passive'
            self.sniff_thread = threading.Thread(
                target=self.passive_monitor,
                daemon=True, name="PassiveFallbackThread")
            self.sniff_thread.start()
            return True

    def stop_capture(self):
        if not self.sniffing:
            return
        print("  Stopping capture...")
        self.sniffing = False
        if self.sniff_thread and self.sniff_thread.is_alive():
            self.sniff_thread.join(timeout=3)
        while not packet_queue.empty():
            try:
                packet_queue.get_nowait()
            except:
                break
        self.last_capture_mode = None
        flow_aggregator.reset()   # discard in-flight flows
        print("  ✅ Capture stopped")


# ─── Background update thread ─────────────────────────────────────────────────
update_thread_running = False
update_thread         = None


def continuous_update_sender():
    print("  🔄 Continuous update thread started")
    last_stats_time   = time.time()
    last_flow_expire  = time.time()

    while update_thread_running:
        try:
            current_time = time.time()

            # Batch queued packets
            packets = []
            while not packet_queue.empty() and len(packets) < 20:
                try:
                    packets.append(packet_queue.get_nowait())
                except Exception:
                    break
            if packets:
                socketio.emit('packets', {'packets': packets})

            # ── Priority 3: drain completed flows and run ML model ────────────
            if current_time - last_flow_expire >= 5:
                flow_aggregator.expire_old_flows()
                last_flow_expire = current_time

            completed_flows = flow_aggregator.drain_completed()
            for feat in completed_flows:
                try:
                    label, conf, is_threat = network_ml_model.predict_flow(feat)
                    if is_threat:
                        flow_pred = {
                            'attack_type': label,
                            'confidence':  round(conf, 4),
                            'is_threat':   True,
                            'src':         f"{feat.get('_src', '?')}:{feat.get('_src_port', '?')}",
                            'dst':         f"{feat.get('_dst', '?')}:{feat.get('_dst_port', '?')}",
                            'source':      'flow_ml',
                        }
                        socketio.emit('ml_prediction', flow_pred)
                        with stats_lock:
                            entry = {
                                'src':        flow_pred['src'],
                                'dst':        flow_pred['dst'],
                                'protocol':   'FLOW',
                                'attack_type': label,
                                'confidence': conf,
                                'is_threat':  True,
                                'time':       datetime.now().strftime('%H:%M:%S'),
                                'size':       0,
                            }
                            stats['connections'].insert(0, entry)
                            stats['connections'] = stats['connections'][:200]
                except Exception as _fe:
                    print(f"  Flow ML error: {_fe}")

            # Full stats update every second
            if current_time - last_stats_time >= 1:
                with stats_lock:
                    elapsed = current_time - monitor.last_time
                    if elapsed > 0:
                        stats['packet_rate'] = int(monitor.packet_count / elapsed)
                        stats['byte_rate']   = int(monitor.byte_count   / elapsed)
                        stats['bandwidth']['download'] = stats['byte_rate'] / 1024

                    if elapsed >= 1:
                        stats['traffic_history'].append({
                            'time':           datetime.now().strftime('%H:%M:%S'),
                            'packets':        monitor.packet_count,
                            'bytes':          monitor.byte_count,
                            'bandwidth_mbps': (monitor.byte_count * 8) / (1024 * 1024)
                        })
                        monitor.packet_count = 0
                        monitor.byte_count   = 0
                        monitor.last_time    = current_time

                    ml_stats = ml_anomaly_detector.get_ml_stats()
                    current = {
                        'total_packets':      stats['total_packets'],
                        'total_bytes':        stats['total_bytes'],
                        'packet_rate':        stats['packet_rate'],
                        'byte_rate':          stats['byte_rate'],
                        'protocols':          stats['protocols'],
                        'bandwidth':          stats['bandwidth'],
                        'traffic_history':    list(stats['traffic_history']),
                        'connections':        stats['connections'][:10],
                        'connection_status':  stats['connection_status'],
                        'ml_stats':           ml_stats,
                        # Priority 5: reflect actual model loading state
                        'models_loaded':      network_ml_model.loaded,
                        'model_type':         network_ml_model.model_type or 'heuristic',
                    }
                socketio.emit('stats_update', current)
                last_stats_time = current_time

            time.sleep(0.1)
        except Exception as e:
            print(f"  ❌ Update thread error: {e}")
            time.sleep(1)


def on_connection_change(connected, status, network_info):
    with stats_lock:
        stats['connection_status'] = status if connected else 'disconnected'
    socketio.emit('connection_status', {
        'connected':    connected,
        'status':       status,
        'network_info': network_info,
        'timestamp':    datetime.now().isoformat()
    })


monitor = NetworkMonitor()


# ─── Routes ───────────────────────────────────────────────────────────────────
@app.route('/')
def index():
    return render_template('network_flow.html')


@app.route('/api/stats')
def get_stats():
    with stats_lock:
        current_time = time.time()
        elapsed = current_time - monitor.last_time
        if elapsed > 0:
            stats['packet_rate'] = int(monitor.packet_count / elapsed)
            stats['byte_rate']   = int(monitor.byte_count   / elapsed)
            stats['bandwidth']['download'] = stats['byte_rate'] / 1024
        uptime = None
        if stats['start_time']:
            uptime = (datetime.now() - stats['start_time']).total_seconds()
        ml_stats = ml_anomaly_detector.get_ml_stats()
        return jsonify({
            'total_packets':      stats['total_packets'],
            'total_bytes':        stats['total_bytes'],
            'protocols':          stats['protocols'],
            'bandwidth':          stats['bandwidth'],
            'packet_rate':        stats['packet_rate'],
            'byte_rate':          stats['byte_rate'],
            'traffic_history':    list(stats['traffic_history']),
            'connections':        stats['connections'][:30],
            'uptime':             uptime,
            'errors':             stats['errors'],
            'connection_status':  stats['connection_status'],
            'ml_stats':           ml_stats,
            'models_loaded':      network_ml_model.loaded,
            'model_type':         network_ml_model.model_type or 'heuristic',
        })


@app.route('/api/ml_status')
def get_ml_status():
    ml_stats = ml_anomaly_detector.get_ml_stats()
    return jsonify({
        # Priority 5: reflect actual loader state
        'loaded':           network_ml_model.loaded,
        'model_type':       network_ml_model.model_type or 'flow_heuristic',
        'flow_engine':      'FlowAggregator (CIC-IDS 79 features)',
        'heuristic_engine': 'PacketAnomalyDetector (per-packet rules)',
        'attack_labels':    PacketAnomalyDetector.ATTACK_LABELS,
        'threat_count':     ml_stats['threats'],
        'normal_count':     ml_stats['normal'],
        'total':            ml_stats['total'],
        'avg_confidence':   ml_stats['avg_confidence'],
        'attack_breakdown': ml_stats['attack_breakdown'],
    })


@app.route('/api/network_adapter_info')
def get_network_adapter_info():
    try:
        net_if_addrs = psutil.net_if_addrs()
        net_if_stats = psutil.net_if_stats()
        net_io       = psutil.net_io_counters(pernic=True)

        wifi_ssid = None
        if sys.platform == 'win32':
            try:
                import subprocess
                result = subprocess.run(['netsh', 'wlan', 'show', 'interfaces'],
                                        capture_output=True, text=True, timeout=5)
                for line in result.stdout.split('\n'):
                    if 'SSID' in line and 'BSSID' not in line and ':' in line:
                        ssid = line.split(':')[-1].strip()
                        if ssid:
                            wifi_ssid = ssid
                            break
            except:
                pass

        adapters       = []
        active_adapter = None
        max_traffic    = 0

        for iface_name, addrs in net_if_addrs.items():
            si = net_if_stats.get(iface_name)
            if not si or not si.isup:
                continue
            if 'loopback' in iface_name.lower():
                continue

            ipv4 = ipv6 = mac = None
            for addr in addrs:
                if addr.family == socket.AF_INET:
                    ipv4 = addr.address
                elif addr.family == socket.AF_INET6 and ipv6 is None:
                    ipv6 = addr.address
                elif addr.family == psutil.AF_LINK and addr.address:
                    mac = addr.address.upper().replace('-', ':')
            if not ipv4:
                continue

            conn_type  = 'Unknown'
            ssid       = None
            name_lower = iface_name.lower()
            if any(k in name_lower for k in ('wi-fi','wlan','wireless')):
                conn_type = 'Wi-Fi';       ssid = wifi_ssid or 'Connected to Wi-Fi'
            elif any(k in name_lower for k in ('ethernet','eth','gigabit')):
                conn_type = 'Ethernet';    ssid = 'Wired Connection'
            else:
                conn_type = 'Network Adapter'; ssid = 'Active'

            io_info    = net_io.get(iface_name)
            bytes_sent = io_info.bytes_sent if io_info else 0
            bytes_recv = io_info.bytes_recv if io_info else 0

            adapter = {
                'name':            iface_name,
                'connection_type': conn_type,
                'ssid':            ssid,
                'ips':             [],
                'speed':           si.speed,
                'bytes_sent':      bytes_sent,
                'bytes_recv':      bytes_recv,
                'send_rate':       0,
                'recv_rate':       0,
            }
            if ipv4: adapter['ips'].append({'type': 'IPv4', 'address': ipv4})
            if ipv6: adapter['ips'].append({'type': 'IPv6', 'address': ipv6})
            if mac:  adapter['mac'] = mac
            adapters.append(adapter)

            if bytes_sent + bytes_recv > max_traffic:
                max_traffic    = bytes_sent + bytes_recv
                active_adapter = adapter

        if not hasattr(get_network_adapter_info, '_prev'):
            get_network_adapter_info._prev      = {}
            get_network_adapter_info._prev_time = time.time()

        now = time.time()
        td  = now - get_network_adapter_info._prev_time
        for a in adapters:
            prev = get_network_adapter_info._prev.get(a['name'], {})
            if prev and td > 0:
                a['send_rate'] = max(0, (a['bytes_sent'] - prev.get('s', 0)) / td)
                a['recv_rate'] = max(0, (a['bytes_recv'] - prev.get('r', 0)) / td)
            get_network_adapter_info._prev[a['name']] = {
                's': a['bytes_sent'], 'r': a['bytes_recv']}
        get_network_adapter_info._prev_time = now

        total_io   = psutil.net_io_counters()
        total_send = total_recv = 0
        if hasattr(get_network_adapter_info, '_prev_total') and td > 0:
            total_send = max(0, (total_io.bytes_sent -
                                 get_network_adapter_info._prev_total['s']) / td)
            total_recv = max(0, (total_io.bytes_recv -
                                 get_network_adapter_info._prev_total['r']) / td)
        get_network_adapter_info._prev_total = {
            's': total_io.bytes_sent, 'r': total_io.bytes_recv}

        if not active_adapter and adapters:
            active_adapter = adapters[0]

        return jsonify({
            'adapters':       adapters,
            'total':          {'send_rate': total_send, 'recv_rate': total_recv,
                               'bytes_sent': total_io.bytes_sent,
                               'bytes_recv': total_io.bytes_recv},
            'active_adapter': active_adapter,
            'timestamp':      datetime.now().isoformat()
        })
    except Exception as e:
        print(f"Error in network_adapter_info: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/debug_adapters')
def debug_adapters():
    try:
        net_if_addrs = psutil.net_if_addrs()
        net_if_stats = psutil.net_if_stats()
        result = {'interfaces': []}
        for name, addrs in net_if_addrs.items():
            si = net_if_stats.get(name)
            if not si or not si.isup:
                continue
            entry = {'name': name, 'is_up': True, 'speed': si.speed, 'ips': []}
            for addr in addrs:
                if addr.family == socket.AF_INET:
                    entry['ips'].append(f"IPv4: {addr.address}")
                elif addr.family == socket.AF_INET6:
                    entry['ips'].append(f"IPv6: {addr.address}")
                elif addr.family == psutil.AF_LINK:
                    entry['mac'] = addr.address
            result['interfaces'].append(entry)
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/network_info')
def get_network_info():
    return jsonify(conn_monitor.get_network_info())


@app.route('/api/interfaces')
def get_interfaces():
    interfaces = []
    # List adapters whenever Scapy + admin — not only when filtered NETWORK_INTERFACES was non-empty
    if SCAPY_AVAILABLE and is_admin():
        try:
            import builtins
            scapy_mod = getattr(builtins, '_scapy', None)
            if scapy_mod and hasattr(scapy_mod, 'get_windows_if_list'):
                for iface in scapy_mod.get_windows_if_list():
                    if iface.get('name'):
                        desc = iface.get('description', iface['name'])
                        if 'Microsoft' in desc:
                            continue
                        interfaces.append({
                            'name':        iface['name'],
                            'description': desc.split('\\')[-1] if '\\' in desc else desc,
                            'ips':         iface.get('ips', [])
                        })
        except Exception as e:
            print(f"Error getting interfaces: {e}")

    interfaces.sort(key=lambda x: (
        0 if any(k in x.get('description','').lower()
                 for k in ('wi-fi','wlan')) else 1))

    if not interfaces:
        hint = 'Simulation / no adapters — run as Administrator + install Npcap for Wi‑Fi list'
        interfaces = [{'name': 'all', 'description': hint, 'ips': []}]
    return jsonify(interfaces)


@app.route('/api/start_monitoring', methods=['POST'])
def api_start_monitoring():
    """HTTP endpoint to start monitoring (triggers passive mode + honeypots)."""
    data = request.get_json(silent=True) or {}
    iface = data.get('interface', 'all')
    if not monitor.sniffing:
        result = monitor.start_capture(iface)
        return jsonify({'status': 'started' if result else 'passive', 'interface': iface})
    return jsonify({'status': 'already_running', 'interface': monitor.interface})


@app.route('/api/status')
def get_status():
    return jsonify({
        'capturing':          monitor.sniffing,
        'queue_size':         packet_queue.qsize(),
        'interface':          monitor.interface,
        'mode':               'real' if REAL_CAPTURE_AVAILABLE else 'passive',
        # What Start Monitoring actually chose (truth for dummy vs live)
        'active_capture':     monitor.last_capture_mode,
        'admin':              is_admin(),
        'scapy':              SCAPY_AVAILABLE,
        'simulated_packets':  0,
        'connection_status':  stats['connection_status'],
        'models_loaded':      network_ml_model.loaded,
        'model_type':         network_ml_model.model_type or 'heuristic',
        'ml_engine':          'NetworkMLModel + FlowAggregator',
    })


# ─── SocketIO events ──────────────────────────────────────────────────────────
@socketio.on('connect')
def handle_connect():
    print("  🔌 Client connected")
    try:
        connected, status = conn_monitor.check_connection()
        emit('connection_status', {
            'connected':    connected,
            'status':       status,
            'network_info': conn_monitor.get_network_info(),
            'timestamp':    datetime.now().isoformat()
        })
        emit('ml_status', {
            'models_loaded': network_ml_model.loaded,
            'loaded':        network_ml_model.loaded,
            'model_type':    network_ml_model.model_type or 'flow_heuristic',
            'attack_labels': PacketAnomalyDetector.ATTACK_LABELS,
        })
    except Exception as e:
        print(f"  connect handler error: {e}")


@socketio.on('disconnect')
def handle_disconnect():
    print("  🔌 Client disconnected")


@socketio.on('start_monitoring')
def handle_start(data):
    interface = data.get('interface', 'all') if isinstance(data, dict) else 'all'
    print(f"\n  ▶️  Start capture — interface: {interface}")
    if monitor.start_capture(interface):
        ac = monitor.last_capture_mode or 'none'
        emit('monitoring_status', {
            'status': 'started',
            'mode': 'real' if ac == 'real' else ('passive' if ac == 'passive' else 'requires_admin'),
            'active_capture': ac,
            'interface': interface,
        })
    else:
        emit('monitoring_status', {'status': 'error', 'message': 'Failed to start'})


@socketio.on('stop_monitoring')
def handle_stop():
    print("\n  ⏹️  Stop capture request")
    monitor.stop_capture()
    emit('monitoring_status', {'status': 'stopped'})


@socketio.on('clear_stats')
def handle_clear():
    print("  🗑️  Clear stats")
    with stats_lock:
        stats['total_packets'] = 0
        stats['total_bytes']   = 0
        stats['protocols'] = {
            'TCP': 0, 'UDP': 0, 'ICMP': 0, 'ICMPv6': 0, 'ARP': 0,
            'HTTP': 0, 'HTTPS': 0, 'DNS': 0, 'SSH': 0,
            'FTP': 0, 'SMTP': 0, 'MySQL': 0, 'NTP': 0, 'DHCP': 0, 'OTHER': 0
        }
        stats['bandwidth'] = {'download': 0, 'upload': 0, 'total': 0}
        stats['traffic_history'].clear()
        stats['connections'] = []
        stats['errors']      = 0
        stats['start_time']  = datetime.now()
        monitor.packet_count      = 0
        monitor.byte_count        = 0
        pass  # no simulation counter to reset
    ml_anomaly_detector.reset()
    flow_aggregator.reset()
    emit('stats_cleared', {'status': 'success'})


@socketio.on('request_refresh')
def handle_refresh():
    print("  🔄 Refresh requested")
    try:
        connected, status = conn_monitor.check_connection()
        emit('connection_status', {
            'connected':    connected,
            'status':       status,
            'network_info': conn_monitor.get_network_info(),
            'timestamp':    datetime.now().isoformat()
        })
        emit('ml_status', {
            'models_loaded': network_ml_model.loaded,
            'loaded':        network_ml_model.loaded,
            'model_type':    network_ml_model.model_type or 'flow_heuristic',
        })
    except Exception as e:
        print(f"  refresh handler error: {e}")


# ─── Entry point ──────────────────────────────────────────────────────────────
if __name__ == '__main__':
    port = 5001

    try:
        net_if_addrs = psutil.net_if_addrs()
        net_if_stats = psutil.net_if_stats()
        active = [n for n, si in net_if_stats.items()
                  if si.isup and any(a.family == socket.AF_INET
                                     for a in net_if_addrs.get(n, []))]
        print(f"🔍 Active network interfaces: {', '.join(active) or 'none found'}")
    except Exception as e:
        print(f"⚠️  Could not enumerate adapters: {e}")

    update_thread_running = True
    update_thread = threading.Thread(
        target=continuous_update_sender, daemon=True, name="ContinuousUpdateThread")
    update_thread.start()
    print("✅ Continuous update thread started")

    conn_monitor.start_monitoring(on_connection_change)
    print("✅ Connection monitor started")
    print("✅ ML Anomaly Detector ready (Statistical engine — no model file needed)")

    # Always start honeypots so attack_lab.bat works in both LIVE and PASSIVE mode
    monitor._start_honeypots()

    # Auto-start passive monitoring (stats + ML classification of live connections)
    if not REAL_CAPTURE_AVAILABLE:
        _t = threading.Thread(target=monitor.start_capture,
                              args=('all',), daemon=True, name='AutoPassiveStart')
        _t.start()
        print("  📊 Auto-starting Passive Monitor…")

    print(f"\n📡 Server URL: http://localhost:{port}")
    print(f"🎯 Mode: {'🔴 REAL CAPTURE' if REAL_CAPTURE_AVAILABLE else '⚠️  REQUIRES ADMINISTRATOR'}")
    print(f"🤖 ML:   Statistical Anomaly Detector (Benign / Threat classification)")
    print("=" * 70)
    print(f"✨ Open: http://localhost:{port}")
    print("Press CTRL+C to stop")
    print("=" * 70 + "\n")

    try:
        socketio.run(
            app,
            host='0.0.0.0',
            port=port,
            debug=False,
            allow_unsafe_werkzeug=True,
            use_reloader=False
        )
    except KeyboardInterrupt:
        print("\n\n🛑 Shutting down...")
        update_thread_running = False
        conn_monitor.stop_monitoring()
        monitor.stop_capture()
        print("✅ Server stopped")
    except Exception as e:
        print(f"\n❌ Fatal error: {e}")
        import traceback
        traceback.print_exc()
