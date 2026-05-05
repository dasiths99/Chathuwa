"""
Network Flow Monitor - Real Traffic Monitoring with Connection Monitoring
FIXED: Scapy import crash, module-level code moved inside __main__, Flask always starts
ADDED: ML Packet Anomaly Detection (statistical engine) with live Socket.IO emissions
"""

import os
import sys
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
            if real and is_admin():
                REAL_CAPTURE_AVAILABLE = True
                print(f"✓ Found {len(real)} interfaces — REAL CAPTURE enabled")
                for iface in real[:5]:
                    print(f"    - {iface.get('name','?')}: {iface.get('description','')}")
            else:
                print(f"⚠️  {len(real)} interfaces found but real capture requires admin")
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

if not SCAPY_AVAILABLE:
    print("\n⚠️  Running in SIMULATION MODE (Scapy unavailable or timed-out)")
else:
    if REAL_CAPTURE_AVAILABLE:
        print("\n✅ REAL CAPTURE MODE ENABLED!")
    else:
        print("\n⚠️  Scapy loaded but running in SIMULATION MODE (no admin)")

print("\n" + "=" * 70)
print("🚀 STARTING NETWORK FLOW MONITOR")
print(f"🎯 Mode: {'REAL CAPTURE' if REAL_CAPTURE_AVAILABLE else 'SIMULATION MODE'}")
print("=" * 70 + "\n")

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

    ATTACK_LABELS = ['Benign', 'DoS/DDoS', 'Port Scan',
                     'Brute Force', 'Bot Activity', 'Infiltration']

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
        if time.time() - self._window_start > 60:
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
        Analyze one packet.  Returns a prediction dict or None
        (None means this packet is skipped for emit-throttling).
        """
        with self._lock:
            self._reset_window_if_needed()
            self._pkt_counter += 1

            src_ip   = self._extract_ip(src)
            dst_port = self._extract_port(dst)

            # Update trackers
            if src_ip:
                if dst_port:
                    self._src_dst_ports[src_ip].add(dst_port)
                self._src_pkts[src_ip] += 1

            # Throttle
            if self._pkt_counter % self._emit_every != 0:
                return None

            # ── Decision tree ──────────────────────────────────────────────
            n_ports = len(self._src_dst_ports.get(src_ip, set())) if src_ip else 0
            n_pkts  = self._src_pkts.get(src_ip, 0)             if src_ip else 0

            attack     = 'Benign'
            confidence = 0.94
            is_threat  = False

            if n_ports >= 20:
                attack, confidence, is_threat = 'Port Scan',   0.83, True
            elif n_pkts >= 300:
                attack, confidence, is_threat = 'DoS/DDoS',    0.88, True
            elif dst_port in self.SUSPICIOUS_PORTS:
                attack, confidence, is_threat = 'Bot Activity', 0.77, True
            elif dst_port in self.BRUTE_PORTS and n_pkts >= 25:
                attack, confidence, is_threat = 'Brute Force',  0.72, True
            elif protocol == 'UDP' and size > 1200 and n_pkts >= 40:
                attack, confidence, is_threat = 'DoS/DDoS',    0.69, True
            elif n_pkts >= 150 and protocol in ('TCP', 'UDP'):
                attack, confidence, is_threat = 'Infiltration', 0.65, True

            # Update aggregate stats
            self._total += 1
            self._conf_sum += confidence
            if is_threat:
                self._threat_count += 1
            else:
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
                'models_loaded':    True,
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

    # ── Simulation helpers ────────────────────────────────────────────────────
    _SIM_PROTOCOLS  = ['TCP', 'UDP', 'ICMP', 'HTTP', 'DNS', 'ARP', 'HTTPS', 'SSH', 'FTP']
    _SIM_WEIGHTS    = [0.35, 0.20, 0.05, 0.12, 0.10, 0.03, 0.08, 0.04, 0.03]

    # Threat scenarios injected periodically
    _THREAT_SCENARIOS = [
        {'protocol': 'TCP', 'dst_port': 4444,  'label': 'Bot Activity',  'conf': 0.82},
        {'protocol': 'TCP', 'dst_port': 22,    'label': 'Brute Force',   'conf': 0.74},
        {'protocol': 'UDP', 'size': 1480,      'label': 'DoS/DDoS',      'conf': 0.86},
        {'protocol': 'TCP', 'dst_port': 31337, 'label': 'Bot Activity',  'conf': 0.79},
        {'protocol': 'TCP', 'dst_port': 21,    'label': 'Brute Force',   'conf': 0.71},
    ]

    def generate_simulated_packet(self):
        protocol = random.choices(self._SIM_PROTOCOLS, weights=self._SIM_WEIGHTS)[0]
        src_ip   = f"192.168.{random.randint(1,254)}.{random.randint(1,254)}"
        dst_ip   = f"10.0.{random.randint(1,254)}.{random.randint(1,254)}"
        size     = (random.randint(500, 1500) if protocol == 'HTTP'  else
                    random.randint(64,  512)  if protocol == 'DNS'   else
                    random.randint(64,  1500))
        # Attach a plausible dst port
        port_map = {'HTTP': 80, 'HTTPS': 443, 'SSH': 22, 'DNS': 53,
                    'FTP': 21, 'SMTP': 25, 'MySQL': 3306}
        dst_port = port_map.get(protocol, random.randint(1024, 65535))
        return {
            'timestamp': datetime.now().strftime('%H:%M:%S.%f')[:-3],
            'protocol':  protocol,
            'size':      size,
            'src':       src_ip,
            'dst':       f"{dst_ip}:{dst_port}",
        }

    def simulate_traffic(self):
        print("  🎮 SIMULATION MODE: Generating test traffic...")
        scenario_counter = 0
        while self.sniffing:
            try:
                rate = random.randint(20, 60)
                for _ in range(rate):
                    if not self.sniffing:
                        break

                    # Every ~50 packets inject a threat scenario for realism
                    scenario_counter += 1
                    inject_threat = (scenario_counter % 50 == 0)

                    if inject_threat:
                        sc       = random.choice(self._THREAT_SCENARIOS)
                        src_ip   = f"192.168.{random.randint(1,254)}.{random.randint(1,254)}"
                        dst_ip   = f"10.0.{random.randint(1,254)}.{random.randint(1,254)}"
                        dst_port = sc.get('dst_port', random.randint(1024, 65535))
                        size     = sc.get('size', random.randint(64, 1500))
                        packet   = {
                            'timestamp': datetime.now().strftime('%H:%M:%S.%f')[:-3],
                            'protocol':  sc['protocol'],
                            'size':      size,
                            'src':       src_ip,
                            'dst':       f"{dst_ip}:{dst_port}",
                        }
                        ml_pred = {
                            'attack_type': sc['label'],
                            'confidence':  sc['conf'],
                            'is_threat':   True,
                            'timestamp':   packet['timestamp'],
                            'src':         packet['src'],
                            'dst':         packet['dst'],
                            'protocol':    packet['protocol'],
                        }
                        ml_anomaly_detector.record_simulated(sc['label'], sc['conf'], True)
                    else:
                        packet  = self.generate_simulated_packet()
                        ml_pred = {
                            'attack_type': 'Benign',
                            'confidence':  round(random.uniform(0.88, 0.98), 4),
                            'is_threat':   False,
                            'timestamp':   packet['timestamp'],
                            'src':         packet['src'],
                            'dst':         packet['dst'],
                            'protocol':    packet['protocol'],
                        }
                        ml_anomaly_detector.record_simulated('Benign', ml_pred['confidence'], False)

                    self.simulated_packets += 1
                    self.packet_count      += 1
                    self.byte_count        += packet['size']

                    with stats_lock:
                        stats['total_packets'] += 1
                        stats['total_bytes']   += packet['size']
                        proto = packet['protocol']
                        stats['protocols'][proto] = stats['protocols'].get(proto, 0) + 1
                        stats['bandwidth']['total']    += packet['size']
                        stats['bandwidth']['download'] += packet['size']

                        conn_entry = {
                            'src':         packet['src'],
                            'dst':         packet['dst'],
                            'protocol':    packet['protocol'],
                            'size':        packet['size'],
                            'time':        packet['timestamp'],
                            'attack_type': ml_pred['attack_type'],
                            'is_threat':   ml_pred['is_threat'],
                            'confidence':  ml_pred['confidence'],
                        }
                        stats['connections'].insert(0, conn_entry)
                        stats['connections'] = stats['connections'][:200]

                    try:
                        packet_queue.put_nowait(packet)
                    except queue.Full:
                        pass

                    # Emit ML prediction for every packet (real-time feed)
                    socketio.emit('ml_prediction', ml_pred)

                    time.sleep(1.0 / rate)

            except Exception as e:
                print(f"  Simulation error: {e}")
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
            src_port  = dst_port = 'N/A'

            if ARP and packet.haslayer(ARP):
                arp = packet[ARP]
                protocol, src_ip, dst_ip = 'ARP', arp.psrc, arp.pdst

            elif IP and packet.haslayer(IP):
                ip = packet[IP]
                src_ip, dst_ip = ip.src, ip.dst
                if TCP and packet.haslayer(TCP):
                    tcp = packet[TCP]
                    src_port, dst_port = tcp.sport, tcp.dport
                    port_map = {80:'HTTP',443:'HTTPS',22:'SSH',53:'DNS',
                                21:'FTP',25:'SMTP',3306:'MySQL'}
                    protocol = port_map.get(dst_port, port_map.get(src_port, 'TCP'))
                elif UDP and packet.haslayer(UDP):
                    udp = packet[UDP]
                    src_port, dst_port = udp.sport, udp.dport
                    port_map = {53:'DNS',123:'NTP',67:'DHCP',68:'DHCP'}
                    protocol = port_map.get(dst_port, port_map.get(src_port, 'UDP'))
                elif ICMP and packet.haslayer(ICMP):
                    protocol = 'ICMP'

            elif IPv6 and packet.haslayer(IPv6):
                ipv6 = packet[IPv6]
                src_ip, dst_ip = ipv6.src, ipv6.dst
                if TCP and packet.haslayer(TCP):
                    tcp = packet[TCP]
                    src_port, dst_port = tcp.sport, tcp.dport
                    protocol = 'TCP'
                elif UDP and packet.haslayer(UDP):
                    udp = packet[UDP]
                    src_port, dst_port = udp.sport, udp.dport
                    protocol = 'UDP'
                else:
                    protocol = 'ICMPv6'

            if protocol == 'OTHER':
                return

            src_str = f"{src_ip}:{src_port}" if src_port != 'N/A' else src_ip
            dst_str = f"{dst_ip}:{dst_port}" if dst_port != 'N/A' else dst_ip

            # ── ML anomaly detection ──────────────────────────────────────
            ml_pred = ml_anomaly_detector.analyze(src_str, dst_str, protocol, packet_size)

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
            if REAL_CAPTURE_AVAILABLE and is_admin() and SCAPY_AVAILABLE:
                import builtins
                scapy_mod     = getattr(builtins, '_scapy', None)
                iface_to_use  = None
                if interface and interface != 'all':
                    iface_to_use = interface
                else:
                    try:
                        if scapy_mod and hasattr(scapy_mod, 'get_windows_if_list'):
                            for iface in scapy_mod.get_windows_if_list():
                                desc = iface.get('description', '').lower()
                                if any(k in desc for k in ('wi-fi','wlan','ethernet')):
                                    iface_to_use = iface.get('name')
                                    print(f"  Found active interface: {iface_to_use}")
                                    break
                    except:
                        pass

                sniff_kwargs = {'prn': self.packet_handler, 'store': 0, 'timeout': 0.1}
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
                print("  ✅ REAL packet capture started!")
            else:
                print("  🎮 Starting SIMULATION mode")
                self.sniff_thread = threading.Thread(
                    target=self.simulate_traffic,
                    daemon=True, name="SimulationThread")
                self.sniff_thread.start()
                print("  ✅ SIMULATION started!")
            return True
        except Exception as e:
            print(f"  ❌ Failed to start capture: {e}")
            self.sniffing = False
            print("  🎮 Falling back to SIMULATION mode")
            self.sniffing = True
            self.sniff_thread = threading.Thread(
                target=self.simulate_traffic,
                daemon=True, name="SimFallbackThread")
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
        print("  ✅ Capture stopped")


# ─── Background update thread ─────────────────────────────────────────────────
update_thread_running = False
update_thread         = None


def continuous_update_sender():
    print("  🔄 Continuous update thread started")
    last_stats_time = time.time()

    while update_thread_running:
        try:
            current_time = time.time()

            # Batch queued packets
            packets = []
            while not packet_queue.empty() and len(packets) < 20:
                try:
                    packets.append(packet_queue.get_nowait())
                except:
                    break
            if packets:
                socketio.emit('packets', {'packets': packets})

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
                        'models_loaded':      True,
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
            'models_loaded':      True,
        })


@app.route('/api/ml_status')
def get_ml_status():
    ml_stats = ml_anomaly_detector.get_ml_stats()
    return jsonify({
        'loaded':           True,
        'model_type':       'Statistical Anomaly Detector',
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
    if REAL_CAPTURE_AVAILABLE:
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
        interfaces = [{'name': 'all', 'description': 'Simulation Mode', 'ips': []}]
    return jsonify(interfaces)


@app.route('/api/status')
def get_status():
    return jsonify({
        'capturing':          monitor.sniffing,
        'queue_size':         packet_queue.qsize(),
        'interface':          monitor.interface,
        'mode':               'real' if REAL_CAPTURE_AVAILABLE else 'simulation',
        'admin':              is_admin(),
        'scapy':              SCAPY_AVAILABLE,
        'simulated_packets':  monitor.simulated_packets,
        'connection_status':  stats['connection_status'],
        'models_loaded':      True,
        'ml_engine':          'Statistical Anomaly Detector',
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
        # Immediately tell the client the ML engine is ready
        emit('ml_status', {
            'models_loaded': True,
            'loaded':        True,
            'model_type':    'Statistical Anomaly Detector',
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
        mode = 'real' if REAL_CAPTURE_AVAILABLE else 'simulation'
        emit('monitoring_status', {'status': 'started', 'mode': mode, 'interface': interface})
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
        monitor.simulated_packets = 0
    ml_anomaly_detector.reset()
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
            'models_loaded': True,
            'loaded':        True,
            'model_type':    'Statistical Anomaly Detector',
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

    print(f"\n📡 Server URL: http://localhost:{port}")
    print(f"🎯 Mode: {'🔴 REAL CAPTURE' if REAL_CAPTURE_AVAILABLE else '🎮 SIMULATION MODE'}")
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
