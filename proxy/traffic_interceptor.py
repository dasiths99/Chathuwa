"""
mitmproxy addon — captures real browser HTTPS traffic
and sends extracted flow features to FastAPI for ML classification.

Run: mitmproxy --listen-port 8080 -s proxy/traffic_interceptor.py
Browser proxy: 127.0.0.1:8080
CA cert install: visit http://mitm.it in browser after starting proxy
"""
import time, math, random, requests
from mitmproxy import http
from collections import defaultdict

API_URL = "http://localhost:5002/predict"

SKIP_DOMAINS = [
    "localhost", "127.0.0.1", "cdn.tailwindcss.com",
    "cdn.jsdelivr.net", "unpkg.com", "cdnjs.cloudflare.com",
    "mitm.it", "connectivitycheck.gstatic.com"
]

session_store = defaultdict(lambda: {
    "start_time": None, "packet_sizes": [],
    "inter_arrival_times": [], "last_time": None,
    "bytes_sent": 0, "bytes_received": 0,
    "request_count": 0, "failed_attempts": 0
})


def get_tls_version(flow):
    if flow.client_conn and hasattr(flow.client_conn, "tls_version") \
       and flow.client_conn.tls_version:
        v = flow.client_conn.tls_version
        return "TLS1.3" if "1.3" in str(v) else "TLS1.2"
    return "TLS1.3" if flow.request.scheme == "https" else "TLS1.2"


def get_ja3(flow):
    host = flow.request.pretty_host
    return f"ja3_{abs(hash(host)) % 100000:05d}"


def compute_entropy(sizes):
    if not sizes:
        return 0.0
    total = sum(sizes)
    if total == 0:
        return 0.0
    probs = [s/total for s in sizes if s > 0]
    return round(-sum(p * math.log2(p) for p in probs if p > 0), 4)


def compute_burstiness(iats):
    if len(iats) < 2:
        return 0.0
    mean = sum(iats) / len(iats)
    if mean == 0:
        return 0.0
    std = (sum((t-mean)**2 for t in iats)/len(iats)) ** 0.5
    return round(std / mean, 4)


def classify_protocol(flow):
    host = flow.request.pretty_host
    if ".onion" in host:
        return "Tor"
    if "dns" in host and flow.request.scheme == "https":
        return "DoH"
    if any(k in host for k in ["vpn", "tunnel", "nordvpn", "expressvpn"]):
        return "VPN"
    if flow.request.http_version == "HTTP/3":
        return "QUIC"
    if flow.request.scheme == "https":
        return "HTTPS"
    return "TLS"


class TrafficInterceptorAddon:

    def request(self, flow: http.HTTPFlow):
        host = flow.request.pretty_host
        if any(s in host for s in SKIP_DOMAINS):
            return
        now  = time.time()
        sess = session_store[host]
        if sess["start_time"] is None:
            sess["start_time"] = now
        sz = len(flow.request.content or b"")
        sess["bytes_sent"] += sz
        sess["packet_sizes"].append(sz)
        sess["request_count"] += 1
        if sess["last_time"] is not None:
            sess["inter_arrival_times"].append((now - sess["last_time"]) * 1000)
        sess["last_time"] = now

    def response(self, flow: http.HTTPFlow):
        host = flow.request.pretty_host
        if any(s in host for s in SKIP_DOMAINS):
            return
        now  = time.time()
        sess = session_store[host]
        if flow.response:
            sz = len(flow.response.content or b"")
            sess["bytes_received"] += sz
            sess["packet_sizes"].append(sz)
            if flow.response.status_code >= 400:
                sess["failed_attempts"] += 1

        flow_dur  = (now - sess["start_time"]) * 1000 if sess["start_time"] else 100.0
        pkt_sizes = sess["packet_sizes"] or [512]
        iats      = sess["inter_arrival_times"] or [50.0]
        b_sent    = max(sess["bytes_sent"], 1)
        b_recv    = max(sess["bytes_received"], 1)
        avg_pkt   = sum(pkt_sizes) / len(pkt_sizes)
        pkt_std   = (sum((x-avg_pkt)**2 for x in pkt_sizes) / len(pkt_sizes)) ** 0.5
        iat_mean  = sum(iats) / len(iats)
        entropy   = compute_entropy(pkt_sizes)
        burst     = compute_burstiness(iats)
        ratio     = round(b_sent / b_recv, 4)
        protocol  = classify_protocol(flow)
        tls_ver   = get_tls_version(flow)
        ja3       = get_ja3(flow)
        vpn = 1 if protocol == "VPN" or \
              any(k in host for k in ["vpn", "proxy", "hide", "anon"]) else 0
        tor = 1 if ".onion" in host or protocol == "Tor" else 0
        doh = 1 if protocol == "DoH" else 0

        record = {
            "source_ip":                 "127.0.0.1",
            "destination_ip":            host,
            "source_port":               random.randint(49152, 65535),
            "destination_port":          443 if flow.request.scheme == "https" else 80,
            "protocol":                  protocol,
            "tls_version":               tls_ver,
            "ja3_fingerprint":           ja3,
            "flow_duration_ms":          round(flow_dur, 2),
            "packet_count":              len(pkt_sizes),
            "avg_packet_size":           round(avg_pkt, 2),
            "packet_size_std":           round(pkt_std, 2),
            "inter_arrival_time_ms":     round(iat_mean, 2),
            "burstiness_score":          burst,
            "bytes_sent":                b_sent,
            "bytes_received":            b_recv,
            "upload_download_ratio":     ratio,
            "dns_over_https":            doh,
            "vpn_usage":                 vpn,
            "tor_usage":                 tor,
            "failed_connection_attempts":sess["failed_attempts"],
            "packet_entropy":            entropy,
            "session_start_hour":        int(time.strftime("%H")),
            "weekend_access":            1 if int(time.strftime("%w")) in [0, 6] else 0,
            "domain":                    host
        }
        try:
            r = requests.post(API_URL, json=record, timeout=2)
            if r.status_code == 200:
                res = r.json()
                print(f"[CAPTURED] {host:<35} → "
                      f"{res.get('policy_label','?'):<12} "
                      f"conf:{res.get('confidence',0)*100:.0f}%")
        except Exception as e:
            print(f"[ERROR] {host}: {e}")
        finally:
            if host in session_store:
                del session_store[host]


addons = [TrafficInterceptorAddon()]
