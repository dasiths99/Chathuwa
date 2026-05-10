"""
Web Access Monitor with ML Attack Prediction
Integrates the trained RandomForest pipeline from Web-access-anolamy-detection.docx
"""

from flask import Flask, render_template, request, jsonify, send_from_directory, send_file, Response
from flask_socketio import SocketIO, emit
import threading
import time
import json
import io
import os
import numpy as np
from datetime import datetime
from urllib.parse import urlparse
import logging
import socket
import select

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config['SECRET_KEY'] = 'web-access-monitor-secret-key'
socketio = SocketIO(
    app,
    cors_allowed_origins="*",
    async_mode='threading',
    logger=False,
    engineio_logger=False,
)

# ─── ML Model Paths ───────────────────────────────────────────────────────────
RESTRICTED_DIR          = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'restricted')
PIPELINE_PATH           = os.path.join(RESTRICTED_DIR, 'attack_detection_pipeline.pkl')
ATTACK_MODEL_PATH       = os.path.join(RESTRICTED_DIR, 'attack_prediction_model.pkl')
COMPLETE_PIPELINE_PATH  = os.path.join(RESTRICTED_DIR, 'complete_prediction_pipeline.pkl')
LABEL_ENCODERS_PATH     = os.path.join(RESTRICTED_DIR, 'label_encoders.pkl')
TARGET_ENCODER_PATH     = os.path.join(RESTRICTED_DIR, 'target_encoder.pkl')
DATASET_PATH            = os.path.join(RESTRICTED_DIR, 'web-access-anolamy-detection_dataset.csv')

# ─── ML Detector ─────────────────────────────────────────────────────────────
class WebAccessMLDetector:
    """
    ML-based attack predictor for web access events.
    Uses the RandomForest pipeline trained in Web-access-anolamy-detection.docx
    """

    FEATURE_COLUMNS = [
        'time', 'end_time', 'user_id', 'source_ip', 'domain', 'domain_type',
        'access_type', 'request_type', 'protocol', 'vpn_usage', 'tor_usage',
        'dns_encryption', 'user_role', 'user_activity_type',
        'recent_web_access_attempts', 'status', 'attack_risk_level'
    ]
    UNKNOWN_TOKEN = '!!!UNKNOWN!!!'

    def __init__(self):
        self.model          = None
        self.label_encoders = None
        self.target_encoder = None
        self.loaded         = False
        self.load_status    = {}
        self.domain_profiles = {}
        self.column_defaults = {}
        self._load()

    def _load(self):
        try:
            import joblib

            # Try complete pipeline first
            for path, name in [(PIPELINE_PATH, 'attack_detection_pipeline'),
                                (COMPLETE_PIPELINE_PATH, 'complete_pipeline')]:
                if os.path.exists(path):
                    pipeline = joblib.load(path)
                    self.model          = pipeline.get('model')
                    self.label_encoders = pipeline.get('label_encoders')
                    self.target_encoder = pipeline.get('target_encoder')
                    self.load_status[name] = True
                    logger.info(f"✓ Loaded pipeline from {name}")
                    break

            # Load individual components if pipeline not found
            if self.model is None and os.path.exists(ATTACK_MODEL_PATH):
                self.model = joblib.load(ATTACK_MODEL_PATH)
                self.load_status['attack_model'] = True
                logger.info("✓ Attack prediction model loaded")

            if self.label_encoders is None and os.path.exists(LABEL_ENCODERS_PATH):
                self.label_encoders = joblib.load(LABEL_ENCODERS_PATH)
                self.load_status['label_encoders'] = True

            if self.target_encoder is None and os.path.exists(TARGET_ENCODER_PATH):
                self.target_encoder = joblib.load(TARGET_ENCODER_PATH)
                self.load_status['target_encoder'] = True

            self._load_dataset_profiles()

            self.loaded = True
            if self.model:
                logger.info(f"✅ Web ML detector ready — components: {list(self.load_status.keys())}")
            else:
                logger.warning("No ML model found - predictions disabled")

        except Exception as e:
            logger.error(f"❌ ML load error: {e}")
            self.loaded = True

    def _load_dataset_profiles(self):
        if not os.path.exists(DATASET_PATH):
            return
        try:
            import pandas as pd
            data = pd.read_csv(DATASET_PATH)
            profile_cols = ['domain_type', 'access_type', 'attack_risk_level']
            default_cols = [
                'user_id', 'source_ip', 'domain_type', 'access_type',
                'request_type', 'protocol', 'user_role', 'user_activity_type',
                'status', 'attack_risk_level'
            ]

            for col in default_cols:
                if col in data.columns and not data[col].dropna().empty:
                    self.column_defaults[col] = str(data[col].dropna().mode().iloc[0])

            if 'domain' in data.columns:
                domains = data['domain'].astype(str).str.lower()
                for domain, group in data.groupby(domains):
                    profile = {}
                    for col in profile_cols:
                        if col in group.columns and not group[col].dropna().empty:
                            profile[col] = str(group[col].dropna().mode().iloc[0])
                    if profile:
                        self.domain_profiles[domain] = profile

            self.load_status['dataset_profiles'] = True
        except Exception as e:
            logger.warning(f"Could not load dataset profiles: {e}")

    def _time_to_minutes(self, t_str):
        try:
            parts = t_str.split(':')
            return int(parts[0]) * 60 + int(parts[1])
        except:
            return 0

    def _encoder_default(self, col):
        if not self.label_encoders or col not in self.label_encoders:
            return self.UNKNOWN_TOKEN
        classes = list(self.label_encoders[col].classes_)
        if self.UNKNOWN_TOKEN in classes:
            return self.UNKNOWN_TOKEN
        return str(classes[0]) if classes else self.UNKNOWN_TOKEN

    def _safe_label(self, col, value):
        if value in (None, '') and col in self.column_defaults:
            value = self.column_defaults[col]
        if value not in (None, ''):
            value = str(value)
            if not self.label_encoders or col not in self.label_encoders:
                return value
            if value in set(self.label_encoders[col].classes_):
                return value
        return self._encoder_default(col)

    def _safe_encode(self, col, value):
        """Encode a value using the label encoder, handling unseen values"""
        if not self.label_encoders or col not in self.label_encoders:
            return 0
        le = self.label_encoders[col]
        try:
            return int(le.transform([self._safe_label(col, value)])[0])
        except ValueError:
            # Unseen value — map to class 0
            return int(le.transform([self._encoder_default(col)])[0])

    def _prediction_risk(self, label):
        return 'Low' if str(label).lower() in {'benign', 'normal'} else 'High'

    def _model_unavailable_result(self):
        return {
            'attack_type': 'ML Model Unavailable',
            'confidence': 0.0,
            'is_threat': False,
            'risk_level': 'Unknown',
            'domain_type': 'Unknown',
            'access_type': 'Unknown',
            'top_predictions': [],
            'method': 'Unavailable'
        }

    def predict(self, capture_entry):
        """
        Predict attack type for a captured URL/web access event.
        Returns a dict with prediction, confidence, and risk level.
        """
        domain   = capture_entry.get('domain', '')
        protocol = capture_entry.get('protocol', 'HTTP')

        if not self.model or not self.label_encoders or not self.target_encoder:
            return self._model_unavailable_result()

        # --- ML prediction ---
        try:
            now  = datetime.now()
            t_str = now.strftime('%H:%M:%S')
            domain_profile = self.domain_profiles.get(str(domain).lower(), {})
            domain_type = self._safe_label('domain_type', capture_entry.get('domain_type') or domain_profile.get('domain_type'))
            access_type = self._safe_label('access_type', capture_entry.get('access_type') or domain_profile.get('access_type'))

            features = {
                'time':                      self._time_to_minutes(t_str),
                'end_time':                  self._time_to_minutes(t_str) + 60,
                'user_id':                   self._safe_encode('user_id', capture_entry.get('user_id')),
                'source_ip':                 self._safe_encode('source_ip', capture_entry.get('source_ip')),
                'domain':                    self._safe_encode('domain', domain),
                'domain_type':               self._safe_encode('domain_type', domain_type),
                'access_type':               self._safe_encode('access_type', access_type),
                'request_type':              self._safe_encode('request_type', capture_entry.get('request_type')),
                'protocol':                  self._safe_encode('protocol', protocol),
                'vpn_usage':                 int(capture_entry.get('vpn_usage', 0) or 0),
                'tor_usage':                 1 if '.onion' in domain else 0,
                'dns_encryption':            1 if protocol == 'HTTPS' else 0,
                'user_role':                 self._safe_encode('user_role', capture_entry.get('user_role')),
                'user_activity_type':        self._safe_encode('user_activity_type', capture_entry.get('user_activity_type')),
                'recent_web_access_attempts': int(capture_entry.get('recent_web_access_attempts', 1) or 1),
                'status':                    self._safe_encode('status', capture_entry.get('status')),
                'attack_risk_level':         self._safe_encode('attack_risk_level', capture_entry.get('attack_risk_level') or domain_profile.get('attack_risk_level'))
            }

            import pandas as pd
            X = pd.DataFrame([features], columns=self.FEATURE_COLUMNS)
            pred_encoded = self.model.predict(X)[0]

            if hasattr(self.model, 'predict_proba'):
                proba = self.model.predict_proba(X)[0]
                confidence = float(proba.max())
                top_classes = [
                    {'label': str(self.target_encoder.inverse_transform([i])[0]),
                     'probability': float(p)}
                    for i, p in enumerate(proba)
                ]
                top_classes.sort(key=lambda x: -x['probability'])
            else:
                confidence = 0.80
                top_classes = []

            label = str(self.target_encoder.inverse_transform([pred_encoded])[0])
            is_threat = label.lower() not in {'benign', 'normal'}
            risk_level = self._prediction_risk(label)

            return {
                'attack_type': label,
                'confidence': round(confidence, 4),
                'is_threat': is_threat,
                'risk_level': risk_level,
                'domain_type': domain_type,
                'access_type': access_type,
                'top_predictions': top_classes[:3],
                'method': 'ML'
            }

        except Exception as e:
            logger.error(f"ML prediction error: {e}")
            return self._model_unavailable_result()

# ─── Global state ─────────────────────────────────────────────────────────────
proxy_active  = False
proxy_thread  = None
captured_urls = []
ml_detector   = WebAccessMLDetector()


def ml_model_available():
    return ml_detector.model is not None


current_stats = {
    'total_captured': 0,
    'recent_urls': [],
    'domain_frequency': {},
    'capture_rate': 0,
    'threat_count': 0,
    'benign_count': 0,
    'attack_breakdown': {},
    'ml_loaded': ml_model_available(),
    'ml_load_status': ml_detector.load_status
}


# ─── Proxy Handler ────────────────────────────────────────────────────────────
class ProxyHandler:
    def __init__(self, client_socket, client_address):
        self.client_socket  = client_socket
        self.client_address = client_address

    def handle(self):
        try:
            data = self.client_socket.recv(8192)
            if not data: return
            request_line = data.split(b'\r\n')[0].decode('utf-8', errors='ignore')
            parts = request_line.split()
            if len(parts) < 3: return
            method, url_or_path = parts[0], parts[1]
            if method == 'CONNECT':
                self.handle_connect(url_or_path)
            else:
                self.handle_http(method, url_or_path, data)
        except Exception as e:
            logger.error(f"Proxy handler error: {e}")
        finally:
            try: self.client_socket.close()
            except: pass

    def handle_connect(self, url_or_path):
        try:
            host_port = url_or_path.split(':')
            host = host_port[0]
            port = int(host_port[1]) if len(host_port) > 1 else 443
            self.capture_url(f"https://{host}/", 'HTTPS', request_type='CONNECT')
            self.client_socket.send(b'HTTP/1.1 200 Connection Established\r\n\r\n')
            target_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            target_socket.connect((host, port))
            self.client_socket.setblocking(0)
            target_socket.setblocking(0)
            sockets = [self.client_socket, target_socket]
            while True:
                try:
                    readable, _, _ = select.select(sockets, [], [], 10)
                    if not readable: continue
                    for s in readable:
                        try:
                            d = s.recv(8192)
                            if not d: return
                            (target_socket if s is self.client_socket else self.client_socket).send(d)
                        except: return
                except: break
        except Exception as e:
            try: self.client_socket.send(b'HTTP/1.1 502 Bad Gateway\r\n\r\n')
            except: pass

    def handle_http(self, method, url_or_path, request_data):
        try:
            if url_or_path.startswith(('http://', 'https://')):
                full_url = url_or_path
            else:
                headers = request_data.split(b'\r\n')
                host = None
                for h in headers:
                    if h.lower().startswith(b'host:'):
                        host = h.split(b':')[1].strip().decode('utf-8')
                        break
                full_url = f"http://{host}{url_or_path}" if host else f"http://{url_or_path}"
            self.capture_url(full_url, 'HTTP', request_type=method)
            parsed = urlparse(full_url)
            host = parsed.netloc.split(':')[0]
            port = int(parsed.netloc.split(':')[1]) if ':' in parsed.netloc else 80
            target = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            target.connect((host, port))
            target.send(request_data)
            resp = target.recv(8192)
            self.client_socket.send(resp)
            target.close()
        except Exception as e:
            try: self.client_socket.send(b'HTTP/1.1 502 Bad Gateway\r\n\r\n')
            except: pass

    def capture_url(self, url, protocol='HTTP', request_type=None):
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lstrip('www.')
            if not domain: domain = parsed.path.split('/')[0]

            entry = {
                'url': url, 'domain': domain, 'protocol': protocol,
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3],
                'source': 'proxy',
                'source_ip': self.client_address[0] if self.client_address else None,
                'request_type': request_type or ('CONNECT' if protocol == 'HTTPS' else 'GET')
            }

            # ML Prediction
            pred = ml_detector.predict(entry)
            entry['ml_prediction'] = pred
            entry['attack_type']   = pred['attack_type']
            entry['is_threat']     = pred['is_threat']
            entry['risk_level']    = pred['risk_level']
            entry['confidence']    = pred['confidence']

            captured_urls.append(entry)
            if len(captured_urls) > 500: captured_urls.pop(0)

            self.update_stats(entry)
            socketio.emit('url_captured', self._safe_entry(entry))
            logger.info(f"Captured: {url} [{protocol}] → {pred['attack_type']} ({pred['confidence']:.2f})")

        except Exception as e:
            logger.error(f"Capture error: {e}")

    def _safe_entry(self, entry):
        """Return a JSON-safe version of the entry"""
        return {
            'url': entry['url'], 'domain': entry['domain'],
            'protocol': entry['protocol'], 'timestamp': entry['timestamp'],
            'attack_type': entry.get('attack_type', 'Unknown'),
            'is_threat': entry.get('is_threat', False),
            'risk_level': entry.get('risk_level', 'Low'),
            'confidence': entry.get('confidence', 0)
        }

    def update_stats(self, entry):
        global current_stats
        current_stats['total_captured'] = len(captured_urls)
        current_stats['recent_urls'] = [
            {
                'url': u['url'], 'domain': u.get('domain',''),
                'protocol': u.get('protocol','HTTP'), 'time': u['timestamp'],
                'attack_type': u.get('attack_type','Unknown'),
                'is_threat': u.get('is_threat', False),
                'risk_level': u.get('risk_level','Low'),
                'confidence': u.get('confidence', 0)
            }
            for u in captured_urls[-50:]
        ]
        domain = entry['domain']
        current_stats['domain_frequency'][domain] = current_stats['domain_frequency'].get(domain, 0) + 1
        if len(current_stats['domain_frequency']) > 20:
            current_stats['domain_frequency'] = dict(
                sorted(current_stats['domain_frequency'].items(),
                       key=lambda x: x[1], reverse=True)[:20])

        if entry.get('is_threat'):
            current_stats['threat_count'] += 1
        else:
            current_stats['benign_count'] += 1

        atk = entry.get('attack_type', 'Unknown')
        current_stats['attack_breakdown'][atk] = current_stats['attack_breakdown'].get(atk, 0) + 1

        if len(captured_urls) > 1:
            try:
                t1 = datetime.strptime(captured_urls[0]['timestamp'], '%Y-%m-%d %H:%M:%S.%f')
                t2 = datetime.strptime(captured_urls[-1]['timestamp'], '%Y-%m-%d %H:%M:%S.%f')
                td = (t2 - t1).total_seconds()
                if td > 0:
                    current_stats['capture_rate'] = round((len(captured_urls) / td) * 60, 2)
            except: pass

        socketio.emit('stats_update', current_stats)


class ProxyServer:
    def __init__(self, port=8080):
        self.port = port; self.running = False; self.server_socket = None

    def start(self):
        self.running = True
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind(('0.0.0.0', self.port))
            self.server_socket.listen(5)
            logger.info(f"Proxy server started on port {self.port}")
            while self.running:
                try:
                    cs, ca = self.server_socket.accept()
                    t = threading.Thread(target=ProxyHandler(cs, ca).handle)
                    t.daemon = True; t.start()
                except: pass
        except Exception as e:
            logger.error(f"Proxy error: {e}")
        finally:
            if self.server_socket: self.server_socket.close()

    def stop(self):
        self.running = False
        if self.server_socket: self.server_socket.close()


proxy = ProxyServer(port=8080)


# ─── Routes ───────────────────────────────────────────────────────────────────
@app.route('/')
def index():
    return render_template('web_accessing.html')


@app.route('/api/stats')
def get_stats():
    return jsonify(current_stats)


@app.route('/api/urls')
def get_urls():
    limit = request.args.get('limit', 100, type=int)
    return jsonify(captured_urls[-limit:])


@app.route('/api/ml_status')
def get_ml_status():
    return jsonify({
        'loaded': ml_model_available(),
        'load_status': ml_detector.load_status,
        'model_available': ml_model_available(),
        'threat_count': current_stats['threat_count'],
        'benign_count': current_stats['benign_count'],
        'attack_breakdown': current_stats['attack_breakdown']
    })


@app.route('/api/clear', methods=['POST'])
def clear_stats():
    global captured_urls, current_stats
    captured_urls = []
    current_stats = {
        'total_captured': 0, 'recent_urls': [], 'domain_frequency': {},
        'capture_rate': 0, 'threat_count': 0, 'benign_count': 0,
        'attack_breakdown': {}, 'ml_loaded': ml_model_available(),
        'ml_load_status': ml_detector.load_status
    }
    socketio.emit('stats_cleared')
    socketio.emit('stats_update', current_stats)
    return jsonify({'status': 'success'})


@app.route('/api/report/download')
def download_report():
    """Generate and download an HTML report for web access monitoring"""
    now = datetime.now()
    html = _build_web_report(now, list(captured_urls[-100:]), dict(current_stats))
    buf  = io.BytesIO(html.encode('utf-8'))
    buf.seek(0)
    filename = f"web_access_report_{now.strftime('%Y%m%d_%H%M%S')}.html"
    return send_file(buf, mimetype='text/html', as_attachment=True, download_name=filename)


def _build_web_report(ts, urls, s):
    total   = s['total_captured']
    threats = s['threat_count']
    benign  = s['benign_count']
    threat_pct = round((threats / max(total, 1)) * 100, 1)

    atk_rows = ''.join(
        f"<tr><td>{t}</td><td>{c}</td><td>{round(c/max(total,1)*100,1)}%</td></tr>"
        for t, c in sorted(s.get('attack_breakdown', {}).items(), key=lambda x: -x[1])
    )

    domain_rows = ''.join(
        f"<tr><td>{d}</td><td>{c}</td></tr>"
        for d, c in sorted(s.get('domain_frequency', {}).items(), key=lambda x: -x[1])[:15]
    )

    url_rows = ''.join(
        f"<tr class='{'threat' if u.get('is_threat') else 'safe'}'>"
        f"<td>{u.get('timestamp','')[:19]}</td>"
        f"<td class='url-cell'>{u.get('url','')[:80]}</td>"
        f"<td>{u.get('protocol','')}</td>"
        f"<td class='badge {'badge-threat' if u.get('is_threat') else 'badge-safe'}'>{u.get('attack_type','Unknown')}</td>"
        f"<td>{u.get('risk_level','')}</td>"
        f"<td>{round(u.get('confidence',0)*100,1)}%</td>"
        f"</tr>"
        for u in reversed(urls[:50])
    )

    return f"""<!DOCTYPE html>
<html><head><meta charset="UTF-8">
<title>Web Access Security Report – {ts.strftime('%Y-%m-%d %H:%M')}</title>
<style>
  * {{box-sizing:border-box;margin:0;padding:0}}
  body {{font-family:'Segoe UI',sans-serif;background:#0c1a2e;color:#e2e8f0;padding:32px}}
  h1 {{font-size:28px;color:#22d3ee;margin-bottom:4px}}
  .subtitle {{color:#64748b;margin-bottom:28px;font-size:14px}}
  .grid {{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:16px;margin-bottom:28px}}
  .card {{background:#112240;border-radius:10px;padding:20px;border:1px solid #1e3a5f}}
  .card h3 {{font-size:11px;text-transform:uppercase;letter-spacing:1px;color:#64748b;margin-bottom:8px}}
  .card .val {{font-size:32px;font-weight:700;color:#22d3ee}}
  .threat .val {{color:#f87171}}
  .warn .val {{color:#fb923c}}
  section {{margin-bottom:28px}}
  section h2 {{font-size:16px;color:#94a3b8;margin-bottom:12px;padding-bottom:8px;border-bottom:1px solid #1e3a5f}}
  .two-col {{display:grid;grid-template-columns:1fr 1fr;gap:20px}}
  table {{width:100%;border-collapse:collapse;font-size:12px}}
  th {{background:#112240;color:#64748b;padding:10px 12px;text-align:left;font-size:10px;text-transform:uppercase;letter-spacing:0.5px}}
  td {{padding:9px 12px;border-bottom:1px solid #0c1a2e}}
  tr.threat td {{background:#7f1d1d20}}
  tr.safe td {{background:#14532d12}}
  .badge {{padding:3px 10px;border-radius:12px;font-size:10px;font-weight:600}}
  .badge-threat {{background:#7f1d1d;color:#fca5a5}}
  .badge-safe {{background:#14532d;color:#86efac}}
  .url-cell {{font-family:monospace;font-size:11px;max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}}
  @media print {{body{{background:#fff;color:#000}} .card{{background:#f8f9fa}} td,th{{color:#000}}}}
</style></head><body>
<h1>🌐 Web Access Security Report</h1>
<p class="subtitle">Generated: {ts.strftime('%A, %B %d, %Y at %H:%M:%S')} &nbsp;|&nbsp; Model: RandomForest Classifier</p>

<div class="grid">
  <div class="card"><h3>Total URLs</h3><div class="val">{total:,}</div></div>
  <div class="card threat"><h3>Threats Detected</h3><div class="val">{threats:,}</div></div>
  <div class="card"><h3>Benign</h3><div class="val">{benign:,}</div></div>
  <div class="card warn"><h3>Threat Rate</h3><div class="val">{threat_pct}%</div></div>
  <div class="card"><h3>ML Status</h3><div class="val">{'Active' if ml_detector.model else 'Unavailable'}</div></div>
</div>

<div class="two-col" style="margin-bottom:28px">
  <section><h2>Attack Type Breakdown</h2>
  <table><tr><th>Attack Type</th><th>Count</th><th>%</th></tr>
  {atk_rows if atk_rows else '<tr><td colspan=3 style="color:#64748b">No threats detected</td></tr>'}
  </table></section>
  <section><h2>Top Accessed Domains</h2>
  <table><tr><th>Domain</th><th>Visits</th></tr>
  {domain_rows if domain_rows else '<tr><td colspan=2 style="color:#64748b">No data</td></tr>'}
  </table></section>
</div>

<section><h2>URL Access Log (last 50)</h2>
<table>
<tr><th>Time</th><th>URL</th><th>Protocol</th><th>Classification</th><th>Risk</th><th>Confidence</th></tr>
{url_rows if url_rows else '<tr><td colspan=6 style="color:#64748b;text-align:center;padding:20px">No URLs captured yet</td></tr>'}
</table></section>

<p style="color:#475569;font-size:12px;margin-top:24px;text-align:center">
Web Access Monitor &nbsp;|&nbsp; ML-powered Attack Detection &nbsp;|&nbsp; {ts.strftime('%Y')}
</p>
<script>window.onload=()=>setTimeout(()=>window.print(),500)</script>
</body></html>"""


# ─── SocketIO events ──────────────────────────────────────────────────────────
@socketio.on('connect')
def handle_connect():
    logger.info(f"Client connected: {request.sid}")
    emit('connected', {
        'status': 'connected',
        'ml_loaded': ml_model_available(),
        'model_available': ml_model_available(),
        'ml_status': ml_detector.load_status
    })
    if current_stats['total_captured'] > 0:
        emit('stats_update', current_stats)
        for u in captured_urls[-20:]:
            safe = {
                'url': u['url'], 'domain': u.get('domain',''),
                'protocol': u.get('protocol','HTTP'), 'timestamp': u['timestamp'],
                'attack_type': u.get('attack_type','Unknown'),
                'is_threat': u.get('is_threat',False),
                'risk_level': u.get('risk_level','Low'),
                'confidence': u.get('confidence',0)
            }
            emit('url_captured', safe)


@socketio.on('start_capture')
def handle_start_capture():
    global proxy_active, proxy_thread
    if not proxy_active:
        proxy_active = True
        proxy_thread = threading.Thread(target=proxy.start, daemon=True)
        proxy_thread.start()
        emit('capture_status', {'status': 'started', 'port': 8080})
    else:
        emit('capture_status', {'status': 'already_running'})


@socketio.on('stop_capture')
def handle_stop_capture():
    global proxy_active
    if proxy_active:
        proxy.stop(); proxy_active = False
        emit('capture_status', {'status': 'stopped'})


@socketio.on('clear_stats')
def handle_clear_stats():
    global captured_urls, current_stats
    captured_urls = []
    current_stats = {
        'total_captured': 0, 'recent_urls': [], 'domain_frequency': {},
        'capture_rate': 0, 'threat_count': 0, 'benign_count': 0,
        'attack_breakdown': {}, 'ml_loaded': ml_model_available(),
        'ml_load_status': ml_detector.load_status
    }
    emit('stats_cleared')
    emit('stats_update', current_stats)


if __name__ == '__main__':
    socketio.run(app, debug=False, host='0.0.0.0', port=5002, allow_unsafe_werkzeug=True)
