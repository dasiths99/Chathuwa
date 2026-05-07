"""
Unified Security Monitoring System - Main Orchestrator
  - Network Flow Monitor  → port 5001  (auto-start)
  - Web Access Monitor    → port 5002  (auto-start)
  - File & Mouse Monitor  → port 5003  (auto-start)  ← FIXED: was lazy-start

FIX: f_m.py is now auto-started along with the other two components.
     The /file-mouse route keeps the loading page as a fallback for the
     small window while the process is still binding, but the process
     itself is kicked off immediately on app launch.
"""

from flask import Flask, render_template, jsonify, redirect as flask_redirect
import subprocess
import threading
import os
import sys
import time
import psutil
import io

# ── Unicode fix for Windows ──────────────────────────────────────────────────
if sys.platform == 'win32':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# ── Component tracking ────────────────────────────────────────────────────────
components_status = {
    'network_flow': {'running': False, 'port': 5001, 'name': 'Network Traffic Monitor'},
    'web_access':   {'running': False, 'port': 5002, 'name': 'Web Access Monitor'},
    'file_mouse':   {'running': False, 'port': 5003, 'name': 'File & Mouse Monitor'},
}

processes = {}          # key → subprocess.Popen
_fm_start_lock = threading.Lock()   # prevent double-start race


# ── Helpers ───────────────────────────────────────────────────────────────────
def check_port_in_use(port: int) -> bool:
    import socket as _socket
    try:
        s = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
        s.settimeout(1)
        result = s.connect_ex(('127.0.0.1', port))
        s.close()
        return result == 0
    except Exception:
        return False


def kill_component_processes(script_name: str):
    """
    Kill *existing* python processes that are running the given script.
    This prevents duplicate listeners like two different network.py on :5001.
    """
    try:
        target = script_name.lower()
        for p in psutil.process_iter(attrs=['pid', 'name', 'cmdline']):
            try:
                name = (p.info.get('name') or '').lower()
                if 'python' not in name:
                    continue
                cmd = ' '.join(p.info.get('cmdline') or []).lower()
                if target in cmd:
                    try:
                        p.kill()
                    except Exception:
                        pass
            except Exception:
                continue
    except Exception:
        pass


def _make_reader(label: str, stream):
    def _read():
        try:
            while True:
                line = stream.readline()
                if not line:
                    break
                try:
                    decoded = line.decode('utf-8', errors='replace').rstrip()
                    if decoded:
                        print(f"[{label}] {decoded}", flush=True)
                except Exception:
                    pass
        except Exception:
            pass
        finally:
            try:
                stream.close()
            except Exception:
                pass
    t = threading.Thread(target=_read, daemon=True, name=f"Reader-{label}")
    t.start()
    return t


def get_component_key(script_name: str):
    if 'network' in script_name:
        return 'network_flow'
    if 'web' in script_name:
        return 'web_access'
    if 'f_m' in script_name:
        return 'file_mouse'
    return None


def run_component(script_name: str, port: int):
    """Launch a component script and stream stdout/stderr."""
    key = get_component_key(script_name)
    try:
        # If something is already bound to this port, do NOT start another copy.
        # This is the primary fix for "attacks not showing" caused by duplicate
        # network.py instances serving different dashboards.
        if check_port_in_use(port):
            print(f"[app] {script_name} already listening on :{port} — skip start", flush=True)
            if key:
                components_status[key]['running'] = True
            return

        # If a stale python process is still running this script, kill it first.
        kill_component_processes(script_name)

        script_path = os.path.join(BASE_DIR, script_name)
        if not os.path.exists(script_path):
            print(f"[app] ERROR: {script_name} not found at {script_path}", flush=True)
            if key:
                components_status[key]['running'] = False
            return

        process = subprocess.Popen(
            [sys.executable, script_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            bufsize=0,
        )
        if key:
            processes[key] = process
            components_status[key]['running'] = True

        print(f"[app] Started {script_name} (PID {process.pid}) on port {port}", flush=True)
        _make_reader(script_name, process.stdout)
        _make_reader(f"{script_name}:ERR", process.stderr)
        return_code = process.wait()
        print(f"[app] {script_name} exited (code {return_code})", flush=True)
    except Exception as exc:
        print(f"[app] Error starting {script_name}: {exc}", flush=True)
    finally:
        if key:
            components_status[key]['running'] = False


def start_file_mouse_if_needed():
    """
    Start f_m.py if it is not already running.
    Safe to call multiple times — guarded by _fm_start_lock.
    """
    with _fm_start_lock:
        if components_status['file_mouse']['running']:
            return
        if check_port_in_use(5003):
            components_status['file_mouse']['running'] = True
            return
        print("[app] Starting File & Mouse Monitor…", flush=True)
        t = threading.Thread(
            target=run_component,
            args=('f_m.py', 5003),
            daemon=True,
            name="Component-f_m.py",
        )
        t.start()
        # Give it up to 30 s to bind (TF import can be slow on first run)
        for _ in range(60):
            time.sleep(0.5)
            if check_port_in_use(5003):
                print("[app] File & Mouse Monitor is up on :5003", flush=True)
                break


def monitor_component_status():
    """Periodically check component ports and update status."""
    while True:
        for key, comp in components_status.items():
            is_running = check_port_in_use(comp['port'])
            if comp['running'] != is_running:
                comp['running'] = is_running
                state = "running" if is_running else "stopped"
                print(f"[app] {comp['name']} is now {state}", flush=True)
        time.sleep(5)


# ── Flask app ─────────────────────────────────────────────────────────────────
app = Flask(__name__)


# ── Routes ────────────────────────────────────────────────────────────────────
@app.route('/')
def index():
    return render_template('index.html', components=components_status)


@app.route('/network-flow')
def network_flow():
    return flask_redirect('http://localhost:5001')


@app.route('/web-access')
def web_access():
    return flask_redirect('http://localhost:5002')


@app.route('/file-mouse')
def file_mouse():
    """
    Redirect to File & Mouse Monitor.
    Since f_m.py is now auto-started on launch, it should already be up.
    The loading page is kept as a fallback for the startup window.
    """
    # Fast-path: already running → redirect immediately
    if check_port_in_use(5003):
        return flask_redirect('http://localhost:5003')

    # Not yet up (still starting) → ensure thread is running, show loader
    threading.Thread(target=start_file_mouse_if_needed, daemon=True,
                     name="FM-EnsureStart").start()

    return _FM_LOADING_PAGE


@app.route('/api/fm_ready')
def fm_ready():
    """Polled by the loading page to know when :5003 is accepting connections."""
    ready = check_port_in_use(5003)
    if ready:
        components_status['file_mouse']['running'] = True
    return jsonify({'ready': ready})


_FM_LOADING_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Starting File &amp; Mouse Monitor…</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font-family: 'Segoe UI', sans-serif;
    background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%);
    min-height: 100vh;
    display: flex; justify-content: center; align-items: center;
  }
  .card {
    background: white; border-radius: 16px; padding: 48px 40px;
    text-align: center; max-width: 440px; width: 90%;
    box-shadow: 0 20px 60px rgba(0,0,0,0.2);
  }
  h2 { color: #333; font-size: 1.6rem; margin-bottom: 8px; }
  p  { color: #666; margin-bottom: 28px; }
  .spinner {
    width: 56px; height: 56px;
    border: 6px solid #e0f0ff;
    border-top-color: #4facfe;
    border-radius: 50%;
    animation: spin 0.9s linear infinite;
    margin: 0 auto 24px;
  }
  @keyframes spin { to { transform: rotate(360deg); } }
  #status { color: #4facfe; font-size: 14px; font-weight: 600; margin-top: 12px; }
  #bar-wrap {
    background: #e9f7ff; border-radius: 8px; height: 8px;
    margin-top: 20px; overflow: hidden;
  }
  #bar {
    height: 100%; width: 0%; background: #4facfe;
    border-radius: 8px; transition: width 1s linear;
  }
  .tip {
    margin-top: 28px; font-size: 12px; color: #aaa;
    border-top: 1px solid #eee; padding-top: 16px;
  }
</style>
</head>
<body>
<div class="card">
  <div class="spinner"></div>
  <h2>📁 File &amp; Mouse Monitor</h2>
  <p>Starting the component, please wait…</p>
  <div id="bar-wrap"><div id="bar"></div></div>
  <div id="status">Initialising…</div>
  <div class="tip">This only takes a few seconds on first launch.</div>
</div>
<script>
  const MAX_WAIT  = 40;
  let   attempts  = 0;
  const bar       = document.getElementById('bar');
  const statusEl  = document.getElementById('status');

  function poll() {
    attempts++;
    bar.style.width = Math.min(attempts / MAX_WAIT * 100, 95) + '%';
    statusEl.textContent = 'Attempt ' + attempts + ' — checking port 5003…';

    fetch('/api/fm_ready')
      .then(r => r.json())
      .then(data => {
        if (data.ready) {
          bar.style.width = '100%';
          statusEl.textContent = '✅ Server ready! Redirecting…';
          setTimeout(() => { window.location.href = 'http://localhost:5003'; }, 400);
        } else if (attempts < MAX_WAIT) {
          setTimeout(poll, 1000);
        } else {
          statusEl.innerHTML =
            'Taking longer than expected. ' +
            '<a href="http://localhost:5003" style="color:#4facfe">Click here to try now</a>';
        }
      })
      .catch(() => {
        if (attempts < MAX_WAIT) setTimeout(poll, 1000);
      });
  }

  setTimeout(poll, 1000);
</script>
</body>
</html>
"""


@app.route('/api/components/status')
def get_components_status():
    # Sync all ports with real checks
    for key, comp in components_status.items():
        comp['running'] = check_port_in_use(comp['port'])
    clean = {}
    for key, comp in components_status.items():
        clean[key] = {
            'running': comp['running'],
            'port':    comp['port'],
            'name':    comp['name'],
        }
    return jsonify(clean)


@app.route('/api/system/stats')
def get_system_stats():
    try:
        cpu_percent = psutil.cpu_percent(interval=0.5)
        memory = psutil.virtual_memory()
        import shutil as _shutil
        _d = _shutil.disk_usage('C:')
        disk = type('D', (), {'total': _d.total, 'used': _d.used, 'free': _d.free,
                              'percent': round(_d.used / _d.total * 100, 1)})()
        return jsonify({
            'cpu':    {'percent': cpu_percent, 'cores': psutil.cpu_count()},
            'memory': {
                'total': memory.total, 'available': memory.available,
                'percent': memory.percent, 'used': memory.used,
            },
            'disk': {
                'total': disk.total, 'used': disk.used,
                'free': disk.free, 'percent': disk.percent,
            },
            'timestamp': time.time(),
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/health')
def health_check():
    return jsonify({
        'status':     'ok',
        'components': {k: v['running'] for k, v in components_status.items()},
        'timestamp':  time.time(),
    })


# ── Entry point ───────────────────────────────────────────────────────────────
if __name__ == '__main__':
    print("\n" + "=" * 70)
    print("🚀 STARTING UNIFIED SECURITY MONITORING SYSTEM")
    print("=" * 70)

    # ── AUTO-START ALL THREE components ──────────────────────────────────────
    # f_m.py is now included here so port 5003 is up before any browser
    # request arrives — fixes the "File & Mouse Monitor not working" bug.
    auto_start = [
        ('network.py',    5001),
        ('web_access.py', 5002),
        ('f_m.py',        5003),   # ← WAS MISSING — now auto-started
    ]

    for script, port in auto_start:
        print(f"[app] Launching {script} on port {port}…", flush=True)
        t = threading.Thread(
            target=run_component,
            args=(script, port),
            daemon=True,
            name=f"Component-{script}",
        )
        t.start()
        # Small stagger so log output stays readable
        time.sleep(1)

    # Port monitor
    threading.Thread(
        target=monitor_component_status,
        daemon=True,
        name="PortMonitor",
    ).start()

    print("\n" + "=" * 70)
    print("✅ ALL THREE COMPONENTS LAUNCHED")
    print("=" * 70)
    print("📡 Main Dashboard         : http://localhost:5000")
    print("🌐 Network Flow Monitor   : http://localhost:5001")
    print("🔗 Web Access Monitor     : http://localhost:5002")
    print("📁 File & Mouse Monitor   : http://localhost:5003  ← AUTO-START (fixed)")
    print("=" * 70)
    print("⚠️  Run as Administrator for real network packet capture!")
    print("Press CTRL+C to stop all services\n")

    try:
        app.run(host='0.0.0.0', port=5000, debug=False, use_reloader=False)
    except KeyboardInterrupt:
        print("\n\n🛑 Shutting down…")
        for key, proc in processes.items():
            try:
                proc.terminate()
                proc.wait(timeout=3)
                print(f"[app] Stopped {key}")
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass
        print("✅ All services stopped")
        sys.exit(0)
