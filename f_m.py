"""
File & Mouse Movement Anomaly Detection Monitor
Real-time monitoring with ML-based anomaly detection.

FIXES applied in this version:
  1. numpy imported safely — crash on missing numpy is caught gracefully.
  2. Mouse SIMULATION fallback added — if pynput is not installed the tracker
     generates realistic synthetic events so the dashboard always has data.
  3. async_mode='threading' keeps eventlet away from stdlib threading.
  4. TF import is non-blocking; server binds to :5003 immediately.
  5. Monitoring AUTO-STARTS when __main__ runs (no manual click needed).
  6. send_file() used instead of render_template() — no templates/ folder.
  7. FIX: load_models() now waits for TF import to complete before checking
     TF_AVAILABLE, so the .h5 models are actually loaded instead of skipped.
"""

import os
import sys
import time
import threading
import queue
import random
import io
import logging
from datetime import datetime
from flask import Flask, send_file, jsonify, request
from flask_socketio import SocketIO, emit
import psutil

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# ── Unicode fix for Windows ───────────────────────────────────────────────────
if sys.platform == 'win32':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')

print("\n" + "=" * 70)
print("📁 FILE & MOUSE MOVEMENT ANOMALY DETECTION")
print("=" * 70)

# ── BASE_DIR must be set before Flask() is called ────────────────────────────
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# ── Safe numpy import ─────────────────────────────────────────────────────────
try:
    import numpy as np
    NUMPY_AVAILABLE = True
    logger.info("✓ numpy available")
except ImportError:
    NUMPY_AVAILABLE = False
    logger.error("❌ numpy not installed — using pure-Python fallback math")
    class _NpStub:
        @staticmethod
        def array(x, **kw): return list(x)
        @staticmethod
        def mean(x): return sum(x) / len(x) if x else 0.0
        @staticmethod
        def square(x): return [v*v for v in x] if hasattr(x, '__iter__') else x*x
        float32 = float
    np = _NpStub()

# ── Flask / SocketIO ──────────────────────────────────────────────────────────
class ReconstructionBaseline:
    """Compatibility class for Kaggle notebook-saved reconstruction_baseline.pkl."""

    def __init__(self, threshold_multiplier=2.0):
        self.threshold_multiplier = threshold_multiplier
        self.mean = None
        self.std = None
        self.threshold = None

    def predict(self, X):
        arr = np.array(X, dtype=float)
        if getattr(arr, 'ndim', 1) == 1:
            arr = arr.reshape(1, -1)
        if self.mean is None:
            return np.zeros(arr.shape[0], dtype=int)
        std = np.array(self.std, dtype=float) if self.std is not None else 1.0
        std = np.where(std == 0, 1.0, std)
        scores = np.mean(np.abs((arr - self.mean) / std), axis=1)
        threshold = self.threshold
        if threshold is None:
            threshold = float(np.mean(scores) + self.threshold_multiplier * np.std(scores))
        return (scores > threshold).astype(int)

    def decision_function(self, X):
        arr = np.array(X, dtype=float)
        if getattr(arr, 'ndim', 1) == 1:
            arr = arr.reshape(1, -1)
        if self.mean is None:
            return np.zeros(arr.shape[0], dtype=float)
        std = np.array(self.std, dtype=float) if self.std is not None else 1.0
        std = np.where(std == 0, 1.0, std)
        return np.mean(np.abs((arr - self.mean) / std), axis=1)


class SimpleIsolationForest:
    """Compatibility class for Kaggle notebook-saved isolation_forest_simple.pkl."""

    def __init__(self, n_trees=100, max_samples=256, contamination=0.1):
        self.n_trees = n_trees
        self.max_samples = max_samples
        self.contamination = contamination
        self.trees = []
        self.depths = []
        self.threshold = None

    def decision_function(self, X):
        arr = np.array(X, dtype=float)
        if getattr(arr, 'ndim', 1) == 1:
            arr = arr.reshape(1, -1)
        if not self.trees:
            return np.zeros(arr.shape[0], dtype=float)
        scores = []
        for row in arr:
            path_lengths = []
            for tree in self.trees:
                path_lengths.append(self._path_length(row, tree))
            scores.append(float(np.mean(path_lengths)))
        return np.array(scores, dtype=float)

    def predict(self, X):
        scores = self.decision_function(X)
        threshold = self.threshold
        if threshold is None:
            pct = max(0.0, min(100.0, self.contamination * 100.0))
            threshold = float(np.percentile(scores, pct))
        return (scores <= threshold).astype(int)

    def _path_length(self, row, node, depth=0):
        if not isinstance(node, dict):
            return depth
        if 'left' not in node or 'right' not in node:
            return depth
        feature = int(node.get('feature', 0))
        split = float(node.get('split', 0.0))
        if feature >= len(row):
            return depth
        branch = node.get('left') if row[feature] <= split else node.get('right')
        return self._path_length(row, branch, depth + 1)


try:
    import __main__ as _main_module
    setattr(_main_module, 'ReconstructionBaseline', ReconstructionBaseline)
    setattr(_main_module, 'SimpleIsolationForest', SimpleIsolationForest)
except Exception:
    pass


app = Flask(__name__)
app.config['SECRET_KEY'] = 'file-mouse-secret-key'

socketio = SocketIO(
    app,
    cors_allowed_origins="*",
    async_mode='threading',
    logger=False,
    engineio_logger=False,
)

# ── Optional package detection ────────────────────────────────────────────────
PYNPUT_AVAILABLE = False
TF_AVAILABLE     = False

# ── KEY FIX: use an Event so load_models() can block until TF import done ────
_tf_import_done = threading.Event()

try:
    import pynput  # noqa: F401
    PYNPUT_AVAILABLE = True
    logger.info("✓ pynput available — real mouse tracking enabled")
except ImportError:
    logger.warning("⚠️  pynput not installed — mouse SIMULATION mode active")
    logger.warning("   To enable real tracking: pip install pynput")


def _try_import_tf():
    """Import TensorFlow in a background thread, then signal _tf_import_done."""
    global TF_AVAILABLE
    try:
        import tensorflow as tf  # noqa: F401
        TF_AVAILABLE = True
        logger.info("✓ TensorFlow loaded — deep model inference enabled")
    except Exception as e:
        logger.warning(f"⚠️  TensorFlow unavailable: {e} — heuristic scoring active")
    finally:
        # Always signal so load_models() is never stuck waiting
        _tf_import_done.set()


# ── Global state ──────────────────────────────────────────────────────────────
monitoring_active = False
file_events       = []
mouse_movements   = []
current_stats = {
    'total_file_events':    0,
    'total_mouse_events':   0,
    'file_operations':      {},
    'mouse_movement_count': 0,
    'mouse_clicks':         0,
    'active_windows':       [],
    'recent_activities':    [],
    'file_anomaly_score':   0.0,
    'mouse_anomaly_score':  0.0,
    'file_anomalies':       0,
    'mouse_anomalies':      0,
    'models_loaded':        False,
    'mouse_mode':           'real' if PYNPUT_AVAILABLE else 'simulation',
}

event_queue = queue.Queue(maxsize=5000)

FILE_MODEL_PATH  = os.path.join(BASE_DIR, 'file', 'best_model.h5')
MOUSE_MODEL_PATH = os.path.join(BASE_DIR, 'file', 'lstm_autoencoder_model.h5')
FILE_PKL_MODEL_DIR = os.path.join(BASE_DIR, 'file', 'best_model')
FILE_PKL_MODEL_CANDIDATES = [
    os.path.join(FILE_PKL_MODEL_DIR, 'reconstruction_baseline.pkl'),
    os.path.join(FILE_PKL_MODEL_DIR, 'isolation_forest_simple.pkl'),
    os.path.join(BASE_DIR, 'file', 'tuning_model', 'ensemble_model.pkl'),
    os.path.join(BASE_DIR, 'file', 'tuning_model', 'reconstruction_baseline_optimized.pkl'),
    os.path.join(BASE_DIR, 'file', 'tuning_model', 'isolation_forest_simple_optimized.pkl'),
]
FILE_MODEL_FEATURE_NAMES_PATH = os.path.join(FILE_PKL_MODEL_DIR, 'feature_names.json')

FILE_FEATURE_DIM  = 3
MOUSE_FEATURE_DIM = 3
SEQUENCE_LENGTH   = 10
MOUSE_SPEED_NORMALIZER = 5000.0
MOUSE_EXTREME_SPEED_THRESHOLD = 0.70
MOUSE_ALERT_THRESHOLD = 0.75


# ── ML Anomaly Detector ───────────────────────────────────────────────────────
class MLAnomalyDetector:
    def __init__(self):
        self.file_model              = None
        self.file_pkl_model          = None
        self.file_pkl_model_path     = None
        self.file_pkl_feature_names  = []
        self.mouse_model             = None
        # best_model.h5 is an autoencoder (3→3 sigmoid); threshold is MSE of
        # reconstruction error — 0.05 works well for features in [0,1] range.
        self.file_anomaly_threshold  = 0.05
        self.mouse_anomaly_threshold = 0.75
        self.models_loaded           = False

    def load_models(self):
        """
        Load .h5 models.

        CRITICAL FIX: wait for the TF import thread to finish before checking
        TF_AVAILABLE.  Previously, load_models() ran concurrently with
        _try_import_tf(), so TF_AVAILABLE was still False when the check ran,
        causing the "TensorFlow not available" branch to fire and skip loading
        entirely.  Waiting on _tf_import_done (with a generous timeout) ensures
        the flag reflects reality before we proceed.
        """
        logger.info("⏳ Waiting for TensorFlow import to complete…")
        # Wait up to 120 s — TF can be slow on first import / cold start
        self._load_file_pkl_model()
        _tf_import_done.wait(timeout=120)

        try:
            if not TF_AVAILABLE:
                raise ImportError("TensorFlow not available after import attempt")

            from tensorflow.keras.models import load_model
            from tensorflow.keras.losses  import MeanSquaredError

            # ── File anomaly model ────────────────────────────────────────────
            if os.path.exists(FILE_MODEL_PATH):
                self.file_model = load_model(FILE_MODEL_PATH, compile=False)
                logger.info(f"✅ File model loaded — input shape: {self.file_model.input_shape}")
            else:
                logger.warning(
                    f"⚠️  File model not found at:\n"
                    f"    {FILE_MODEL_PATH}\n"
                    f"    Place best_model.h5 inside a 'file/' sub-folder next to f_m.py"
                )

            # ── Mouse LSTM autoencoder model ──────────────────────────────────
            if os.path.exists(MOUSE_MODEL_PATH):
                self.mouse_model = load_model(
                    MOUSE_MODEL_PATH,
                    custom_objects={'mse': MeanSquaredError()},
                    compile=False,
                )
                logger.info(f"✅ Mouse model loaded — input shape: {self.mouse_model.input_shape}")
            else:
                logger.warning(
                    f"⚠️  Mouse model not found at:\n"
                    f"    {MOUSE_MODEL_PATH}\n"
                    f"    Place lstm_autoencoder_model.h5 inside a 'file/' sub-folder next to f_m.py"
                )

        except Exception as e:
            logger.warning(f"⚠️  Model load error: {e}  — heuristic mode active")

        self.models_loaded             = True
        current_stats['models_loaded'] = True

        file_model_ready = self.file_model is not None or self.file_pkl_model is not None
        if file_model_ready and self.mouse_model:
            status = "✅ Both ML models loaded — real inference active"
        elif file_model_ready:
            status = "⚠️  File model loaded; mouse model missing — partial inference"
        elif self.mouse_model:
            status = "⚠️  Mouse model loaded; file model missing — partial inference"
        else:
            status = "⚠️  No ML models loaded — heuristic scoring active"
        logger.info(status)

        # Push updated status to connected clients
        try:
            socketio.emit('stats_update', current_stats)
        except Exception:
            pass

    # ── Feature extractors ────────────────────────────────────────────────────
    def _load_file_pkl_model(self):
        """Load Kaggle best_model/*.pkl file-access artifact when available."""
        try:
            import json
            import joblib
        except Exception as exc:
            logger.info(f"PKL file model skipped: joblib/json unavailable ({exc})")
            return

        if os.path.exists(FILE_MODEL_FEATURE_NAMES_PATH):
            try:
                with open(FILE_MODEL_FEATURE_NAMES_PATH, 'r', encoding='utf-8') as f:
                    names = json.load(f)
                if isinstance(names, list):
                    self.file_pkl_feature_names = [str(name) for name in names]
                elif isinstance(names, dict):
                    raw = names.get('feature_names') or names.get('features') or []
                    self.file_pkl_feature_names = [str(name) for name in raw]
            except Exception as exc:
                logger.warning(f"Could not read PKL feature names: {exc}")

        for candidate in FILE_PKL_MODEL_CANDIDATES:
            if not os.path.exists(candidate):
                continue
            try:
                self.file_pkl_model = joblib.load(candidate)
                self.file_pkl_model_path = candidate
                logger.info(f"File PKL model loaded: {candidate}")
                return
            except Exception as exc:
                logger.warning(f"Could not load file PKL model {candidate}: {exc}")

    def _file_pkl_vector(self, features):
        """
        Convert live 3-feature events into the Kaggle training feature vector.
        Unknown training columns are filled with 0 so the model can still run.
        """
        try:
            size_risk, ext_risk, op_risk = [float(x) for x in list(features)[:3]]
        except Exception:
            size_risk, ext_risk, op_risk = 0.0, 0.2, 0.1

        values = {
            'size_risk': size_risk,
            'ext_risk': ext_risk,
            'extension_risk': ext_risk,
            'op_risk': op_risk,
            'operation_risk': op_risk,
            'Rapid_file_access': max(size_risk, op_risk),
            'Executable_File_Access': 1.0 if ext_risk >= 0.7 else 0.0,
            'Access_Frequency_Anomaly': max(size_risk, op_risk),
            'Unusual_file_access': ext_risk,
            'Data_exfilteration': size_risk,
            'signature_mismatch': 0.0,
            'Content_Mismatch': 0.0,
            'Hours': 0.5,
            'to_removable_media': 0.0,
            'from_removable_media': 0.0,
        }

        names = self.file_pkl_feature_names
        if names:
            return [values.get(name, 0.0) for name in names]
        return [size_risk, ext_risk, op_risk]

    def _predict_file_pkl_anomaly(self, features):
        if self.file_pkl_model is None:
            return None
        try:
            import numpy as _np
            row = _np.array(self._file_pkl_vector(features), dtype=_np.float32).reshape(1, -1)

            if hasattr(self.file_pkl_model, 'predict'):
                pred = self.file_pkl_model.predict(row)
                raw = pred[0] if hasattr(pred, '__len__') else pred
                if isinstance(raw, str):
                    text = raw.lower()
                    return 0.9 if 'anom' in text or 'attack' in text else 0.1
                numeric = float(raw)
                return 0.9 if numeric == 1.0 else 0.1

            if hasattr(self.file_pkl_model, 'decision_function'):
                score = self.file_pkl_model.decision_function(row)
                raw = float(score[0] if hasattr(score, '__len__') else score)
                return float(max(0.0, min(1.0, 1.0 - raw)))
        except Exception as exc:
            logger.debug(f"File PKL predict error: {exc}")
        return None

    def extract_file_features(self, ev):
        size     = ev.get('size', 0)
        filename = ev.get('filename', '')
        ext      = filename.rsplit('.', 1)[-1].lower() if '.' in filename else 'no_ext'
        ext_risk = {
            'exe': 0.9, 'dll': 0.8, 'sys': 0.7, 'bat': 0.8, 'ps1': 0.9,
            'vbs': 0.8, 'cmd': 0.7, 'scr': 0.8, 'com': 0.8, 'msi': 0.7,
            'doc': 0.3, 'docx': 0.3, 'xls': 0.3, 'xlsx': 0.3, 'pdf': 0.4,
            'zip': 0.5, 'rar': 0.5, '7z': 0.5, 'tar': 0.4, 'gz': 0.3,
            'jpg': 0.1, 'png': 0.1, 'gif': 0.1, 'mp4': 0.15, 'mp3': 0.1,
            'txt': 0.15, 'csv': 0.2, 'json': 0.2, 'xml': 0.25, 'tmp': 0.15,
            'log': 0.2, 'db': 0.45, 'sqlite': 0.45, 'no_ext': 0.2,
        }
        # Lowered 'deleted' from 1.0 → 0.7 and 'created' from 0.0 → 0.1
        # to avoid flagging every deletion as an anomaly.
        op_risk = {'created': 0.1, 'modified': 0.4, 'deleted': 0.7}
        try:
            return np.array([
                min(size / (100 * 1024 * 1024), 1.0),
                ext_risk.get(ext, 0.2),
                op_risk.get(ev.get('type', 'created'), 0.1),
            ], dtype=np.float32)
        except Exception:
            return [min(size / (100 * 1024 * 1024), 1.0),
                    ext_risk.get(ext, 0.2),
                    op_risk.get(ev.get('type', 'created'), 0.1)]

    def extract_mouse_features(self, ev):
        x     = ev.get('x', 0)
        y     = ev.get('y', 0)
        speed = ev.get('speed', 0)
        try:
            return np.array([
                float(x) / 1920.0,
                float(y) / 1080.0,
                min(float(speed) / MOUSE_SPEED_NORMALIZER, 1.0),
            ], dtype=np.float32)
        except Exception:
            return [float(x) / 1920.0, float(y) / 1080.0, min(float(speed) / MOUSE_SPEED_NORMALIZER, 1.0)]

    # ── Predictors ────────────────────────────────────────────────────────────
    def predict_file_anomaly(self, features):
        try:
            f = list(features)
            size_risk, ext_risk, op_risk = f[0], f[1], f[2]
            base = size_risk * 0.1 + ext_risk * 0.5 + op_risk * 0.4
            # High-risk extension alone is enough to boost (creating an .exe
            # or .bat is suspicious regardless of operation type).
            if ext_risk >= 0.7:
                heuristic = float(min(base + 0.15, 0.95))
            else:
                heuristic = float(min(base, 0.65))
        except Exception:
            heuristic = 0.0

        pkl_score = self._predict_file_pkl_anomaly(features)
        if pkl_score is not None:
            return pkl_score

        if self.file_model is None:
            return heuristic
        try:
            import numpy as _np
            inp   = _np.array(features, dtype=_np.float32).reshape(1, -1)
            recon = self.file_model.predict(inp, verbose=0)
            # best_model.h5 is an autoencoder (output shape == input shape 3).
            # Anomaly score = normalised MSE of reconstruction error.
            mse   = float(_np.mean((inp.flatten() - recon.flatten()) ** 2))
            return float(min(mse / self.file_anomaly_threshold, 1.0))
        except Exception as e:
            logger.debug(f"File predict error: {e}")
            return heuristic

    def predict_mouse_anomaly(self, features_seq):
        if features_seq is None:
            return 0.0
        try:
            if len(features_seq) == 0:
                return 0.0
        except TypeError:
            return 0.0

        try:
            speeds = [float(f[2]) for f in features_seq]
            avg_speed = sum(speeds) / len(speeds) if speeds else 0.0
            peak_speed = max(speeds) if speeds else 0.0
            if peak_speed < MOUSE_EXTREME_SPEED_THRESHOLD:
                # Ordinary movement should stay visibly normal even if the
                # autoencoder reconstruction is imperfect on this machine.
                heuristic = float(min(avg_speed * 0.25, 0.20))
            else:
                extreme_ratio = (
                    (peak_speed - MOUSE_EXTREME_SPEED_THRESHOLD) /
                    max(1.0 - MOUSE_EXTREME_SPEED_THRESHOLD, 0.001)
                )
                heuristic = float(min(0.75 + extreme_ratio * 0.20, 0.95))
        except Exception:
            heuristic = 0.0

        if self.mouse_model is None:
            return heuristic

        try:
            if len(features_seq) < SEQUENCE_LENGTH:
                return heuristic
            import numpy as _np
            seq   = _np.array(features_seq[-SEQUENCE_LENGTH:], dtype=_np.float32)
            inp   = seq.reshape(1, SEQUENCE_LENGTH, MOUSE_FEATURE_DIM)
            recon = self.mouse_model.predict(inp, verbose=0)
            diff  = [a - b for a, b in zip(inp.flatten(), recon.flatten())]
            mse   = sum(d*d for d in diff) / len(diff)
            model_score = float(min(mse / self.mouse_anomaly_threshold, 1.0))
            if peak_speed < MOUSE_EXTREME_SPEED_THRESHOLD:
                return float(min(model_score, heuristic, 0.20))
            return float(max(model_score, heuristic))
        except Exception as e:
            logger.debug(f"Mouse predict error: {e}")
            return heuristic


detector = MLAnomalyDetector()


# ── Mouse Tracker ─────────────────────────────────────────────────────────────
class MouseTracker:
    def __init__(self):
        self.running          = False
        self.last_x           = 960
        self.last_y           = 540
        self.last_time        = time.time()
        self.movement_buffer  = []
        self.last_emit_time   = 0
        self.movement_counter = 0
        self._listener        = None
        self._sim_thread      = None

    def start(self):
        if self.running:
            return True
        self.running = True
        if PYNPUT_AVAILABLE:
            ok = self._start_real()
            if ok:
                return True
            logger.warning("⚠️  pynput listener failed — falling back to simulation")
        logger.info("🎮 Mouse SIMULATION mode starting…")
        self._sim_thread = threading.Thread(
            target=self._simulate_mouse, daemon=True, name="MouseSimulator")
        self._sim_thread.start()
        logger.info("✅ Mouse simulation started")
        return True

    def stop(self):
        self.running = False
        if self._listener:
            try:
                self._listener.stop()
            except Exception:
                pass
            self._listener = None
        logger.info("Mouse tracking stopped")

    def _start_real(self):
        try:
            from pynput import mouse as pynput_mouse
            try:
                import ctypes
                pt = ctypes.wintypes.POINT()
                ctypes.windll.user32.GetCursorPos(ctypes.byref(pt))
                self.last_x, self.last_y = pt.x, pt.y
            except Exception:
                self.last_x, self.last_y = 960, 540
            self.last_time = time.time()
            self._listener = pynput_mouse.Listener(
                on_move=self._on_move, on_click=self._on_click)
            self._listener.start()
            logger.info("✅ REAL mouse tracking started (pynput)")
            return True
        except Exception as e:
            logger.error(f"❌ pynput listener failed: {e}")
            self.running = False
            return False

    def _on_move(self, x, y):
        if not self.running:
            return
        self.movement_counter += 1
        if self.movement_counter % 5 != 0:
            return
        t    = time.time()
        dt   = t - self.last_time
        dist = ((x - self.last_x) ** 2 + (y - self.last_y) ** 2) ** 0.5
        speed = dist / dt if dt > 0 else 0.0
        self._process_event({
            'type':      'move',
            'x':         int(x),
            'y':         int(y),
            'speed':     float(speed),
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        })
        self.last_x, self.last_y, self.last_time = x, y, t

    def _on_click(self, x, y, button, pressed):
        if not self.running or not pressed:
            return
        self._process_event({
            'type':      'click',
            'button':    str(button).split('.')[-1],
            'x':         int(x),
            'y':         int(y),
            'speed':     0,
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        })

    def _simulate_mouse(self):
        x, y = 960, 540
        burst_counter = 0
        while self.running:
            try:
                burst_counter += 1
                is_burst = (burst_counter % 60 == 0)
                if is_burst:
                    dx = random.randint(-600, 600)
                    dy = random.randint(-400, 400)
                    speed = float((dx ** 2 + dy ** 2) ** 0.5) / 0.05
                else:
                    dx = random.randint(-60, 60)
                    dy = random.randint(-40, 40)
                    speed = float((dx ** 2 + dy ** 2) ** 0.5) / random.uniform(0.1, 0.5)
                x = max(0, min(1920, x + dx))
                y = max(0, min(1080, y + dy))
                self._process_event({
                    'type':      'move', 'x': x, 'y': y,
                    'speed':     round(speed, 2),
                    'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                })
                if random.random() < 0.05:
                    self._process_event({
                        'type':      'click',
                        'button':    random.choice(['left', 'right']),
                        'x': x, 'y': y, 'speed': 0,
                        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                    })
                time.sleep(random.uniform(0.2, 0.7))
            except Exception as e:
                logger.debug(f"Mouse simulation error: {e}")
                time.sleep(1)

    def _process_event(self, event):
        global mouse_movements, current_stats

        features = detector.extract_mouse_features(event)
        self.movement_buffer.append(features)
        if len(self.movement_buffer) > 20:
            self.movement_buffer.pop(0)

        anomaly_score = 0.0
        if len(self.movement_buffer) >= SEQUENCE_LENGTH:
            anomaly_score = detector.predict_mouse_anomaly(
                self.movement_buffer[-SEQUENCE_LENGTH:])
        else:
            try:
                anomaly_score = min(float(features[2]), 0.95)
            except Exception:
                anomaly_score = 0.0

        event['anomaly_score'] = float(anomaly_score)
        mouse_movements.append(event)
        if len(mouse_movements) > 200:
            mouse_movements.pop(0)

        if event['type'] == 'move':
            current_stats['mouse_movement_count'] += 1
        elif event['type'] == 'click':
            current_stats['mouse_clicks'] += 1

        current_stats['total_mouse_events'] += 1
        current_stats['mouse_anomaly_score'] = float(anomaly_score)
        if anomaly_score >= MOUSE_ALERT_THRESHOLD:
            current_stats['mouse_anomalies'] += 1

        now = time.time()
        if now - self.last_emit_time >= 0.3:
            recent = {
                'type': 'mouse', 'action': event['type'],
                'details': f"({event.get('x', 0)}, {event.get('y', 0)})",
                'time': event['timestamp'], 'anomaly_score': float(anomaly_score),
            }
            current_stats['recent_activities'].insert(0, recent)
            if len(current_stats['recent_activities']) > 50:
                current_stats['recent_activities'].pop()
            try:
                socketio.emit('mouse_event',  event)
                socketio.emit('stats_update', current_stats)
            except Exception as e:
                logger.debug(f"Emit error (mouse): {e}")
            self.last_emit_time = now

        if anomaly_score >= MOUSE_ALERT_THRESHOLD:
            try:
                socketio.emit('anomaly_alert', {
                    'type':      'mouse',
                    'message':   f"Anomalous mouse {event['type']}: speed={event.get('speed', 0):.0f}",
                    'score':     float(anomaly_score),
                    'timestamp': event['timestamp'],
                })
            except Exception:
                pass


# ── File Monitor ──────────────────────────────────────────────────────────────
class FileMonitor:
    def __init__(self):
        self.running        = False
        self.monitor_thread = None
        self.file_state     = {}
        self.last_emit_time = 0
        self.recent_events  = {}
        self.recent_paths   = {}

        candidates = [
            os.path.expanduser("~\\Desktop"),
            os.path.expanduser("~\\Documents"),
            os.path.expanduser("~\\Downloads"),
            os.path.expanduser("~/Desktop"),
            os.path.expanduser("~/Documents"),
            os.path.expanduser("~/Downloads"),
        ]
        # On Windows with OneDrive folder redirection, Desktop/Documents live
        # under OneDrive (e.g. C:\Users\induw\OneDrive\Desktop), not ~\Desktop.
        # Use winreg to get the real shell folder paths.
        if sys.platform == 'win32':
            try:
                import winreg
                _key = winreg.OpenKey(
                    winreg.HKEY_CURRENT_USER,
                    r'Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders'
                )
                for _reg_name in ('Desktop', 'Personal'):
                    try:
                        candidates.append(winreg.QueryValueEx(_key, _reg_name)[0])
                    except Exception:
                        pass
                winreg.CloseKey(_key)
            except Exception:
                pass
        self.watched_paths = self._normalize_watch_paths(candidates)
        if not self.watched_paths:
            home = os.path.expanduser("~")
            if os.path.isdir(home):
                self.watched_paths = [home]

    def _normalize_watch_paths(self, paths):
        """Remove duplicate and nested watch roots to avoid double counting."""
        normalized = []
        seen = set()
        for path in paths:
            if not path or not os.path.isdir(path):
                continue
            real = os.path.normcase(os.path.abspath(path))
            if real in seen:
                continue
            seen.add(real)
            normalized.append(os.path.abspath(path))

        result = []
        for path in sorted(normalized, key=len):
            real = os.path.normcase(os.path.abspath(path))
            is_nested = False
            for existing in result:
                existing_real = os.path.normcase(os.path.abspath(existing))
                try:
                    common = os.path.commonpath([real, existing_real])
                except ValueError:
                    common = ''
                if common == existing_real:
                    is_nested = True
                    break
            if not is_nested:
                result.append(path)
        return result

    def start(self):
        if self.running:
            return False
        if not self.watched_paths:
            logger.warning("⚠️  No valid paths to watch for file changes")
            return False
        self.running = True
        self.monitor_thread = threading.Thread(
            target=self._monitor_files, daemon=True, name="FileMonitor")
        self.monitor_thread.start()
        logger.info("✅ Real file monitoring started")
        logger.info(f"   Watching: {', '.join(self.watched_paths)}")
        return True

    def stop(self):
        self.running = False
        logger.info("File monitoring stopped")

    def _get_files_in_directory(self, path):
        # Returns dict {filepath: (rounded_mtime, size)} for O(1) lookups
        # and proper modification detection.
        files = {}
        try:
            for root, dirs, filenames in os.walk(path):
                dirs[:] = [d for d in dirs
                           if not d.startswith('.') and d not in ('$RECYCLE.BIN',)]
                for filename in filenames:
                    full = os.path.join(root, filename)
                    try:
                        st = os.stat(full)
                        files[full] = (round(st.st_mtime, 1), st.st_size)
                    except OSError:
                        pass
        except Exception as e:
            logger.debug(f"Scan error {path}: {e}")
        return files

    def _monitor_files(self):
        for path in self.watched_paths:
            self.file_state[path] = self._get_files_in_directory(path)
            logger.info(f"   ✓ Baseline {path}: {len(self.file_state[path])} files")
        logger.info("File monitoring active — scanning every 2 s…")
        while self.running:
            try:
                for path in self.watched_paths:
                    if not os.path.isdir(path):
                        continue
                    current = self._get_files_in_directory(path)
                    old     = self.file_state.get(path, {})

                    cur_keys = set(current.keys())
                    old_keys = set(old.keys())

                    for fp in cur_keys - old_keys:
                        _, sz = current[fp]
                        self._process_event({
                            'type': 'created', 'path': fp,
                            'filename': os.path.basename(fp), 'size': int(sz),
                            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                        })
                    for fp in old_keys - cur_keys:
                        _, sz = old[fp]
                        self._process_event({
                            'type': 'deleted', 'path': fp,
                            'filename': os.path.basename(fp), 'size': int(sz),
                            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                        })
                    for fp in cur_keys & old_keys:
                        if current[fp] != old[fp]:
                            _, sz = current[fp]
                            self._process_event({
                                'type': 'modified', 'path': fp,
                                'filename': os.path.basename(fp), 'size': int(sz),
                                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                            })

                    self.file_state[path] = current
                time.sleep(2)
            except Exception as e:
                logger.error(f"File monitor error: {e}")
                time.sleep(5)

    def _process_event(self, event):
        global file_events, current_stats
        if self._is_duplicate_event(event):
            return

        features      = detector.extract_file_features(event)
        anomaly_score = detector.predict_file_anomaly(features)
        event['anomaly_score'] = float(anomaly_score)

        file_events.append(event)
        if len(file_events) > 500:
            file_events.pop(0)

        current_stats['total_file_events'] += 1
        current_stats['file_operations'][event['type']] = (
            current_stats['file_operations'].get(event['type'], 0) + 1)
        current_stats['file_anomaly_score'] = float(anomaly_score)
        if anomaly_score > 0.5:
            current_stats['file_anomalies'] += 1

        recent = {
            'type': 'file', 'operation': event['type'],
            'path': event['filename'], 'time': event['timestamp'],
            'anomaly_score': float(anomaly_score),
        }
        current_stats['recent_activities'].insert(0, recent)
        if len(current_stats['recent_activities']) > 50:
            current_stats['recent_activities'].pop()

        try:
            socketio.emit('file_event',   event)
            socketio.emit('stats_update', current_stats)
        except Exception as e:
            logger.debug(f"Emit error (file): {e}")

        if anomaly_score > 0.5:
            try:
                socketio.emit('anomaly_alert', {
                    'type':      'file',
                    'message':   f"Anomalous file {event['type']}: {event['filename']}",
                    'score':     float(anomaly_score),
                    'timestamp': event['timestamp'],
                })
            except Exception:
                pass
            logger.info(f"FILE ANOMALY: {event['type']} - {event['filename']} "
                        f"(score={anomaly_score:.3f})")

    def _is_duplicate_event(self, event):
        """
        Suppress duplicate file events caused by overlapping folders or Windows
        write behavior where a single action appears as create+modify.
        """
        now = time.time()
        path = os.path.normcase(os.path.abspath(event.get('path', '')))
        event_type = event.get('type', '')
        size = int(event.get('size') or 0)

        if not path:
            return False

        # Clean old cache entries.
        for key, ts in list(self.recent_events.items()):
            if now - ts > 10:
                self.recent_events.pop(key, None)
        for old_path, info in list(self.recent_paths.items()):
            if now - info.get('time', 0) > 10:
                self.recent_paths.pop(old_path, None)

        exact_key = (path, event_type, size)
        loose_key = (path, event_type)
        if now - self.recent_events.get(exact_key, 0) <= 8:
            return True
        if now - self.recent_events.get(loose_key, 0) <= 8:
            return True

        last_for_path = self.recent_paths.get(path)
        if last_for_path:
            age = now - last_for_path.get('time', 0)
            last_type = last_for_path.get('type')
            # Treat create/delete followed by modify as the same user action.
            if event_type == 'modified' and last_type in ('created', 'deleted') and age < 5:
                return True
            # Some Windows/OneDrive folders report the same create/delete across
            # multiple scans. Count the first one only.
            if event_type == last_type and age <= 8:
                return True

        self.recent_events[exact_key] = now
        self.recent_events[loose_key] = now
        self.recent_paths[path] = {'time': now, 'type': event_type, 'size': size}
        return False

# ── Instantiate monitors ──────────────────────────────────────────────────────
file_monitor  = FileMonitor()
mouse_tracker = MouseTracker()

update_thread_running = False


# ── Continuous stats push ─────────────────────────────────────────────────────
def continuous_update_sender():
    logger.info("  🔄 Continuous update thread started")
    last_push  = time.time()
    last_decay = time.time()
    while update_thread_running:
        try:
            now = time.time()
            # Decay displayed anomaly scores toward 0 every 10 s so a single
            # past anomalous event does not permanently light up the dashboard.
            if now - last_decay >= 10:
                current_stats['file_anomaly_score']  *= 0.75
                current_stats['mouse_anomaly_score'] *= 0.75
                last_decay = now
            if now - last_push >= 1:
                try:
                    socketio.emit('stats_update', current_stats)
                except Exception:
                    pass
                last_push = now
            time.sleep(0.5)
        except Exception as e:
            logger.error(f"Update thread error: {e}")
            time.sleep(1)


# ── Routes ────────────────────────────────────────────────────────────────────
@app.route('/')
def index():
    from flask import render_template as _rt
    templates_path = os.path.join(BASE_DIR, 'templates', 'file_mouse.html')
    if os.path.exists(templates_path):
        return _rt('file_mouse.html')
    direct_path = os.path.join(BASE_DIR, 'file_mouse.html')
    if os.path.exists(direct_path):
        return send_file(direct_path)
    logger.error(f"❌ file_mouse.html not found. Looked in:\n  {templates_path}\n  {direct_path}")
    return (
        "<meta charset='UTF-8'>"
        "<h2>⚠️ file_mouse.html not found</h2>"
        "<p>Put <b>file_mouse.html</b> in one of these locations:</p>"
        f"<ul><li><code>{templates_path}</code> (recommended)</li>"
        f"<li><code>{direct_path}</code></li></ul>"
    ), 404


@app.route('/api/stats')
def get_stats():
    return jsonify(current_stats)


@app.route('/api/status')
def get_status():
    return jsonify({
        'monitoring_active':     monitoring_active,
        'models_loaded':         detector.models_loaded,
        'file_model_loaded':     detector.file_model is not None or detector.file_pkl_model is not None,
        'file_h5_model_loaded':  detector.file_model is not None,
        'file_pkl_model_loaded': detector.file_pkl_model is not None,
        'mouse_model_loaded':    detector.mouse_model is not None,
        'file_events_count':     len(file_events),
        'mouse_events_count':    len(mouse_movements),
        'mouse_tracking_active': mouse_tracker.running,
        'pynput_available':      PYNPUT_AVAILABLE,
        'tf_available':          TF_AVAILABLE,
        'numpy_available':       NUMPY_AVAILABLE,
        'mouse_mode':            'real' if PYNPUT_AVAILABLE else 'simulation',
        'file_model_path':       FILE_MODEL_PATH,
        'file_pkl_model_path':   detector.file_pkl_model_path,
        'mouse_model_path':      MOUSE_MODEL_PATH,
        'file_model_exists':     os.path.exists(FILE_MODEL_PATH),
        'file_pkl_model_exists': any(os.path.exists(p) for p in FILE_PKL_MODEL_CANDIDATES),
        'mouse_model_exists':    os.path.exists(MOUSE_MODEL_PATH),
    })


@app.route('/api/clear', methods=['POST'])
def clear_stats():
    global file_events, mouse_movements, current_stats
    file_events     = []
    mouse_movements = []
    current_stats = {
        'total_file_events':    0,
        'total_mouse_events':   0,
        'file_operations':      {},
        'mouse_movement_count': 0,
        'mouse_clicks':         0,
        'active_windows':       [],
        'recent_activities':    [],
        'file_anomaly_score':   0.0,
        'mouse_anomaly_score':  0.0,
        'file_anomalies':       0,
        'mouse_anomalies':      0,
        'models_loaded':        detector.models_loaded,
        'mouse_mode':           'real' if PYNPUT_AVAILABLE else 'simulation',
    }
    try:
        socketio.emit('stats_cleared')
        socketio.emit('stats_update', current_stats)
    except Exception:
        pass
    return jsonify({'status': 'success'})


# ── SocketIO events ───────────────────────────────────────────────────────────
@socketio.on('connect')
def handle_connect():
    logger.info("  🔌 Client connected")
    emit('connected', {
        'status':        'connected',
        'models_loaded': detector.models_loaded,
        'mouse_mode':    'real' if PYNPUT_AVAILABLE else 'simulation',
        'pynput':        PYNPUT_AVAILABLE,
        'tf':            TF_AVAILABLE,
        'file_model':    detector.file_model  is not None,
        'mouse_model':   detector.mouse_model is not None,
    })
    if monitoring_active:
        emit('monitoring_status', {
            'status': 'started',
            'mode':   'real_mouse' if PYNPUT_AVAILABLE else 'simulation',
        })
    if current_stats['total_file_events'] > 0 or current_stats['total_mouse_events'] > 0:
        emit('stats_update', current_stats)


@socketio.on('start_monitoring')
def handle_start():
    global monitoring_active
    logger.info("  ▶️  Start monitoring request")
    if not monitoring_active:
        monitoring_active = True
        file_monitor.start()
        mouse_tracker.start()
        mode = 'real_mouse' if PYNPUT_AVAILABLE else 'simulation'
        emit('monitoring_status', {'status': 'started', 'mode': mode})
        logger.info(f"✅ Monitoring started — mode: {mode}")
    else:
        emit('monitoring_status', {'status': 'already_running'})


@socketio.on('stop_monitoring')
def handle_stop():
    global monitoring_active
    logger.info("  ⏹️  Stop monitoring request")
    if monitoring_active:
        file_monitor.stop()
        mouse_tracker.stop()
        monitoring_active = False
        emit('monitoring_status', {'status': 'stopped'})
    else:
        emit('monitoring_status', {'status': 'already_stopped'})


@socketio.on('clear_stats')
def handle_clear():
    global file_events, mouse_movements, current_stats
    logger.info("  🗑️  Clear stats")
    file_events     = []
    mouse_movements = []
    current_stats = {
        'total_file_events':    0,
        'total_mouse_events':   0,
        'file_operations':      {},
        'mouse_movement_count': 0,
        'mouse_clicks':         0,
        'active_windows':       [],
        'recent_activities':    [],
        'file_anomaly_score':   0.0,
        'mouse_anomaly_score':  0.0,
        'file_anomalies':       0,
        'mouse_anomalies':      0,
        'models_loaded':        detector.models_loaded,
        'mouse_mode':           'real' if PYNPUT_AVAILABLE else 'simulation',
    }
    emit('stats_cleared')
    emit('stats_update', current_stats)


# ── Entry point ───────────────────────────────────────────────────────────────
if __name__ == '__main__':
    # ── Step 1: start TF import in background ─────────────────────────────────
    _tf_thread = threading.Thread(target=_try_import_tf, daemon=True, name="TFImport")
    _tf_thread.start()

    # ── Step 2: load models — waits internally for TF import to finish ────────
    # Run in a daemon thread so the Flask server starts immediately,
    # but the thread itself will block until TF is ready before loading .h5 files.
    _model_thread = threading.Thread(
        target=detector.load_models, daemon=True, name="ModelLoad")
    _model_thread.start()

    # ── Step 3: continuous stats emitter ──────────────────────────────────────
    update_thread_running = True
    _update_thread = threading.Thread(
        target=continuous_update_sender, daemon=True, name="UpdateThread")
    _update_thread.start()

    # ── Step 4: AUTO-START monitoring ─────────────────────────────────────────
    monitoring_active = True
    file_monitor.start()
    mouse_tracker.start()

    port = 5003

    print("\n" + "=" * 70)
    print(f"📡 File & Mouse Monitor URL : http://localhost:{port}")
    print(f"🖱️  Mouse mode  : {'✅ REAL (pynput)' if PYNPUT_AVAILABLE else '🎮 SIMULATION (pynput not installed)'}")
    print(f"📐 numpy        : {'✅ available' if NUMPY_AVAILABLE else '⚠️  missing — pure-Python fallback active'}")
    print(f"🤖 ML models   : Loading in background (waiting for TF)…")
    print(f"📂 File model  : {FILE_MODEL_PATH}")
    print(f"📂 Mouse model : {MOUSE_MODEL_PATH}")
    print("📁 File monitoring  : ✅ AUTO-STARTED")
    print("🖱️  Mouse tracking  : ✅ AUTO-STARTED (" +
          ("real" if PYNPUT_AVAILABLE else "simulation") + ")")
    print("=" * 70 + "\n")

    try:
        socketio.run(
            app,
            host='0.0.0.0',
            port=port,
            debug=False,
            allow_unsafe_werkzeug=True,
            use_reloader=False,
        )
    except KeyboardInterrupt:
        print("\n\n🛑 Shutting down…")
        update_thread_running = False
        file_monitor.stop()
        mouse_tracker.stop()
        print("✅ Server stopped")
    except Exception as e:
        print(f"\n❌ Fatal error: {e}")
        import traceback
        traceback.print_exc()
