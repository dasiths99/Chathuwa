import csv
import os
import secrets
import threading
import time
from collections import Counter, defaultdict
from datetime import datetime
from io import StringIO

import joblib
import numpy as np
import pandas as pd
from flask import Flask, Response, jsonify, render_template, request, session
from flask_socketio import SocketIO
from sklearn.preprocessing import LabelEncoder


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
API_MODEL_DIR = os.path.join(BASE_DIR, 'API_analyzer', 'Models')
API_DATA_DIR = os.path.join(BASE_DIR, 'DataSet')
API_TEST_SOURCE_DATASET_PATH = os.path.join(API_DATA_DIR, 'remaining_behavior_ext.csv')
API_TEST_EXTRACTED_DATASET_PATH = os.path.join(API_DATA_DIR, 'api_behavior_test_samples_v2.csv')

API_ALLOWED_CLASSES = ['normal', 'bot', 'outlier', 'attack']
API_IP_TYPE_CLASSES = ['default', 'private', 'public', 'unknown_ip_type']
API_BEHAVIOR_TYPE_CLASSES = API_ALLOWED_CLASSES + ['unknown_behavior_type']
API_BEHAVIOR_CLASSES = ['Normal', 'Googlebot/2.1', 'bot', 'outlier', 'attack', 'unknown_behavior_category']
API_SOURCE_CLASSES = ['F', 'R', 'unknown_source_category']

API_FEATURE_COLUMNS = [
    'inter_api_access_duration(sec)',
    'api_access_uniqueness',
    'sequence_length(count)',
    'vsession_duration(min)',
    'num_sessions',
    'num_users',
]

CSV_COLUMNS = [
    'inter_api_access_duration(sec)',
    'api_access_uniqueness',
    'sequence_length(count)',
    'vsession_duration(min)',
    'num_sessions',
    'num_users',
    'num_unique_apis',
    'ip_type',
    'behavior',
    'behavior_type',
    'source',
]


app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY') or secrets.token_hex(32)
app.config['MAX_CONTENT_LENGTH'] = int(os.getenv('MAX_CONTENT_LENGTH', str(16 * 1024 * 1024)))
socketio = SocketIO(app, cors_allowed_origins='*', async_mode='threading')

api_requests_log = []
api_anomaly_count = 0
api_class_counts = defaultdict(int)
is_api_monitoring_active = False
api_state_lock = threading.RLock()

api_dataset_streaming_active = False
api_dataset_stream_thread = None
api_dataset_stream_stop_event = threading.Event()
api_dataset_stream_index = 0
api_dataset_stream_lock = threading.Lock()

api_test_dataset_cache = None
api_test_dataset_lock = threading.Lock()

api_model = None
api_scaler = None
api_label_encoder = None

api_le_ip_type = LabelEncoder().fit(API_IP_TYPE_CLASSES)
api_le_behavior_type = LabelEncoder().fit(API_BEHAVIOR_TYPE_CLASSES)
api_le_behavior = LabelEncoder().fit(API_BEHAVIOR_CLASSES)
api_le_source = LabelEncoder().fit(API_SOURCE_CLASSES)


def normalize_api_prediction(raw_label, features=None):
    label = str(raw_label or '').strip().lower()
    if label in API_ALLOWED_CLASSES:
        return label
    if any(token in label for token in ('attack', 'sql', 'xss', 'brute', 'injection')):
        return 'attack'
    if 'bot' in label or 'crawler' in label:
        return 'bot'
    if any(token in label for token in ('outlier', 'anomaly', 'suspicious')):
        return 'outlier'
    return 'normal'


def safe_float(value, default=0.0):
    try:
        if pd.isna(value):
            return default
        return float(value)
    except Exception:
        return default


def safe_int(value, default=0):
    try:
        if pd.isna(value):
            return default
        return int(float(value))
    except Exception:
        return default


def safe_label_transform(encoder, value, fallback):
    text = str(value if value not in (None, '') else fallback)
    try:
        if text in encoder.classes_:
            return int(encoder.transform([text])[0])
        if fallback in encoder.classes_:
            return int(encoder.transform([fallback])[0])
    except Exception:
        pass
    return 0


def load_api_artifacts():
    global api_model, api_scaler, api_label_encoder
    model_path = os.path.join(API_MODEL_DIR, 'api_model.pkl')
    scaler_path = os.path.join(API_MODEL_DIR, 'api_scaler.pkl')
    encoder_path = os.path.join(API_MODEL_DIR, 'api_label_encoder.pkl')

    try:
        api_model = joblib.load(model_path) if os.path.exists(model_path) else None
        api_scaler = joblib.load(scaler_path) if os.path.exists(scaler_path) else None
        api_label_encoder = joblib.load(encoder_path) if os.path.exists(encoder_path) else None
    except Exception as exc:
        print(f"[api] Could not load API model artifacts: {exc}", flush=True)
        api_model = api_scaler = api_label_encoder = None


def strict_api_artifacts_ready():
    if api_model is None:
        return False, 'api_model.pkl is missing or could not be loaded'
    if api_label_encoder is None:
        return False, 'api_label_encoder.pkl is missing or could not be loaded'
    return True, 'ready'


def strict_api_artifacts_payload():
    ready, reason = strict_api_artifacts_ready()
    return {
        'ready': ready,
        'reason': reason,
        'model': os.path.join('API_analyzer', 'Models', 'api_model.pkl'),
        'scaler': os.path.join('API_analyzer', 'Models', 'api_scaler.pkl'),
        'label_encoder': os.path.join('API_analyzer', 'Models', 'api_label_encoder.pkl'),
    }


def derive_api_categories(raw_data, features):
    path = str(raw_data.get('path') or raw_data.get('url') or '').lower()
    method = str(raw_data.get('method') or 'GET').upper()
    body = str(raw_data.get('body') or '')
    user_agent = str(raw_data.get('user_agent') or raw_data.get('User-Agent') or '').lower()

    suspicious_tokens = sum(
        token in f'{path} {body}'
        for token in ('../', 'select ', 'union ', '<script', 'drop ', ' or ', 'token=', 'admin', 'passwd')
    )
    if 'bot' in user_agent or 'crawler' in user_agent:
        behavior_type = 'bot'
        behavior = 'bot'
    elif suspicious_tokens or method in ('DELETE', 'PUT', 'PATCH'):
        behavior_type = 'attack'
        behavior = 'attack'
    elif features.get('sequence_length(count)', 0) > 90 or features.get('vsession_duration(min)', 0) > 50000:
        behavior_type = 'outlier'
        behavior = 'outlier'
    else:
        behavior_type = 'normal'
        behavior = 'Normal'

    return {
        'ip_type': raw_data.get('ip_type') or 'default',
        'behavior_type': behavior_type,
        'behavior': raw_data.get('behavior') or behavior,
        'source': raw_data.get('source') or 'unknown_source_category',
    }


def normalize_input(raw_data):
    now = time.time()
    path = str(raw_data.get('path') or raw_data.get('url') or '/api/request')
    src_ip = str(raw_data.get('src_ip') or raw_data.get('ip') or request.remote_addr or '0.0.0.0')
    method = str(raw_data.get('method') or 'GET').upper()

    features = {
        'inter_api_access_duration(sec)': safe_float(raw_data.get('inter_api_access_duration(sec)'), 0.0),
        'api_access_uniqueness': safe_float(raw_data.get('api_access_uniqueness'), 0.5),
        'sequence_length(count)': safe_float(raw_data.get('sequence_length(count)'), 1.0),
        'vsession_duration(min)': safe_float(raw_data.get('vsession_duration(min)'), 1.0),
        'num_sessions': safe_float(raw_data.get('num_sessions'), 1.0),
        'num_users': safe_float(raw_data.get('num_users'), 1.0),
        'num_unique_apis': safe_float(raw_data.get('num_unique_apis'), 1.0),
    }
    categories = derive_api_categories(raw_data, features)
    return {
        **features,
        **categories,
        'method': method,
        'path': path,
        'src_ip': src_ip,
        'timestamp': raw_data.get('timestamp') or datetime.fromtimestamp(now).isoformat(),
    }


def build_model_matrix(normalized):
    row = {col: safe_float(normalized.get(col), 0.0) for col in API_FEATURE_COLUMNS}

    model_features = list(getattr(api_model, 'feature_names_in_', []) or [])
    if model_features:
        extended = dict(row)
        extended.update({
            'num_unique_apis': safe_float(normalized.get('num_unique_apis'), 0.0),
            'type_ip': safe_label_transform(api_le_ip_type, normalized.get('ip_type'), 'unknown_ip_type'),
            'type_behaviour': safe_label_transform(api_le_behavior_type, normalized.get('behavior_type'), 'unknown_behavior_type'),
            'behaviour': safe_label_transform(api_le_behavior, normalized.get('behavior'), 'unknown_behavior_category'),
            'source_type': safe_label_transform(api_le_source, normalized.get('source'), 'unknown_source_category'),
        })
        df = pd.DataFrame([{name: extended.get(name, 0.0) for name in model_features}])
    else:
        df = pd.DataFrame([row], columns=API_FEATURE_COLUMNS)

    if api_scaler is not None and not model_features:
        try:
            return api_scaler.transform(df)
        except Exception:
            return df
    return df


def heuristic_prediction(normalized):
    label = normalize_api_prediction(normalized.get('behavior_type'), normalized)
    score = 0.72
    if label == 'attack':
        score = 0.91
    elif label == 'bot':
        score = 0.87
    elif label == 'outlier':
        score = 0.82
    return label, score, 'heuristic'


def predict_api_call(raw_data, require_trained_model=False):
    normalized = normalize_input(raw_data)
    ready, reason = strict_api_artifacts_ready()

    if ready:
        try:
            matrix = build_model_matrix(normalized)
            pred = api_model.predict(matrix)[0]
            if api_label_encoder is not None:
                try:
                    raw_label = api_label_encoder.inverse_transform([pred])[0]
                except Exception:
                    raw_label = pred
            else:
                raw_label = pred
            label = normalize_api_prediction(raw_label, normalized)

            confidence = 0.86
            if hasattr(api_model, 'predict_proba'):
                proba = api_model.predict_proba(matrix)[0]
                confidence = float(np.max(proba))

            return {
                **normalized,
                'prediction': label,
                'raw_prediction': str(raw_label),
                'confidence': confidence,
                'accuracy_percent': round(confidence * 100.0, 2),
                'prediction_method': 'machine_learning',
                'used_trained_model': True,
            }
        except Exception as exc:
            if require_trained_model:
                raise
            print(f"[api] ML prediction failed, using heuristic: {exc}", flush=True)

    label, confidence, method = heuristic_prediction(normalized)
    return {
        **normalized,
        'prediction': label,
        'raw_prediction': label,
        'confidence': confidence,
        'accuracy_percent': round(confidence * 100.0, 2),
        'prediction_method': method if not require_trained_model else f'fallback: {reason}',
        'used_trained_model': False,
    }


def process_api_request_data(data, source='socket', require_trained_model=False):
    global api_anomaly_count
    if not is_api_monitoring_active:
        return None

    result = predict_api_call(data, require_trained_model=require_trained_model)
    prediction = normalize_api_prediction(result.get('prediction'), result)
    record = {
        **result,
        'prediction': prediction,
        'source': source,
        'timestamp': datetime.now().isoformat(),
    }

    with api_state_lock:
        api_requests_log.append(record)
        if len(api_requests_log) > 1000:
            del api_requests_log[:-1000]
        api_class_counts[prediction] += 1
        if prediction != 'normal':
            api_anomaly_count += 1

        payload_counts = {label: int(api_class_counts.get(label, 0)) for label in API_ALLOWED_CLASSES}
        total_requests = len(api_requests_log)
        total_anomalies = api_anomaly_count

    socketio.emit('api_threat', {
        **record,
        'class_counts': payload_counts,
        'total_requests': total_requests,
        'total_anomalies': total_anomalies,
        'model_artifacts_used': strict_api_artifacts_payload() if record.get('used_trained_model') else None,
    })
    socketio.emit('api_monitoring_status', {
        'is_monitoring': is_api_monitoring_active,
        'total_requests': total_requests,
        'total_anomalies': total_anomalies,
        'class_counts': payload_counts,
    })
    return record


def get_api_test_dataset(force_refresh=False):
    global api_test_dataset_cache
    with api_test_dataset_lock:
        if force_refresh:
            api_test_dataset_cache = None
        if api_test_dataset_cache is not None:
            return api_test_dataset_cache.copy()

        path = API_TEST_EXTRACTED_DATASET_PATH if os.path.exists(API_TEST_EXTRACTED_DATASET_PATH) else API_TEST_SOURCE_DATASET_PATH
        if os.path.exists(path):
            df = pd.read_csv(path)
        else:
            df = pd.DataFrame([{
                'inter_api_access_duration(sec)': 0.2,
                'api_access_uniqueness': 0.5,
                'sequence_length(count)': 10,
                'vsession_duration(min)': 5,
                'num_sessions': 1,
                'num_users': 1,
                'num_unique_apis': 4,
                'ip_type': 'default',
                'behavior': 'Normal',
                'behavior_type': 'normal',
                'source': 'unknown_source_category',
            }])

        for col in CSV_COLUMNS:
            if col not in df.columns:
                df[col] = 'unknown_source_category' if col == 'source' else 'default' if col == 'ip_type' else 'Normal' if col == 'behavior' else 'normal' if col == 'behavior_type' else 0
        api_test_dataset_cache = df[CSV_COLUMNS].copy()
        return api_test_dataset_cache.copy()


def dataset_row_to_api_event(row):
    payload = {col: row.get(col) for col in CSV_COLUMNS}
    payload.update({
        'method': 'GET',
        'path': f"/api/investigate/{safe_int(row.name, 0)}",
        'src_ip': '127.0.0.1',
    })
    return payload


def dataset_event_stream(interval_seconds=1.0):
    global api_dataset_streaming_active, api_dataset_stream_index
    try:
        while not api_dataset_stream_stop_event.is_set():
            if is_api_monitoring_active:
                df = get_api_test_dataset()
                if not df.empty:
                    with api_dataset_stream_lock:
                        idx = api_dataset_stream_index % len(df)
                        api_dataset_stream_index += 1
                    process_api_request_data(dataset_row_to_api_event(df.iloc[idx]), source='dataset_stream')
            if api_dataset_stream_stop_event.wait(interval_seconds):
                break
    finally:
        api_dataset_streaming_active = False


def start_dataset_event_stream(interval_seconds=1.0):
    global api_dataset_streaming_active, api_dataset_stream_thread
    with api_dataset_stream_lock:
        if api_dataset_streaming_active and api_dataset_stream_thread and api_dataset_stream_thread.is_alive():
            return False
        api_dataset_stream_stop_event.clear()
        api_dataset_streaming_active = True
        api_dataset_stream_thread = threading.Thread(
            target=dataset_event_stream,
            args=(interval_seconds,),
            daemon=True,
            name='ApiDatasetStream',
        )
        api_dataset_stream_thread.start()
        return True


def stop_dataset_event_stream():
    global api_dataset_streaming_active
    api_dataset_stream_stop_event.set()
    api_dataset_streaming_active = False


@app.before_request
def auto_login():
    session.setdefault('user_id', 'api_analyst')
    session.setdefault('user_email', 'analyst@example.local')


@app.before_request
def capture_live_api_request():
    if not is_api_monitoring_active:
        return None
    if request.path.startswith('/api/') or request.path.startswith('/socket.io') or request.path == '/api-analyzer':
        return None
    payload = {
        'method': request.method,
        'path': request.path,
        'src_ip': request.remote_addr or '0.0.0.0',
        'body': request.get_data(as_text=True)[:2000],
    }
    process_api_request_data(payload, source='http_capture')
    return None


@app.route('/')
def index():
    return '', 302, {'Location': '/api-analyzer'}


@app.route('/api-analyzer')
def api_analyzer():
    return render_template('api_analyzer.html', username=session.get('user_id', 'api_analyst'))


@app.route('/api/start_api_monitoring', methods=['POST'])
def start_api_monitoring():
    global is_api_monitoring_active
    is_api_monitoring_active = True
    socketio.emit('api_monitoring_status', {
        'is_monitoring': True,
        'total_requests': len(api_requests_log),
        'total_anomalies': api_anomaly_count,
        'class_counts': {label: int(api_class_counts.get(label, 0)) for label in API_ALLOWED_CLASSES},
    })
    return jsonify({'status': 'success', 'message': 'API behavior monitoring started'})


@app.route('/api/stop_api_monitoring', methods=['POST'])
def stop_api_monitoring():
    global is_api_monitoring_active
    is_api_monitoring_active = False
    stop_dataset_event_stream()
    socketio.emit('api_monitoring_status', {
        'is_monitoring': False,
        'total_requests': len(api_requests_log),
        'total_anomalies': api_anomaly_count,
        'class_counts': {label: int(api_class_counts.get(label, 0)) for label in API_ALLOWED_CLASSES},
    })
    return jsonify({'status': 'success', 'message': 'API behavior monitoring stopped'})


@app.route('/api/get_api_stats')
def get_api_stats():
    with api_state_lock:
        avg = 0.0
        if api_requests_log:
            avg = sum(float(item.get('accuracy_percent', 0.0)) for item in api_requests_log) / len(api_requests_log)
        return jsonify({
            'status': 'success',
            'is_monitoring': is_api_monitoring_active,
            'total_requests': len(api_requests_log),
            'total_anomalies': api_anomaly_count,
            'class_counts': {label: int(api_class_counts.get(label, 0)) for label in API_ALLOWED_CLASSES},
            'average_accuracy_percent': round(avg, 2),
            'recent_events': api_requests_log[-50:],
            'model_artifacts': strict_api_artifacts_payload(),
        })


@app.route('/api/generate_api_report', methods=['POST'])
def generate_api_report():
    with api_state_lock:
        class_counts = {label: int(api_class_counts.get(label, 0)) for label in API_ALLOWED_CLASSES}
        top_paths = Counter(item.get('path', '/') for item in api_requests_log).most_common(10)
        total = len(api_requests_log)
        anomaly_rate = (api_anomaly_count / total * 100.0) if total else 0.0
        report = {
            'generated_at': datetime.now().isoformat(),
            'monitoring_status': 'Running' if is_api_monitoring_active else 'Stopped',
            'total_requests': total,
            'total_anomalies': api_anomaly_count,
            'anomaly_rate': round(anomaly_rate, 2),
            'class_counts': class_counts,
            'top_paths': [{'path': path, 'count': count} for path, count in top_paths],
            'recent_events': api_requests_log[-10:],
        }
    return jsonify({'status': 'success', 'report': report})


@app.route('/api/test_api_call', methods=['POST'])
def test_api_call():
    data = request.get_json(silent=True) or {}
    return jsonify({
        'status': 'success',
        'models_loaded': strict_api_artifacts_ready()[0],
        'result': predict_api_call(data),
    })


@app.route('/api/generate_test_api_event', methods=['POST'])
def generate_test_api_event():
    global is_api_monitoring_active
    payload = request.get_json(silent=True) or {}
    requested_profile = str(payload.get('profile') or '').strip().lower()
    auto_start = bool(payload.get('auto_start', True))
    auto_stream = bool(payload.get('auto_stream', True))
    refresh_dataset = bool(payload.get('refresh_dataset', False))
    interval = min(10.0, max(0.2, safe_float(payload.get('stream_interval_seconds'), 1.0)))

    if auto_start:
        is_api_monitoring_active = True

    df = get_api_test_dataset(force_refresh=refresh_dataset)
    if requested_profile in API_ALLOWED_CLASSES:
        df = df[df['behavior_type'].astype(str).str.lower().eq(requested_profile)]
    if df.empty:
        return jsonify({'status': 'error', 'message': 'No dataset rows available for the requested profile'}), 400

    if auto_stream:
        started = start_dataset_event_stream(interval)
        return jsonify({
            'status': 'success',
            'models_loaded': strict_api_artifacts_ready()[0],
            'is_monitoring': is_api_monitoring_active,
            'dataset_file': API_TEST_EXTRACTED_DATASET_PATH,
            'streaming': True,
            'stream_started': started,
            'message': 'Dataset API event streaming started' if started else 'Dataset API event streaming is already running',
            'stream_interval_seconds': interval,
            'generated_count': 0,
            'matched_count': 0,
            'events': [],
        })

    count = max(1, min(10, safe_int(payload.get('count'), 1)))
    sample = df.sample(n=count, replace=len(df) < count, random_state=int(time.time()) % 65535)
    events = []
    matched = 0
    for _, row in sample.iterrows():
        event_data = dataset_row_to_api_event(row)
        result = process_api_request_data(event_data, source='test_generator') if is_api_monitoring_active else predict_api_call(event_data)
        expected = normalize_api_prediction(row.get('behavior_type'))
        did_match = result.get('prediction') == expected
        matched += int(did_match)
        events.append({
            'expected_profile': expected,
            'predicted_class': result.get('prediction'),
            'raw_prediction': result.get('raw_prediction'),
            'accuracy_percent': result.get('accuracy_percent'),
            'prediction_method': result.get('prediction_method'),
            'used_trained_model': bool(result.get('used_trained_model')),
            'matched_requested_profile': did_match,
            'attempts_used': 1,
            'method': event_data.get('method'),
            'path': event_data.get('path'),
            'src_ip': event_data.get('src_ip'),
            'feature_snapshot': {col: event_data.get(col) for col in CSV_COLUMNS},
        })

    return jsonify({
        'status': 'success',
        'models_loaded': strict_api_artifacts_ready()[0],
        'is_monitoring': is_api_monitoring_active,
        'requested_profile': requested_profile or 'all',
        'dataset_file': API_TEST_EXTRACTED_DATASET_PATH,
        'generated_count': len(events),
        'matched_count': matched,
        'events': events,
    })


@app.route('/api/predict_behavior', methods=['POST'])
def predict_behavior():
    data = request.get_json(silent=True) or {}
    result = predict_api_call(data)
    return jsonify({
        'status': 'success',
        'method': result.get('prediction_method'),
        'predicted_behavior': result.get('raw_prediction'),
        'normalized_class': result.get('prediction'),
        'confidence': result.get('confidence'),
        'accuracy_percent': result.get('accuracy_percent'),
    })


@app.route('/api/upload_csv_predictions', methods=['POST'])
def upload_csv_predictions():
    global is_api_monitoring_active
    if 'file' not in request.files:
        return jsonify({'status': 'error', 'message': 'No file provided'}), 400

    upload = request.files['file']
    if not upload.filename:
        return jsonify({'status': 'error', 'message': 'No file selected'}), 400
    if not upload.filename.lower().endswith('.csv'):
        return jsonify({'status': 'error', 'message': 'Only CSV files are allowed'}), 400

    stream = StringIO(upload.stream.read().decode('utf-8-sig', errors='replace'))
    df = pd.read_csv(stream)
    if df.empty:
        return jsonify({'status': 'error', 'message': 'CSV file is empty'}), 400

    is_api_monitoring_active = True
    predictions = []
    errors = []
    for idx, row in df.iterrows():
        try:
            data = row.to_dict()
            result = process_api_request_data(data, source='csv_upload', require_trained_model=False) or predict_api_call(data)
            key_features = {col: data.get(col, 'N/A') for col in CSV_COLUMNS[:7]}
            record = {
                'index': idx + 1,
                'record_id': f'Record {idx + 1}',
                'prediction': result.get('prediction'),
                'accuracy': round(float(result.get('accuracy_percent', 0.0)), 2),
                'timestamp': datetime.now().isoformat(),
                'input_data': data,
                'key_features': key_features,
            }
            predictions.append(record)
            socketio.emit('api_investigation_prediction', {
                'record_index': idx,
                'record_id': record['record_id'],
                'prediction': record['prediction'],
                'predicted_class': record['prediction'],
                'accuracy': record['accuracy'],
                'timestamp': record['timestamp'],
                'total_processed': len(predictions),
                'total_records': len(df),
                'class_counts': {label: int(api_class_counts.get(label, 0)) for label in API_ALLOWED_CLASSES},
                'key_features': key_features,
            })
        except Exception as exc:
            errors.append({'row': idx + 1, 'error': str(exc)})

    detailed = [{
        'record_id': item['record_id'],
        'behavior_type': item['prediction'],
        'accuracy': item['accuracy'],
        'key_features': item['key_features'],
        'timestamp': item['timestamp'],
    } for item in predictions]

    summary = {
        'total_records': len(df),
        'successfully_processed': len(predictions),
        'errors': len(errors),
        'predictions': predictions,
        'detailed_predictions': detailed,
        'error_details': errors or None,
        'class_distribution': {label: int(api_class_counts.get(label, 0)) for label in API_ALLOWED_CLASSES},
    }
    return jsonify({'status': 'success', 'message': f'Successfully processed {len(predictions)} records', 'summary': summary})


@app.route('/api/download_csv_template')
def download_csv_template():
    df = get_api_test_dataset().head(1000)
    output = StringIO()
    writer = csv.writer(output, lineterminator='\n')
    writer.writerow(CSV_COLUMNS)
    for _, row in df.iterrows():
        writer.writerow([row.get(col, '') for col in CSV_COLUMNS])
    return Response(
        output.getvalue(),
        mimetype='text/csv',
        headers={'Content-Disposition': 'attachment; filename="api_behavior_records_template.csv"'},
    )


@socketio.on('connect')
def handle_connect():
    socketio.emit('api_monitoring_status', {
        'is_monitoring': is_api_monitoring_active,
        'total_requests': len(api_requests_log),
        'total_anomalies': api_anomaly_count,
        'class_counts': {label: int(api_class_counts.get(label, 0)) for label in API_ALLOWED_CLASSES},
    })


@socketio.on('api_request')
def handle_api_request_event(data):
    try:
        process_api_request_data(data or {}, source='socket')
    except Exception as exc:
        print(f"[api] socket request failed: {exc}", flush=True)


load_api_artifacts()


if __name__ == '__main__':
    host = os.getenv('HOST', '0.0.0.0')
    port = int(os.getenv('PORT', '5005'))
    debug = os.getenv('DEBUG', 'false').strip().lower() in ('1', 'true', 'yes', 'on')
    socketio.run(app, host=host, port=port, debug=debug, allow_unsafe_werkzeug=True, use_reloader=False)
