# AN ML-ENABLED ARCHITECTURE FOR USER WEB ACCESSING BEHAVIORS

Real-time encrypted web traffic behavior monitoring and policy-aware threat detection system. Classifies HTTPS flows into Allowed / Restricted / Suspicious using XGBoost on side-channel features — without decrypting payloads.

## Port Map

| Port | Service |
|------|---------|
| 5000 | Main dashboard (separate component) |
| 5001 | Other component |
| 5002 | THIS component frontend |
| 5003 | Other component |
| 8002 | THIS component FastAPI backend |
| 8080 | mitmproxy traffic interceptor |

## Setup

1. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

2. Train model — open `restricted/web-access-anolamy-detection.ipynb` → Run All Cells

3. Start backend:
   ```bash
   bash run.sh
   ```

4. Start proxy:
   ```bash
   cd proxy && bash start_proxy.sh
   ```

5. Configure browser proxy: `127.0.0.1` port `8080`

6. Install CA certificate: visit `http://mitm.it` in browser → install certificate

7. Open frontend: `templates/web_accessing.html` in browser

8. Browse any website — see live classifications in the dashboard

## API Docs

Swagger UI: http://localhost:8002/docs

## How Real Traffic Capture Works

mitmproxy intercepts HTTPS at the TLS layer and extracts metadata only:
- Domain name (from TLS SNI)
- Timing and packet statistics
- TLS version and JA3 fingerprint
- Byte counts and entropy

No payload content is read or stored. Features are sent to the XGBoost model for classification, matching research paper methodology exactly.
