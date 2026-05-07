/**
 * CyberTraffic AI — background service worker
 * Captures real browser HTTP/HTTPS request metadata via webRequest API
 * and posts feature vectors to localhost:5002/predict for XGBoost classification.
 *
 * No proxy, no CA cert needed — uses the browser's own webRequest hooks.
 */

const API_URL   = 'http://localhost:5002/predict';
const MAX_RECENT = 100;

// Domains to skip (internal, CDN, extension APIs)
const SKIP_HOSTS = [
  'localhost', '127.0.0.1', '0.0.0.0',
  'cdn.tailwindcss.com', 'cdn.jsdelivr.net',
  'clients2.google.com', 'update.googleapis.com',
  'clients.l.google.com', 'safebrowsing.googleapis.com',
  'connectivitycheck.gstatic.com', 'ocsp.pki.goog'
];

// Pending request timing: requestId → { startTime, url, failedAttempts, sentBytes }
const pending = {};
// Count error events per host for failed_connection_attempts feature
const hostErrors = {};
// Recent inter-arrival times per host
const lastRequestTime = {};

let monitoringEnabled = true;

// ── Helpers ───────────────────────────────────────────────────────────────────

function shouldSkip(url) {
  try {
    const u = new URL(url);
    return SKIP_HOSTS.some(h => u.hostname === h || u.hostname.endsWith('.' + h));
  } catch { return true; }
}

function getPort(url) {
  try {
    const u = new URL(url);
    if (u.port) return parseInt(u.port);
    return u.protocol === 'https:' ? 443 : 80;
  } catch { return 443; }
}

function getProtocol(url, type) {
  try {
    const u = new URL(url);
    const host = u.hostname;
    if (host.endsWith('.onion'))                         return 'Tor';
    if (getPort(url) === 853 || /dns\.|doh\./i.test(host)) return 'DoH';
    if (/vpn|nordvpn|expressvpn|tunnel/i.test(host))    return 'VPN';
    if (u.protocol === 'https:')                         return 'HTTPS';
    return 'TLS';
  } catch { return 'HTTPS'; }
}

function classifyDomain(hostname) {
  const h = hostname.toLowerCase();
  if (/\.onion$/.test(h))                                              return { tor: 1, vpn: 0, doh: 0 };
  if (/vpn|nordvpn|expressvpn|protonvpn|tunnel|wireguard/i.test(h))  return { tor: 0, vpn: 1, doh: 0 };
  if (/dns\.|doh\.|cloudflare-dns|dns\.google/i.test(h))              return { tor: 0, vpn: 0, doh: 1 };
  return { tor: 0, vpn: 0, doh: 0 };
}

function estimateEntropy(contentType, byteLen) {
  if (!contentType) return +(2.5 + Math.random()).toFixed(4);
  if (/video|audio|zip|octet/i.test(contentType)) return +(7.0 + Math.random() * 0.8).toFixed(4);
  if (/json|text|html/i.test(contentType))        return +(2.0 + Math.random() * 1.5).toFixed(4);
  return +(3.5 + Math.random() * 2).toFixed(4);
}

function estimatePacketCount(bytes) {
  const mtu = 1460;
  return Math.max(1, Math.ceil(bytes / mtu));
}

function jitter(base, pct = 0.15) {
  return +(base * (1 + (Math.random() * 2 - 1) * pct)).toFixed(2);
}

function getContentLength(headers) {
  if (!headers) return 0;
  const h = headers.find(h => h.name.toLowerCase() === 'content-length');
  return h ? parseInt(h.value) || 0 : 0;
}

function getContentType(headers) {
  if (!headers) return '';
  const h = headers.find(h => h.name.toLowerCase() === 'content-type');
  return h ? h.value : '';
}

// ── webRequest listeners ───────────────────────────────────────────────────────

chrome.webRequest.onBeforeRequest.addListener(
  (details) => {
    if (!monitoringEnabled) return;
    if (shouldSkip(details.url)) return;

    const host = new URL(details.url).hostname;
    const now  = details.timeStamp;

    // Estimate bytes sent from requestBody
    let sentBytes = 0;
    if (details.requestBody) {
      if (details.requestBody.raw) {
        sentBytes = details.requestBody.raw.reduce((s, r) => s + (r.bytes ? r.bytes.byteLength : 0), 0);
      } else if (details.requestBody.formData) {
        sentBytes = JSON.stringify(details.requestBody.formData).length;
      }
    }

    pending[details.requestId] = {
      url:       details.url,
      host,
      startTime: now,
      sentBytes: Math.max(sentBytes, 64), // min 64 bytes (headers)
    };
  },
  { urls: ['<all_urls>'] },
  ['requestBody']
);

chrome.webRequest.onErrorOccurred.addListener(
  (details) => {
    if (shouldSkip(details.url)) return;
    const host = new URL(details.url).hostname;
    hostErrors[host] = (hostErrors[host] || 0) + 1;
    delete pending[details.requestId];
  },
  { urls: ['<all_urls>'] }
);

chrome.webRequest.onCompleted.addListener(
  (details) => {
    if (!monitoringEnabled) return;
    const req = pending[details.requestId];
    if (!req) return;
    delete pending[details.requestId];
    if (shouldSkip(details.url)) return;

    const now         = details.timeStamp;
    const flowDur     = Math.max(now - req.startTime, 1);
    const host        = req.host;
    const protocol    = getProtocol(details.url, details.type);
    const port        = getPort(details.url);
    const { tor, vpn, doh } = classifyDomain(host);

    const contentType = getContentType(details.responseHeaders);
    const recvBytes   = Math.max(getContentLength(details.responseHeaders), 512);
    const sentBytes   = Math.max(req.sentBytes, 64);
    const pktCount    = estimatePacketCount(recvBytes + sentBytes);
    const avgPktSize  = jitter((recvBytes + sentBytes) / pktCount);
    const pktStd      = jitter(avgPktSize * 0.3);
    const entropy     = estimateEntropy(contentType, recvBytes);

    // Inter-arrival time (ms since last request to same host)
    const lastT  = lastRequestTime[host] || req.startTime;
    const iat    = Math.max(now - lastT, 10);
    lastRequestTime[host] = now;

    // Burstiness (ratio of std/mean of IAT — simplified single-value estimate)
    const burst  = +(Math.min(iat > 200 ? 0.05 : 0.35 + Math.random() * 0.2, 1.0)).toFixed(4);

    const ratio  = +(sentBytes / recvBytes).toFixed(4);
    const hour   = new Date().getHours();
    const dow    = new Date().getDay();
    const failed = hostErrors[host] || 0;

    const record = {
      source_ip:                  '127.0.0.1',
      destination_ip:             host,
      source_port:                Math.floor(Math.random() * 16383) + 49152,
      destination_port:           port,
      protocol,
      tls_version:                port === 443 ? 'TLS1.3' : 'TLS1.2',
      ja3_fingerprint:            `ja3_${(Math.abs(host.split('').reduce((a,c) => a + c.charCodeAt(0), 0)) % 20) + 1}`,
      flow_duration_ms:           +flowDur.toFixed(2),
      packet_count:               pktCount,
      avg_packet_size:            avgPktSize,
      packet_size_std:            pktStd,
      inter_arrival_time_ms:      +iat.toFixed(2),
      burstiness_score:           burst,
      bytes_sent:                 sentBytes,
      bytes_received:             recvBytes,
      upload_download_ratio:      ratio,
      dns_over_https:             doh,
      vpn_usage:                  vpn,
      tor_usage:                  tor,
      failed_connection_attempts: failed,
      packet_entropy:             entropy,
      session_start_hour:         hour,
      weekend_access:             (dow === 0 || dow === 6) ? 1 : 0,
      domain:                     host
    };

    // Fire-and-forget POST to the local ML API
    fetch(API_URL, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify(record)
    })
    .then(r => r.json())
    .then(result => {
      // Store latest result for popup display
      chrome.storage.session.get({ recent: [] }, (data) => {
        const entry = {
          domain:       host,
          policy:       result.policy_label || '?',
          risk:         result.risk_level    || '?',
          risk_color:   result.risk_color    || '#94a3b8',
          confidence:   result.confidence    || 0,
          alert:        result.alert_triggered || false,
          alert_reason: result.alert_reason  || null,
          timestamp:    new Date().toLocaleTimeString(),
          flow_id:      result.flow_id || ''
        };
        const recent = [entry, ...data.recent].slice(0, MAX_RECENT);
        chrome.storage.session.set({ recent, lastResult: entry });

        // Badge color based on policy
        const colors = { Allowed: '#22c55e', Restricted: '#f59e0b', Suspicious: '#ef4444' };
        chrome.action.setBadgeBackgroundColor({ color: colors[entry.policy] || '#94a3b8' });
        chrome.action.setBadgeText({ text: entry.policy === 'Suspicious' ? '!' : '' });
      });
    })
    .catch(() => {}); // API not running — silently skip
  },
  { urls: ['<all_urls>'] },
  ['responseHeaders']
);

// ── Message API (from popup) ──────────────────────────────────────────────────
chrome.runtime.onMessage.addListener((msg, sender, reply) => {
  if (msg.type === 'GET_STATE') {
    chrome.storage.session.get({ recent: [], lastResult: null }, (data) => {
      reply({ monitoring: monitoringEnabled, ...data });
    });
    return true;
  }
  if (msg.type === 'SET_MONITORING') {
    monitoringEnabled = msg.value;
    chrome.storage.session.set({ monitoringEnabled: msg.value });
    if (!msg.value) {
      chrome.action.setBadgeText({ text: '' });
    }
    reply({ ok: true });
    return true;
  }
  if (msg.type === 'CLEAR') {
    chrome.storage.session.set({ recent: [], lastResult: null });
    chrome.action.setBadgeText({ text: '' });
    reply({ ok: true });
    return true;
  }
});
