const counts = { Allowed: 0, Restricted: 0, Suspicious: 0 };

function updateStats(recent) {
  const c = { Allowed: 0, Restricted: 0, Suspicious: 0 };
  recent.forEach(r => { if (c[r.policy] !== undefined) c[r.policy]++; });
  document.getElementById('cnt-allowed').textContent    = c.Allowed;
  document.getElementById('cnt-restricted').textContent = c.Restricted;
  document.getElementById('cnt-suspicious').textContent = c.Suspicious;
  document.getElementById('cnt-total').textContent      = recent.length;
  document.getElementById('footerCount').textContent    = `${recent.length} flows captured this session`;
}

function renderLast(entry) {
  if (!entry) return;
  const lc = document.getElementById('lastCapture');
  lc.classList.add('visible');
  document.getElementById('lcDomain').textContent = entry.domain;
  const badge = document.getElementById('lcBadge');
  badge.textContent  = entry.policy;
  badge.className    = `badge badge-${entry.policy}`;
  document.getElementById('lcConf').textContent = `${(entry.confidence * 100).toFixed(0)}% confidence`;
  document.getElementById('lcTime').textContent = entry.timestamp;
  const alertEl = document.getElementById('lcAlert');
  if (entry.alert) {
    alertEl.textContent = '⚠ ' + (entry.alert_reason || 'Alert triggered');
    alertEl.classList.add('visible');
  } else {
    alertEl.classList.remove('visible');
  }
}

function renderFlows(recent) {
  const list = document.getElementById('flowList');
  if (!recent || recent.length === 0) {
    list.innerHTML = '<div class="empty-state"><div class="empty-icon">📡</div><div class="empty-text">Browse any website to start capturing</div></div>';
    return;
  }
  list.innerHTML = recent.slice(0, 50).map(r => `
    <div class="flow-item">
      <div class="risk-dot" style="background:${r.risk_color}"></div>
      <div class="flow-domain" title="${r.domain}">${r.domain}</div>
      <span class="badge badge-${r.policy}">${r.policy}</span>
      <div class="flow-conf">${(r.confidence * 100).toFixed(0)}%</div>
      <div class="flow-time">${r.timestamp}</div>
    </div>`).join('');
}

function checkAPI() {
  fetch('http://localhost:5002/health', { signal: AbortSignal.timeout(2000) })
    .then(r => r.json())
    .then(d => {
      const el = document.getElementById('apiStatus');
      el.textContent = d.model_loaded ? 'ML Active' : 'API OK';
      el.className   = 'api-status api-ok';
    })
    .catch(() => {
      const el = document.getElementById('apiStatus');
      el.textContent = 'API Down';
      el.className   = 'api-status api-err';
    });
}

function loadState() {
  chrome.runtime.sendMessage({ type: 'GET_STATE' }, (res) => {
    if (!res) return;
    const monitoring = res.monitoring !== false;
    document.getElementById('monitorToggle').checked  = monitoring;
    document.getElementById('toggleLabel').textContent = monitoring ? 'ON' : 'OFF';
    const dot  = document.getElementById('statusDot');
    const text = document.getElementById('statusText');
    dot.className  = monitoring ? 'dot dot-green' : 'dot dot-gray';
    text.textContent = monitoring ? 'Monitoring active — capturing traffic' : 'Monitoring paused';

    updateStats(res.recent || []);
    renderLast(res.lastResult);
    renderFlows(res.recent || []);
  });
}

// Toggle monitoring on/off
document.getElementById('monitorToggle').addEventListener('change', (e) => {
  const val = e.target.checked;
  document.getElementById('toggleLabel').textContent = val ? 'ON' : 'OFF';
  const dot  = document.getElementById('statusDot');
  const text = document.getElementById('statusText');
  dot.className    = val ? 'dot dot-green' : 'dot dot-gray';
  text.textContent = val ? 'Monitoring active — capturing traffic' : 'Monitoring paused';
  chrome.runtime.sendMessage({ type: 'SET_MONITORING', value: val });
});

// Clear history
document.getElementById('clearBtn').addEventListener('click', () => {
  chrome.runtime.sendMessage({ type: 'CLEAR' }, () => loadState());
});

// Open dashboard
document.getElementById('openDash').addEventListener('click', (e) => {
  e.preventDefault();
  chrome.tabs.create({ url: 'http://localhost:5002' });
});

// Init
checkAPI();
loadState();
// Auto-refresh popup while open
setInterval(loadState, 2000);
