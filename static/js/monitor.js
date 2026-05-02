let pollInterval = null;
let targetUrl    = null;

// ── Init ─────────────────────────────────────────────────────
window.initMonitor = () => {
  const btn = document.getElementById('btn-start');
  if (!btn) return; // Not on the monitor page

  const urlParams = new URLSearchParams(window.location.search);
  targetUrl = urlParams.get('target');
  if (targetUrl) {
    document.getElementById('monitor-target-info').innerHTML =
      `Tracking traffic triggered by: <strong style="color:var(--accent-amber);">${targetUrl}</strong><br>
       <span style="color:var(--text-muted);font-size:0.78rem;">We will open this URL automatically when you click Start.</span>`;
  }
};
window.onload = window.initMonitor;

// ── Start ─────────────────────────────────────────────────────
async function startMonitor() {
  if (targetUrl) {
    let u = targetUrl;
    if (!u.startsWith('http')) u = 'https://' + u;
    window.open(u, '_blank');
  }

  const btn = document.getElementById('btn-start');
  btn.disabled = true;
  btn.innerHTML = '<span class="ts-spinner me-2"></span>Starting...';

  const res = await fetch('/monitor/start', { method: 'POST' });
  if (res.ok) {
    document.getElementById('btn-stop').disabled  = false;
    document.getElementById('btn-start').innerHTML = '<i class="bi bi-play-fill"></i> Start Tracking';

    const liveDot = document.getElementById('live-dot');
    if (liveDot) liveDot.style.display = 'inline-block';

    setStatusBadge('Tracking Active', 'success');
    showToast('Deep tracking started. Monitoring all network packets.', 'success');

    pollInterval = setInterval(fetchStatus, 3000);
    fetchStatus();
  } else {
    btn.disabled = false;
    btn.innerHTML = '<i class="bi bi-play-fill"></i> Start Tracking';
    showToast('Failed to start monitoring. Is the server running as Administrator?', 'danger');
  }
}

// ── Stop ──────────────────────────────────────────────────────
async function stopMonitor() {
  clearInterval(pollInterval);
  const stopBtn = document.getElementById('btn-stop');
  stopBtn.disabled = true;
  stopBtn.innerHTML = '<span class="ts-spinner me-2"></span>Stopping...';

  const res  = await fetch('/monitor/stop', { method: 'POST' });
  const data = await res.json();

  document.getElementById('btn-start').disabled = false;
  stopBtn.innerHTML = '<i class="bi bi-stop-fill"></i> Stop Tracking';

  const liveDot = document.getElementById('live-dot');
  if (liveDot) liveDot.style.display = 'none';

  setStatusBadge('Stopped', 'secondary');

  if (data.anomaly) {
    showAlert('Threat detected during session — logged to blockchain for forensic analysis.');
    showToast('Anomaly detected and logged to blockchain!', 'danger');
  } else {
    showToast('Session ended. No threats detected.', 'info');
  }
}

// ── Fetch Status ──────────────────────────────────────────────
async function fetchStatus() {
  try {
    const res  = await fetch('/monitor/status');
    const data = await res.json();
    updateStats(data);
    updateVerdict(data);
    updateConnectionsTable(data.active_connections || []);
    if (data.alert_triggered) showAlert(data.alert_reason || 'Threat detected.');
  } catch (e) {
    console.error('Status fetch failed:', e);
  }
}

// ── Update Stats ──────────────────────────────────────────────
function animateCount(id, target) {
  const el = document.getElementById(id);
  const current = parseInt(el.textContent.replace(/,/g, '')) || 0;
  const diff = target - current;
  if (diff === 0) return;
  const step = Math.ceil(Math.abs(diff) / 15);
  let v = current;
  const iv = setInterval(() => {
    v = diff > 0 ? Math.min(v + step, target) : Math.max(v - step, target);
    el.textContent = v.toLocaleString();
    if (v === target) clearInterval(iv);
  }, 30);
}

function updateStats(data) {
  animateCount('stat-packets', data.total_packets   || 0);
  animateCount('stat-syns',    data.tcp_syn_count   || 0);
  animateCount('stat-bytes',   data.avg_packet_size || 0);
  animateCount('stat-ips',     data.unique_dst_ips  || 0);
}

// ── Update Verdict ────────────────────────────────────────────
function updateVerdict(data) {
  const badge  = document.getElementById('verdict-badge');
  const detail = document.getElementById('verdict-detail');
  const flags  = document.getElementById('flags-list');

  if (data.is_anomaly) {
    badge.textContent = data.verdict || 'THREAT DETECTED';
    badge.className   = 'badge bg-danger fs-6 px-3 py-2';
    detail.textContent= `Anomaly Score: ${data.anomaly_score}`;
    detail.style.color= 'var(--accent-red)';
  } else if (data.total_packets > 0) {
    badge.textContent = data.verdict || 'NORMAL';
    badge.className   = 'badge bg-success fs-6 px-3 py-2';
    detail.textContent= 'Background traffic behavior is within normal range';
    detail.style.color= 'var(--text-secondary)';
  } else {
    badge.textContent = 'Waiting...';
    badge.className   = 'badge bg-secondary fs-6 px-3 py-2';
    detail.textContent= '';
  }

  if (data.flags && data.flags.length > 0) {
    flags.innerHTML = data.flags.map(f =>
      `<div class="alert alert-danger py-2 mb-2" style="font-size:0.875rem;">
         <i class="bi bi-shield-fill-exclamation me-2"></i>${f}
       </div>`
    ).join('');
  } else {
    flags.innerHTML = '';
  }
}

// ── Update Connections Table ───────────────────────────────────
function updateConnectionsTable(connections) {
  const tbody = document.getElementById('ip-table-body');
  if (!connections.length) {
    tbody.innerHTML =
      `<tr><td colspan="4" class="text-center py-5" style="color:var(--text-muted);">
        <i class="bi bi-wifi-off d-block fs-2 mb-2"></i>No active connections yet.
       </td></tr>`;
    return;
  }

  tbody.innerHTML = connections.map((conn, i) => {
    const kb = (conn.bytes / 1024).toFixed(1);
    const hostColor = conn.hostname === 'Unknown Server' ? 'var(--accent-amber)'
                    : conn.hostname === 'Resolving...'   ? 'var(--text-muted)'
                    : 'var(--accent-cyan)';
    const ports    = conn.ports.length > 0 ? conn.ports.join(', ') : '—';
    const portLabel= conn.port_count > 5 ? `${ports} <span style="color:var(--text-muted);">(+${conn.port_count - 5} more)</span>` : ports;

    return `<tr style="animation:fadeSlideUp 0.35s ease both;animation-delay:${i * 0.03}s;">
      <td class="ps-3">
        <strong style="color:${hostColor};font-size:0.875rem;">${conn.hostname}</strong>
      </td>
      <td><code style="font-size:0.8rem;">${conn.ip}</code></td>
      <td><span class="badge bg-secondary" style="font-size:0.72rem;">${portLabel}</span></td>
      <td style="font-size:0.85rem;">
        ${kb} <span style="color:var(--text-muted);">KB</span>
        <span style="color:var(--text-muted);font-size:0.78rem;">(${conn.packets} pkts)</span>
      </td>
    </tr>`;
  }).join('');
}

// ── Helpers ───────────────────────────────────────────────────
function setStatusBadge(text, color) {
  const badge = document.getElementById('status-badge');
  badge.textContent = text;
  badge.className   = `badge bg-${color} fs-6 px-3 py-2`;
}

function showAlert(reason) {
  const banner = document.getElementById('alert-banner');
  document.getElementById('alert-reason').textContent = reason;
  banner.classList.remove('d-none');
}