let pollInterval = null;

async function startMonitor() {
  const res = await fetch('/monitor/start', { method: 'POST' });
  if (res.ok) {
    document.getElementById('btn-start').disabled = true;
    document.getElementById('btn-stop').disabled  = false;
    document.getElementById('status-badge').textContent  = 'Monitoring...';
    document.getElementById('status-badge').className   =
      'badge bg-success fs-6 px-3 py-2';
    pollInterval = setInterval(fetchStatus, 3000);
    fetchStatus();
  }
}

async function stopMonitor() {
  clearInterval(pollInterval);
  const res  = await fetch('/monitor/stop', { method: 'POST' });
  const data = await res.json();
  document.getElementById('btn-start').disabled = false;
  document.getElementById('btn-stop').disabled  = true;
  document.getElementById('status-badge').textContent = 'Stopped';
  document.getElementById('status-badge').className   =
    'badge bg-secondary fs-6 px-3 py-2';
  if (data.anomaly) {
    showAlert('Anomaly detected during session — logged to blockchain.');
  }
}

async function fetchStatus() {
  try {
    const res  = await fetch('/monitor/status');
    const data = await res.json();
    updateStats(data);
    updateVerdict(data);
    updateIpTable(data.top_ips || []);
    if (data.alert_triggered) {
      showAlert(data.alert_reason || 'Anomaly detected.');
    }
  } catch (e) {
    console.error('Status fetch failed:', e);
  }
}

function updateStats(data) {
  document.getElementById('stat-packets').textContent =
    data.total_packets || 0;
  document.getElementById('stat-ips').textContent     =
    data.unique_dst_ips || 0;
  document.getElementById('stat-bytes').textContent   =
    ((data.total_bytes || 0) / 1024).toFixed(1);
  document.getElementById('stat-duration').textContent =
    (data.duration_seconds || 0) + 's';
}

function updateVerdict(data) {
  const badge  = document.getElementById('verdict-badge');
  const detail = document.getElementById('verdict-detail');
  const flags  = document.getElementById('flags-list');

  if (data.is_anomaly) {
    badge.textContent  = 'ANOMALY DETECTED';
    badge.className    = 'badge bg-danger fs-6 px-3 py-2';
    detail.textContent = `Anomaly score: ${data.anomaly_score}`;
  } else {
    badge.textContent  = data.verdict || 'NORMAL';
    badge.className    = 'badge bg-success fs-6 px-3 py-2';
    detail.textContent = 'Traffic patterns look normal';
  }

  if (data.flags && data.flags.length > 0) {
    flags.innerHTML = data.flags.map(f =>
      `<div class="alert alert-danger py-2 mb-2">
         <i class="bi bi-exclamation-triangle-fill me-2"></i>${f}
       </div>`
    ).join('');
  } else {
    flags.innerHTML = '';
  }
}

function updateIpTable(topIps) {
  const tbody = document.getElementById('ip-table-body');
  if (!topIps.length) {
    tbody.innerHTML =
      '<tr><td colspan="2" class="text-center text-muted py-3">' +
      'No data yet</td></tr>';
    return;
  }
  tbody.innerHTML = topIps.map(([ip, count]) =>
    `<tr>
       <td class="ps-3"><code>${ip}</code></td>
       <td>${count}</td>
     </tr>`
  ).join('');
}

function showAlert(reason) {
  const banner = document.getElementById('alert-banner');
  document.getElementById('alert-reason').textContent = reason;
  banner.classList.remove('d-none');
}