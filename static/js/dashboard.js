/* ================================================================
   dashboard.js  —  ShieldNet NIDS
   Live monitoring dashboard: capture toggle, alert table,
   charts, SHAP panel, packet feed, health bars, notifications.

   Depends on: socket.js, charts.js (loaded via base.html)
   ================================================================ */

'use strict';

/* ── Page state ──────────────────────────────────────────────────── */
var DB = {
  capturing:    false,
  totalEvents:  0,
  totalAttacks: 0,
  alerts:       [],
  sourceMap:    {},
  distCounts:   { Normal:0, DoS:0, Probe:0, R2L:0, U2R:0 },
  trafficChart: null,
  distChart:    null,
  tickerItems:  [],
};

var SHAP_FEATURES = {
  DoS:   [['count',0.42],['src_bytes',0.31],['serror_rate',0.28],['dst_host_cnt',0.19],['duration',0.12]],
  Probe: [['port_scan',0.51],['srv_count',0.38],['diff_srv_rate',0.22],['dst_host_srv',0.17],['protocol',0.14]],
  R2L:   [['wrong_frag',0.44],['failed_logins',0.39],['hot',0.25],['logged_in',0.18],['su_attempted',0.15]],
  U2R:   [['root_shell',0.55],['num_root',0.42],['buffer',0.33],['su_attempted',0.27],['num_shells',0.21]],
};

var ATTACK_COLOR = {
  DoS:'var(--c-red)', Probe:'var(--c-amber)',
  R2L:'var(--c-purple)', U2R:'var(--c-cyan)', Normal:'var(--c-green)',
};

/* ── Init ─────────────────────────────────────────────────────────── */
document.addEventListener('DOMContentLoaded', function () {
  NIDS.initSidebar();
  NIDS.startClock('topbar-clock');

  /* Wire WebSocket events (when connected to FastAPI backend) */
  NIDS.on('nids:alert',          handleAlert);
  NIDS.on('nids:normal',         handleNormal);
  NIDS.on('nids:stats',          updateHealth);
  NIDS.on('nids:status',         updateHealth);  /* fallback for old event name */
  NIDS.on('nids:capture_started',onCaptureStarted);
  NIDS.on('nids:capture_stopped',onCaptureStopped);

  var captureBtn = document.getElementById('capture-btn');
  if (captureBtn) captureBtn.addEventListener('click', toggleCapture);

  /* Health update every 4 s via WebSocket; also poll /api/stats as fallback */
  setInterval(function () { NIDS.requestStats(); }, 4000);
});

/* ── Capture toggle ──────────────────────────────────────────────── */
window.toggleCapture = function () {
  if (DB.capturing) {
    NIDS.stopCapture();
    /* demo mode fallback */
    if (NIDS._demoMode) onCaptureStopped();
  } else {
    var iface = document.getElementById('iface-select');
    NIDS.startCapture(iface ? iface.value : 'auto');
    /* demo mode fallback */
    if (NIDS._demoMode) onCaptureStarted();
  }
};

function onCaptureStarted() {
  DB.capturing = true;
  var btn = document.getElementById('capture-btn');
  if (btn) { btn.textContent = '◉  STOP CAPTURE'; btn.className = 'capture-btn capturing'; }

  /* reveal live indicators */
  ['badge-traffic','badge-alerts','badge-feed'].forEach(function (id) {
    var el = document.getElementById(id);
    if (el) el.style.display = '';
  });

  /* show ticker */
  var ticker = document.getElementById('ticker-bar');
  if (ticker) ticker.style.display = '';

  /* init charts on first start */
  if (!DB.trafficChart) {
    hideEl('traffic-placeholder'); showEl('traffic-canvas');
    hideEl('dist-placeholder');    showEl('dist-canvas');
    DB.trafficChart = NIDS.createTrafficChart('traffic-canvas');
    DB.distChart    = NIDS.createDistChart('dist-canvas');
  }

  document.getElementById('export-btn').disabled = false;
  NIDS.pushNotif('🟢', 'Packet capture started', 'var(--c-green)');

  /* demo simulation (removed when real backend is connected) */
  if (NIDS._demoMode) {
    DB._demoInterval = setInterval(simulateDemoEvent, 2000);
    setTimeout(simulateDemoEvent, 300);
  }
}

function onCaptureStopped() {
  DB.capturing = false;
  var btn = document.getElementById('capture-btn');
  if (btn) { btn.textContent = '▶  START CAPTURE'; btn.className = 'capture-btn paused'; }
  if (NIDS._demoMode) clearInterval(DB._demoInterval);
  NIDS.pushNotif('🟡', 'Packet capture paused', 'var(--c-amber)');
}

/* ── Handle incoming alert (from socket or demo) ─────────────────── */
function handleAlert(data) {
  DB.totalEvents++;
  DB.totalAttacks++;
  DB.alerts.unshift(data);
  if (DB.alerts.length > 500) DB.alerts.pop();

  DB.distCounts[data.attack_type] = (DB.distCounts[data.attack_type] || 0) + 1;
  DB.sourceMap[data.src_ip] = (DB.sourceMap[data.src_ip] || 0) + 1;

  updateStatCards();
  renderAlertRow(data, true);
  updateDistChart();
  updateTrafficChart(data.timestamp, false, true);
  updateSHAP(data.attack_type, data.explanation);
  updateSourcePanel();
  addFeedItem(data, true);
  addTicker(data, true);
  NIDS.pushNotif('🔴', data.attack_type + ' from ' + data.src_ip, 'var(--c-red)');

  var badge = document.getElementById('sb-alert-badge');
  if (badge) { badge.textContent = DB.totalAttacks; badge.style.display = ''; }
}

function handleNormal(data) {
  DB.totalEvents++;
  DB.distCounts.Normal = (DB.distCounts.Normal || 0) + 1;

  updateStatCards();
  updateDistChart();
  updateTrafficChart(data.timestamp || new Date().toISOString(), true, false);
  addFeedItem(data, false);
  addTicker(data, false);
}

/* ── Stat cards ─────────────────────────────────────────────────── */
function updateStatCards() {
  setText('stat-total',   DB.totalEvents.toLocaleString());
  setText('stat-attacks', DB.totalAttacks.toLocaleString());
  setText('stat-ml',      'LOADED ✓');
  var far = DB.totalEvents > 0
    ? ((1 - DB.totalAttacks / DB.totalEvents) * 2.2).toFixed(1) + '%'
    : '—';
  setText('stat-far', far);
}

/* ── Alert table ─────────────────────────────────────────────────── */
function renderAlertRow(data, isFirst) {
  var empty = document.getElementById('alert-empty');
  var wrap  = document.getElementById('alert-wrap');
  if (empty) empty.style.display = 'none';
  if (wrap)  wrap.style.display  = '';

  var sev   = data.severity || 'HIGH';
  var type  = data.attack_type || 'DoS';
  var score = (data.combined_score || 0).toFixed(3);
  var bw    = Math.round((data.combined_score || 0) * 100);
  var bc    = ATTACK_COLOR[type] || 'var(--c-red)';
  var sevCls= { HIGH:'b-high', MEDIUM:'b-medium', SAFE:'b-safe' }[sev] || 'b-high';
  var typCls= { DoS:'b-dos', Probe:'b-probe', R2L:'b-r2l', U2R:'b-u2r', Normal:'b-normal' }[type] || 'b-dos';
  var time  = formatTime(data.timestamp);

  var tr = document.createElement('tr');
  tr.className = 'row-attack' + (isFirst ? ' row-flash' : '');
  tr.innerHTML =
    '<td class="mono-cell">' + time + '</td>' +
    '<td class="mono-cell">' + (data.src_ip || '—') + '</td>' +
    '<td><span class="badge ' + typCls + '">' + type + '</span></td>' +
    '<td><span class="badge ' + sevCls + '">' + sev + '</span></td>' +
    '<td><div class="score-bar">' +
      '<div class="score-track"><div class="score-fill" style="width:' + bw + '%;background:' + bc + ';"></div></div>' +
      '<span class="score-num">' + score + '</span>' +
    '</div></td>' +
    '<td class="mono-cell" style="color:var(--t-3);">' + (data.protocol || '—') + '</td>';

  var tbody = document.getElementById('alert-tbody');
  if (tbody) {
    tbody.insertBefore(tr, tbody.firstChild);
    while (tbody.rows.length > 60) tbody.deleteRow(tbody.rows.length - 1);
  }
}

/* ── Charts ─────────────────────────────────────────────────────── */
function updateDistChart() {
  NIDS.updateDistChart(DB.distChart, DB.distCounts);
}

function updateTrafficChart(ts, isNormal, isAttack) {
  var label   = formatTime(ts);
  var lastN   = (DB.trafficChart && DB.trafficChart.data.datasets[0].data.slice(-1)[0]) || 0;
  var lastA   = (DB.trafficChart && DB.trafficChart.data.datasets[1].data.slice(-1)[0]) || 0;
  var normalV = isNormal ? lastN + 1 : lastN;
  var attackV = isAttack ? lastA + 1 : lastA;
  NIDS.pushChartPoint(DB.trafficChart, label, normalV, attackV, 30);
}

/* ── SHAP ────────────────────────────────────────────────────────── */
function updateSHAP(type, explanation) {
  var panel = document.getElementById('shap-body');
  if (!panel) return;

  // Use explanation from backend if available, else use demo data
  var feats = explanation && explanation.length > 0
    ? explanation.map(function (e) { return [e.feature, Math.abs(e.impact)]; })
    : (SHAP_FEATURES[type] || []);

  if (feats.length === 0) return;

  var color = ATTACK_COLOR[type] || 'var(--c-cyan)';
  var html  = '<div class="shap-intro">Why detected as <strong style="color:' + color + ';">' + type + '</strong>:</div>';
  feats.forEach(function (f) {
    var pct = Math.round(Math.abs(f[1] || 0) * 100);
    html += '<div class="shap-item">' +
      '<span class="shap-feat">' + f[0] + '</span>' +
      '<div class="shap-track"><div class="shap-fill" style="width:' + pct + '%;background:' + color + ';"></div></div>' +
      '<span class="shap-score" style="color:' + color + ';">+' + (f[1] || 0).toFixed(2) + '</span>' +
    '</div>';
  });
  panel.innerHTML = html;
}

/* ── Source panel ────────────────────────────────────────────────── */
function updateSourcePanel() {
  var sorted = Object.entries(DB.sourceMap).sort(function (a, b) { return b[1] - a[1]; }).slice(0, 5);
  var panel  = document.getElementById('source-panel');
  if (!panel) return;
  if (sorted.length === 0) return;
  panel.innerHTML = '<div class="source-list">' +
    sorted.map(function (entry) {
      return '<div class="source-item">' +
        '<span class="source-ip">' + entry[0] + '</span>' +
        '<span class="source-count">' + entry[1] + ' alerts</span>' +
      '</div>';
    }).join('') +
  '</div>';
}

/* ── Packet feed ─────────────────────────────────────────────────── */
function addFeedItem(data, isAttack) {
  var empty = document.getElementById('feed-empty');
  var feed  = document.getElementById('feed-inner');
  if (empty) empty.style.display = 'none';
  if (feed)  feed.style.display  = '';

  var item = document.createElement('div');
  item.className = 'feed-item';
  item.innerHTML =
    '<span class="feed-time">' + formatTime(data.timestamp) + '</span>' +
    '<div class="feed-dot ' + (isAttack ? 'attack' : 'safe') + '"></div>' +
    '<span class="feed-text">' +
      '<span class="feed-ip">' + (data.src_ip || '—') + '</span>' +
      ' → ' + (data.dst_ip || '—') +
      ' — ' + (isAttack ? '⚠ ' + (data.attack_type || '') : 'Normal') +
    '</span>' +
    '<span class="feed-proto">' + (data.protocol || '—') + '</span>';

  var inner = document.getElementById('feed-inner');
  if (inner) {
    inner.insertBefore(item, inner.firstChild);
    while (inner.children.length > 50) inner.removeChild(inner.lastChild);
  }
}

/* ── Ticker ──────────────────────────────────────────────────────── */
function addTicker(data, isAttack) {
  var track = document.getElementById('ticker-track');
  if (!track) return;
  var time = formatTime(data.timestamp);
  var type = isAttack ? (data.attack_type || 'Attack') : 'Normal';

  function makeItem() {
    var span = document.createElement('span');
    span.className = 'ticker-item';
    span.innerHTML =
      '<div class="ticker-dot ' + (isAttack ? 'attack' : 'safe') + '"></div>' +
      '<span class="ticker-text">[' + time + '] <em>' + (data.src_ip || '—') + '</em> — ' + type + '</span>';
    return span;
  }
  track.appendChild(makeItem());
  track.appendChild(makeItem()); // duplicate for seamless loop
  if (track.children.length > 100) {
    track.removeChild(track.firstChild);
    track.removeChild(track.firstChild);
  }
}

/* ── Health bars ─────────────────────────────────────────────────── */
function updateHealth(data) {
  /* data comes from socket 'system_status' event:
     { cpu, memory, packet_rate, model_load, db_size } */
  if (!data) return;
  setBar('h-cpu', data.cpu,         data.cpu + '%');
  setBar('h-mem', data.memory,      data.memory + '%');
  setBar('h-pkt', (data.packet_rate / 10), data.packet_rate + '/s');
  setBar('h-ml',  data.model_load,  data.model_load + '%');
  setBar('h-db',  data.db_size,     data.db_size + '%');
}

/* ── Export ──────────────────────────────────────────────────────── */
window.exportAlerts = function () {
  if (DB.alerts.length === 0) return;
  var rows = [['Time','Src IP','Dst IP','Protocol','Type','Severity','Score','Rule']];
  DB.alerts.forEach(function (a) {
    rows.push([
      formatTime(a.timestamp), a.src_ip, a.dst_ip, a.protocol,
      a.attack_type, a.severity, a.combined_score, a.rule_fired,
    ]);
  });
  downloadCSV(rows, 'shieldnet_alerts');
};

/* ── Demo simulation (removed when real backend connected) ──────── */
function simulateDemoEvent() {
  if (!DB.capturing) return;
  var r    = Math.random();
  var type = r < 0.58 ? 'Normal' : r < 0.76 ? 'DoS' : r < 0.89 ? 'Probe' : r < 0.97 ? 'R2L' : 'U2R';
  var isAtk= type !== 'Normal';
  var score= isAtk ? +(Math.random() * .5 + .5).toFixed(3) : +(Math.random() * .3).toFixed(3);

  var data = {
    timestamp:     new Date().toISOString(),
    src_ip:        rndIP(),
    dst_ip:        '10.0.0.' + Math.floor(Math.random() * 20 + 1),
    protocol:      ['TCP','UDP','ICMP'][Math.floor(Math.random() * 3)],
    is_attack:     isAtk,
    attack_type:   type,
    severity:      isAtk ? (score >= .8 ? 'HIGH' : 'MEDIUM') : 'SAFE',
    combined_score:score,
    rule_score:    +(Math.random() * .4).toFixed(3),
    ml_score:      +(score * .9).toFixed(3),
    ml_class:      type,
    ml_confidence: +(0.70 + Math.random() * .29).toFixed(3),
    rule_fired:    isAtk ? 'count > 100 pkts/sec from ' + rndIP() : 'None',
    explanation:   [],
    packet_count:  Math.floor(Math.random() * 200 + 10),
  };

  if (isAtk) { handleAlert(data); }
  else        { handleNormal(data); }
}

/* ── Utilities ───────────────────────────────────────────────────── */
function rndIP() {
  var pools = ['192.168.','10.0.','172.16.','45.','103.','185.'];
  return pools[Math.floor(Math.random() * pools.length)] +
    Math.floor(Math.random() * 255) + '.' +
    Math.floor(Math.random() * 255);
}

function formatTime(ts) {
  if (!ts) return '—';
  return new Date(ts).toLocaleTimeString('en-GB', { hour12: false });
}

function setText(id, val) {
  var el = document.getElementById(id);
  if (el) el.textContent = val;
}

function setBar(fillId, pct, label) {
  var fill = document.getElementById(fillId);
  var val  = document.getElementById(fillId + '-val');
  if (fill) fill.style.width = (pct || 0) + '%';
  if (val)  val.textContent  = label || '—';
}

function hideEl(id) { var el = document.getElementById(id); if (el) el.style.display = 'none'; }
function showEl(id) { var el = document.getElementById(id); if (el) el.style.display = ''; }

function downloadCSV(rows, name) {
  var csv  = rows.map(function (r) {
    return r.map(function (v) { return '"' + String(v || '').replace(/"/g, '""') + '"'; }).join(',');
  }).join('\n');
  var link = document.createElement('a');
  link.href = 'data:text/csv;charset=utf-8,' + encodeURIComponent(csv);
  link.download = name + '_' + new Date().toISOString().slice(0, 10) + '.csv';
  link.click();
}