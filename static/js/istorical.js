/* ================================================================
   historical.js  —  ShieldNet NIDS
   Historical analysis page: fetches /api/analytics from Flask,
   builds charts, performance table, system events.

   Depends on: socket.js, charts.js (loaded via base.html)
   ================================================================ */

'use strict';

/* ── Init ─────────────────────────────────────────────────────────── */
document.addEventListener('DOMContentLoaded', function () {
  NIDS.initSidebar();
  NIDS.startClock('topbar-clock');
  loadAnalytics('24h');

  document.querySelectorAll('.period-tab').forEach(function (btn) {
    btn.addEventListener('click', function () {
      document.querySelectorAll('.period-tab').forEach(function (b) { b.classList.remove('active'); });
      this.classList.add('active');
      loadAnalytics(this.dataset.period || '24h');
    });
  });
});

/* ── Load data from backend ─────────────────────────────────────── */
function loadAnalytics(period) {
  /* Attempt real API call first */
  fetch('/api/analytics?period=' + period)
    .then(function (res) {
      if (!res.ok) throw new Error('API unavailable');
      return res.json();
    })
    .then(function (data) {
      renderAll(data);
    })
    .catch(function () {
      /* Backend not running yet — show empty/placeholder state */
      renderEmpty();
    });
}

/* ── Render all sections with real data ─────────────────────────── */
function renderAll(data) {
  hideEl('analytics-empty');
  showEl('analytics-content');

  /* Metric cards */
  setTxt('m-total',   (data.total_events   || 0).toLocaleString());
  setTxt('m-attacks', (data.total_attacks  || 0).toLocaleString());
  setTxt('m-accuracy',(data.accuracy       || '—') + (data.accuracy ? '%' : ''));
  setTxt('m-response',(data.avg_response   || '—'));

  /* Charts */
  buildTrendChart(data.hourly_counts);
  buildTypeChart(data.type_counts);
  buildROCChart(data.auc_score);
  buildSHAPChart(data.shap_features);
  buildPerfTable(data.class_metrics);
  buildEvents(data.system_events);
}

/* ── Render empty placeholder (no data yet) ─────────────────────── */
function renderEmpty() {
  showEl('analytics-empty');
  hideEl('analytics-content');
}

/* ── Charts ─────────────────────────────────────────────────────── */
var charts = {};

function buildTrendChart(hourly) {
  if (charts.trend) charts.trend.destroy();
  charts.trend = NIDS.createTrendChart('trend-chart', hourly);
}

function buildTypeChart(counts) {
  if (charts.type) charts.type.destroy();
  charts.type = NIDS.createTypeChart('type-chart', counts);
}

function buildROCChart(auc) {
  if (charts.roc) charts.roc.destroy();
  charts.roc = NIDS.createROCChart('roc-chart', auc);
}

function buildSHAPChart(shapData) {
  if (charts.shap) charts.shap.destroy();
  charts.shap = NIDS.createSHAPChart('shap-chart', shapData || {
    labels: ['count','src_bytes','serror_rate','same_srv_rate','dst_host_cnt',
             'duration','rerror_rate','srv_count','diff_srv_rate','logged_in'],
    values: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
  });
}

/* ── Performance table ───────────────────────────────────────────── */
function buildPerfTable(metrics) {
  var tbody = document.getElementById('perf-tbody');
  if (!tbody) return;

  if (!metrics || metrics.length === 0) {
    tbody.innerHTML = '<tr><td colspan="5" style="text-align:center;color:var(--t-4);padding:24px;font-size:.86rem;">Train the model first — run backend/ml/train_model.py</td></tr>';
    return;
  }

  var colors = { Normal:'var(--c-green)', DoS:'var(--c-red)', Probe:'var(--c-amber)', R2L:'var(--c-purple)', U2R:'var(--c-cyan)' };
  tbody.innerHTML = metrics.map(function (m) {
    var c = colors[m.label] || 'var(--t-1)';
    return '<tr>' +
      '<td style="font-weight:600;color:' + c + ';font-family:var(--f-mono);">' + m.label + '</td>' +
      '<td><div class="mini-wrap"><div class="mini-bar"><div class="mini-fill" style="width:' + parseFloat(m.precision) + '%;background:' + c + ';"></div></div>' + m.precision + '</div></td>' +
      '<td style="font-family:var(--f-mono);">' + m.recall  + '</td>' +
      '<td style="color:' + c + ';font-weight:600;font-family:var(--f-mono);">' + m.f1 + '</td>' +
      '<td style="color:var(--t-3);font-family:var(--f-mono);">' + (m.support || 0).toLocaleString() + '</td>' +
    '</tr>';
  }).join('') + '<tr style="border-top:1px solid var(--c-border);"><td style="font-weight:700;color:var(--t-1);font-family:var(--f-mono);">OVERALL</td>' +
    '<td style="color:var(--c-cyan);font-family:var(--f-mono);">—</td>' +
    '<td style="color:var(--c-cyan);font-family:var(--f-mono);">—</td>' +
    '<td style="color:var(--c-cyan);font-weight:700;font-family:var(--f-mono);" id="overall-f1">—</td>' +
    '<td style="color:var(--t-3);font-family:var(--f-mono);" id="overall-support">—</td></tr>';
}

/* ── System events list ───────────────────────────────────────────── */
function buildEvents(events) {
  var list = document.getElementById('events-list');
  if (!list) return;

  if (!events || events.length === 0) {
    list.innerHTML = '<div style="padding:20px 0;text-align:center;font-size:.84rem;color:var(--t-4);">No system events recorded yet.</div>';
    return;
  }

  list.innerHTML = events.map(function (e) {
    return '<div class="event-item">' +
      '<span class="event-icon">' + (e.icon || '📌') + '</span>' +
      '<span class="event-text">' + e.text + '</span>' +
      '<span class="event-time">' + e.time + '</span>' +
    '</div>';
  }).join('');
}

/* ── Utilities ───────────────────────────────────────────────────── */
function setTxt(id, val) { var el = document.getElementById(id); if (el) el.textContent = val || '—'; }
function hideEl(id) { var el = document.getElementById(id); if (el) el.style.display = 'none'; }
function showEl(id) { var el = document.getElementById(id); if (el) el.style.display = ''; }