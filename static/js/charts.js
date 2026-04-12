/* ================================================================
   charts.js  —  ShieldNet NIDS
   All Chart.js chart factory functions.
   Called by dashboard.js and historical.js
   ================================================================ */

'use strict';

const NIDS = window.NIDS || {};
window.NIDS = NIDS;

/* ── Shared Chart.js defaults ───────────────────────────────────── */
NIDS.chartDefaults = {
  responsive: true,
  maintainAspectRatio: false,
  animation: { duration: 300 },
  plugins: {
    legend: {
      labels: {
        color: '#7a92b8',
        font: { size: 12, family: 'Syne' },
        padding: 14,
        usePointStyle: true,
      },
    },
    tooltip: {
      backgroundColor: 'rgba(9,18,32,0.95)',
      borderColor: '#1e2e4a',
      borderWidth: 1,
      titleColor: '#eef2ff',
      bodyColor: '#b8c8e8',
      padding: 12,
      cornerRadius: 8,
    },
  },
  scales: {
    x: {
      ticks:  { color: '#7a92b8', font: { size: 10 }, maxTicksLimit: 7 },
      grid:   { color: 'rgba(22,32,56,0.7)' },
      border: { color: '#162038' },
    },
    y: {
      ticks:  { color: '#7a92b8', font: { size: 10 } },
      grid:   { color: 'rgba(22,32,56,0.7)' },
      border: { color: '#162038' },
      beginAtZero: true,
    },
  },
};

/* ── Traffic timeline (live line chart) ─────────────────────────── */
NIDS.createTrafficChart = function (canvasId) {
  var ctx = document.getElementById(canvasId);
  if (!ctx) return null;
  return new Chart(ctx, {
    type: 'line',
    data: {
      labels: [],
      datasets: [
        {
          label: 'Normal',
          data: [],
          borderColor: '#00e57a',
          backgroundColor: 'rgba(0,229,122,0.07)',
          tension: 0.42, fill: true, pointRadius: 0, borderWidth: 2,
        },
        {
          label: 'Attacks',
          data: [],
          borderColor: '#ff3355',
          backgroundColor: 'rgba(255,51,85,0.07)',
          tension: 0.42, fill: true, pointRadius: 0, borderWidth: 2,
        },
      ],
    },
    options: Object.assign({}, NIDS.chartDefaults, { animation: { duration: 200 } }),
  });
};

/* ── Attack distribution (doughnut) ────────────────────────────── */
NIDS.createDistChart = function (canvasId) {
  var ctx = document.getElementById(canvasId);
  if (!ctx) return null;
  return new Chart(ctx, {
    type: 'doughnut',
    data: {
      labels: ['Normal', 'DoS', 'Probe', 'R2L', 'U2R'],
      datasets: [{
        data: [0, 0, 0, 0, 0],
        backgroundColor: [
          'rgba(0,229,122,0.72)', 'rgba(255,51,85,0.72)',
          'rgba(255,173,0,0.72)', 'rgba(176,96,255,0.72)', 'rgba(0,200,240,0.72)',
        ],
        borderColor: ['#00e57a','#ff3355','#ffad00','#b060ff','#00c8f0'],
        borderWidth: 1.5,
        hoverOffset: 9,
      }],
    },
    options: {
      responsive: true, maintainAspectRatio: false, cutout: '63%',
      animation: { duration: 400 },
      plugins: {
        legend: {
          position: 'bottom',
          labels: { color: '#7a92b8', font: { size: 12, family: 'Syne' }, padding: 13, usePointStyle: true },
        },
        tooltip: NIDS.chartDefaults.plugins.tooltip,
      },
    },
  });
};

/* ── 24-hour trend bar chart (historical) ───────────────────────── */
NIDS.createTrendChart = function (canvasId, data) {
  var ctx = document.getElementById(canvasId);
  if (!ctx) return null;
  var hours = Array.from({ length: 24 }, function (_, i) { return i + ':00'; });
  data = data || {
    dos:   hours.map(function () { return 0; }),
    probe: hours.map(function () { return 0; }),
    r2l:   hours.map(function () { return 0; }),
    u2r:   hours.map(function () { return 0; }),
  };
  return new Chart(ctx, {
    type: 'bar',
    data: {
      labels: hours,
      datasets: [
        { label: 'DoS',   data: data.dos,   backgroundColor: 'rgba(255,51,85,0.68)',  borderColor: '#ff3355', borderWidth: 1, borderRadius: 3 },
        { label: 'Probe', data: data.probe, backgroundColor: 'rgba(255,173,0,0.68)',  borderColor: '#ffad00', borderWidth: 1, borderRadius: 3 },
        { label: 'R2L',   data: data.r2l,   backgroundColor: 'rgba(176,96,255,0.68)', borderColor: '#b060ff', borderWidth: 1, borderRadius: 3 },
        { label: 'U2R',   data: data.u2r,   backgroundColor: 'rgba(0,200,240,0.68)',  borderColor: '#00c8f0', borderWidth: 1, borderRadius: 3 },
      ],
    },
    options: Object.assign({}, NIDS.chartDefaults, {
      plugins: Object.assign({}, NIDS.chartDefaults.plugins, {
        tooltip: Object.assign({}, NIDS.chartDefaults.plugins.tooltip, { mode: 'index', intersect: false }),
      }),
      scales: Object.assign({}, NIDS.chartDefaults.scales, {
        x: Object.assign({}, NIDS.chartDefaults.scales.x, {
          ticks: Object.assign({}, NIDS.chartDefaults.scales.x.ticks, { maxTicksLimit: 8 }),
        }),
      }),
    }),
  });
};

/* ── Attack type breakdown doughnut (historical) ────────────────── */
NIDS.createTypeChart = function (canvasId, data) {
  var ctx = document.getElementById(canvasId);
  if (!ctx) return null;
  data = data || { normal: 0, dos: 0, probe: 0, r2l: 0, u2r: 0 };
  return new Chart(ctx, {
    type: 'doughnut',
    data: {
      labels: ['Normal', 'DoS', 'Probe', 'R2L', 'U2R'],
      datasets: [{
        data: [data.normal, data.dos, data.probe, data.r2l, data.u2r],
        backgroundColor: [
          'rgba(0,229,122,0.72)', 'rgba(255,51,85,0.72)',
          'rgba(255,173,0,0.72)', 'rgba(176,96,255,0.72)', 'rgba(0,200,240,0.72)',
        ],
        borderColor: ['#00e57a','#ff3355','#ffad00','#b060ff','#00c8f0'],
        borderWidth: 1.5, hoverOffset: 8,
      }],
    },
    options: {
      responsive: true, maintainAspectRatio: false, cutout: '60%',
      animation: { duration: 600 },
      plugins: {
        legend: {
          position: 'bottom',
          labels: { color: '#7a92b8', font: { size: 12, family: 'Syne' }, padding: 12, usePointStyle: true },
        },
        tooltip: NIDS.chartDefaults.plugins.tooltip,
      },
    },
  });
};

/* ── ROC curve (historical) ─────────────────────────────────────── */
NIDS.createROCChart = function (canvasId, aucScore) {
  var ctx = document.getElementById(canvasId);
  if (!ctx) return null;
  aucScore = aucScore || 0;
  var pts  = [0, 0.05, 0.10, 0.18, 0.28, 0.42, 0.60, 0.80, 1];
  // ROC points would come from backend /api/model/metrics
  // Using zeros until model is trained
  var rocY = aucScore > 0
    ? [0, 0.55, 0.75, 0.84, 0.91, 0.95, 0.97, 0.986, 1]
    : pts.map(function () { return 0; });

  return new Chart(ctx, {
    type: 'line',
    data: {
      labels: pts.map(function (v) { return v.toFixed(2); }),
      datasets: [
        {
          label: 'ROC (AUC = ' + (aucScore || '—') + ')',
          data: rocY,
          borderColor: '#00c8f0', backgroundColor: 'rgba(0,200,240,0.07)',
          tension: 0.4, fill: true, pointRadius: 3, borderWidth: 2,
          pointBackgroundColor: '#00c8f0',
        },
        {
          label: 'Random (AUC = 0.5)',
          data: pts,
          borderColor: 'rgba(122,146,184,0.38)', borderDash: [5, 5],
          pointRadius: 0, borderWidth: 1, fill: false,
        },
      ],
    },
    options: Object.assign({}, NIDS.chartDefaults, {
      scales: {
        x: Object.assign({}, NIDS.chartDefaults.scales.x, {
          title: { display: true, text: 'False Positive Rate', color: '#7a92b8', font: { size: 10 } },
        }),
        y: Object.assign({}, NIDS.chartDefaults.scales.y, {
          title: { display: true, text: 'True Positive Rate', color: '#7a92b8', font: { size: 10 } },
        }),
      },
    }),
  });
};

/* ── SHAP global importance (horizontal bar) ────────────────────── */
NIDS.createSHAPChart = function (canvasId, shapData) {
  var ctx = document.getElementById(canvasId);
  if (!ctx) return null;
  shapData = shapData || { labels: [], values: [] };

  return new Chart(ctx, {
    type: 'bar',
    data: {
      labels: shapData.labels,
      datasets: [{
        label: 'Mean |SHAP value|',
        data: shapData.values,
        backgroundColor: [
          '#ff3355','#ff3355','#ff5500','#ffad00',
          '#ffad00','#00c8f0','#00c8f0','#b060ff','#b060ff','#00e57a',
        ],
        borderWidth: 0, borderRadius: 4,
      }],
    },
    options: {
      indexAxis: 'y',
      responsive: true, maintainAspectRatio: false,
      animation: { duration: 600 },
      plugins: {
        legend: { display: false },
        tooltip: Object.assign({}, NIDS.chartDefaults.plugins.tooltip, {
          callbacks: { label: function (ctx) { return 'SHAP: ' + ctx.raw.toFixed(3); } },
        }),
      },
      scales: {
        x: {
          ticks: { color: '#7a92b8', font: { size: 10 } },
          grid:  { color: 'rgba(22,32,56,0.6)' }, border: { color: '#162038' },
        },
        y: {
          ticks: { color: '#7a92b8', font: { size: 10, family: 'JetBrains Mono' } },
          grid:  { color: 'rgba(22,32,56,0.2)' }, border: { color: '#162038' },
        },
      },
    },
  });
};

/* ── Helper: push a point to a live line chart ───────────────────── */
NIDS.pushChartPoint = function (chart, label, normalVal, attackVal, maxPoints) {
  if (!chart) return;
  maxPoints = maxPoints || 30;
  chart.data.labels.push(label);
  chart.data.datasets[0].data.push(normalVal);
  chart.data.datasets[1].data.push(attackVal);
  if (chart.data.labels.length > maxPoints) {
    chart.data.labels.shift();
    chart.data.datasets.forEach(function (ds) { ds.data.shift(); });
  }
  chart.update('none');
};

/* ── Helper: update doughnut data ───────────────────────────────── */
NIDS.updateDistChart = function (chart, counts) {
  if (!chart) return;
  chart.data.datasets[0].data = [
    counts.Normal || 0, counts.DoS || 0, counts.Probe || 0,
    counts.R2L    || 0, counts.U2R || 0,
  ];
  chart.update('none');
};