/* ================================================================
   socket.js  —  ShieldNet NIDS
   SocketIO client – connects to Flask-SocketIO backend.
   Emits events that dashboard.js and other pages listen to.
   ================================================================ */

'use strict';

const NIDS = window.NIDS || {};
window.NIDS = NIDS;

/* ── Connection ─────────────────────────────────────────────────── */
NIDS.socket = null;
NIDS.connected = false;

NIDS.connectSocket = function () {
  // io() comes from the Flask-SocketIO CDN script
  // URL is auto-detected from the page origin
  if (typeof io === 'undefined') {
    console.warn('[socket.js] SocketIO not loaded — running in demo mode');
    NIDS._demoMode = true;
    return;
  }

  NIDS.socket = io({
    transports: ['websocket', 'polling'],
    reconnection: true,
    reconnectionAttempts: 10,
    reconnectionDelay: 2000,
  });

  /* ── Connection lifecycle ──────────────────────────────────────── */
  NIDS.socket.on('connect', function () {
    NIDS.connected = true;
    console.log('[NIDS] Socket connected:', NIDS.socket.id);
    NIDS._emit('nids:connected', { id: NIDS.socket.id });
    NIDS._updateConnectionUI(true);
  });

  NIDS.socket.on('disconnect', function (reason) {
    NIDS.connected = false;
    console.warn('[NIDS] Socket disconnected:', reason);
    NIDS._emit('nids:disconnected', { reason });
    NIDS._updateConnectionUI(false);
  });

  NIDS.socket.on('connect_error', function (err) {
    console.error('[NIDS] Connection error:', err.message);
  });

  /* ── Server → Client events ──────────────────────────────────── */

  // New alert from ensemble engine
  NIDS.socket.on('new_alert', function (data) {
    // data shape:
    // { timestamp, src_ip, dst_ip, protocol, is_attack, attack_type,
    //   severity, combined_score, rule_score, ml_score, ml_class,
    //   ml_confidence, rule_fired, explanation, packet_count }
    NIDS._emit('nids:alert', data);
  });

  // Normal traffic notification (low-priority)
  NIDS.socket.on('normal_traffic', function (data) {
    NIDS._emit('nids:normal', data);
  });

  // System status update from backend
  NIDS.socket.on('system_status', function (data) {
    // data: { cpu, memory, packet_rate, model_load, db_size, uptime }
    NIDS._emit('nids:status', data);
  });

  // Capture started/stopped confirmation
  NIDS.socket.on('capture_started', function (data) {
    NIDS._emit('nids:capture_started', data);
  });
  NIDS.socket.on('capture_stopped', function (data) {
    NIDS._emit('nids:capture_stopped', data);
  });
};

/* ── Client → Server ──────────────────────────────────────────── */
NIDS.startCapture = function (iface) {
  if (NIDS.socket && NIDS.connected) {
    NIDS.socket.emit('start_capture', { interface: iface || 'auto' });
  } else if (NIDS._demoMode) {
    NIDS._emit('nids:capture_started', {});
  } else {
    console.warn('[NIDS] Socket not connected yet; cannot start capture.');
  }
};

NIDS.stopCapture = function () {
  if (NIDS.socket && NIDS.connected) {
    NIDS.socket.emit('stop_capture', {});
  }
};

NIDS.requestStatus = function () {
  if (NIDS.socket && NIDS.connected) {
    NIDS.socket.emit('request_status', {});
  }
};

/* ── Internal event bus ───────────────────────────────────────── */
NIDS._listeners = {};

NIDS.on = function (event, fn) {
  if (!NIDS._listeners[event]) NIDS._listeners[event] = [];
  NIDS._listeners[event].push(fn);
};

NIDS.off = function (event, fn) {
  if (!NIDS._listeners[event]) return;
  NIDS._listeners[event] = NIDS._listeners[event].filter(function (f) { return f !== fn; });
};

NIDS._emit = function (event, data) {
  var fns = NIDS._listeners[event];
  if (!fns) return;
  fns.forEach(function (fn) {
    try { fn(data); } catch (e) { console.error('[NIDS event]', event, e); }
  });
};

/* ── Connection status UI helper ──────────────────────────────── */
NIDS._updateConnectionUI = function (online) {
  var dot  = document.getElementById('sb-status-dot');
  var text = document.getElementById('sb-status-text');
  if (dot)  dot.style.background  = online ? 'var(--c-green)' : 'var(--c-amber)';
  if (text) text.textContent       = online ? 'MONITORING ACTIVE' : 'RECONNECTING...';
};

/* ── Auto-connect on page load ────────────────────────────────── */
document.addEventListener('DOMContentLoaded', function () {
  NIDS.connectSocket();
});