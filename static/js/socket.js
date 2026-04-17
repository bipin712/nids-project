/* ================================================================
   socket.js  —  Network Intrusion Detection System
   WebSocket client – connects to FastAPI backend.
   Emits events that dashboard.js and other pages listen to.
   ================================================================ */

'use strict';

const NIDS = window.NIDS || {};
window.NIDS = NIDS;

/* ── Connection ─────────────────────────────────────────────────── */
NIDS.socket = null;
NIDS.connected = false;

NIDS.connectSocket = function () {
  // Determine protocol (ws or wss based on current page protocol)
  const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  const wsUrl = protocol + '//' + window.location.host + '/ws';
  
  console.log('[socket.js] Connecting to WebSocket at:', wsUrl);
  
  NIDS.socket = new WebSocket(wsUrl);

  /* ── Connection lifecycle ──────────────────────────────────────── */
  NIDS.socket.onopen = function () {
    NIDS.connected = true;
    console.log('[NIDS] WebSocket connected');
    NIDS._emit('nids:connected', { id: 'ws-client' });
    NIDS._updateConnectionUI(true);
  };

  NIDS.socket.onclose = function (event) {
    NIDS.connected = false;
    console.warn('[NIDS] WebSocket disconnected:', event.code, event.reason);
    NIDS._emit('nids:disconnected', { reason: event.reason || 'Connection closed' });
    NIDS._updateConnectionUI(false);
    
    // Attempt reconnection after 3 seconds
    setTimeout(NIDS.connectSocket, 3000);
  };

  NIDS.socket.onerror = function (err) {
    console.error('[NIDS] WebSocket error:', err);
    NIDS._emit('nids:error', { message: 'WebSocket connection error' });
  };

  NIDS.socket.onmessage = function (event) {
    try {
      const message = JSON.parse(event.data);
      const type = message.type;
      const data = message.data;

      switch (type) {
        case 'new_alert':
          NIDS._emit('nids:alert', data);
          break;
        case 'initial_alerts':
          NIDS._emit('nids:initial_alerts', data);
          break;
        case 'stats_update':
          NIDS._emit('nids:stats', data);
          break;
        case 'normal_traffic':
          NIDS._emit('nids:normal', data);
          break;
        case 'capture_started':
          NIDS._emit('nids:capture_started', data);
          break;
        case 'capture_stopped':
          NIDS._emit('nids:capture_stopped', data);
          break;
        default:
          console.log('[NIDS] Unknown message type:', type);
      }
    } catch (e) {
      console.error('[NIDS] Failed to parse WebSocket message:', e);
    }
  };
};

/* ── Client → Server ──────────────────────────────────────────── */
NIDS.requestStats = function () {
  if (NIDS.socket && NIDS.connected && NIDS.socket.readyState === WebSocket.OPEN) {
    NIDS.socket.send('request_stats');
  }
};

NIDS.startCapture = function (iface) {
  if (NIDS.socket && NIDS.connected && NIDS.socket.readyState === WebSocket.OPEN) {
    NIDS.socket.send(JSON.stringify({ type: 'start_capture', interface: iface || 'auto' }));
  } else {
    console.warn('[NIDS] WebSocket not connected; cannot start capture.');
  }
};

NIDS.stopCapture = function () {
  if (NIDS.socket && NIDS.connected && NIDS.socket.readyState === WebSocket.OPEN) {
    NIDS.socket.send(JSON.stringify({ type: 'stop_capture' }));
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