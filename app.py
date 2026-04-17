# app.py
# Flask + Flask-SocketIO server for NIDS
# Entry point — run with: sudo venv/bin/python3 app.py
# Serves all dashboard pages, handles WebSocket, starts sniffer thread

import threading
import csv
import os
from datetime import datetime
from flask import Flask, render_template, jsonify, request, send_file
from flask_socketio import SocketIO, emit

# ── Import your backend modules ────────────────────────────────────────────
from alert_logger import generate_alert, get_recent, get_all, get_stats
from ml_classifier import is_ready, classify, get_confidence
import sniffer

# ── Flask + SocketIO setup ──────────────────────────────────────────────────
app = Flask(__name__)
app.config['SECRET_KEY'] = 'nids_secret_key_2026'

# async_mode='eventlet' supports WebSocket properly
# If friend used plain polling — it still works via /api/alerts route
socketio = SocketIO(app, async_mode='eventlet', cors_allowed_origins='*')

# ── Global sniffer thread ───────────────────────────────────────────────────
sniffer_thread = None
sniffer_running = False

# ── Helper: push alert to all connected browsers via WebSocket ──────────────
def push_alert_to_dashboard(alert):
    """Called by alert_logger when new alert is generated."""
    try:
        socketio.emit('new_alert', alert)
    except Exception as e:
        print(f"[APP] SocketIO emit error: {e}")

# Inject the push function into alert_logger so it can call it
import alert_logger
alert_logger.push_callback = push_alert_to_dashboard

# ══════════════════════════════════════════════════════════════════════════════
#   PAGE ROUTES — serves HTML templates
# ══════════════════════════════════════════════════════════════════════════════

@app.route('/')
def index():
    """Main dashboard page."""
    return render_template('index.html')

@app.route('/alerts')
def alerts_page():
    """Live alerts page."""
    return render_template('alerts.html')

@app.route('/analysis')
def analysis_page():
    """Attack analysis and charts page."""
    return render_template('analysis.html')

@app.route('/ml-status')
def ml_status_page():
    """ML model status page."""
    return render_template('ml_status.html')

@app.route('/logs')
def logs_page():
    """Full alert history log page."""
    return render_template('logs.html')

@app.route('/settings')
def settings_page():
    """System settings page."""
    return render_template('settings.html')

# ══════════════════════════════════════════════════════════════════════════════
#   API ROUTES — returns JSON data (used by JS polling OR WebSocket fallback)
# ══════════════════════════════════════════════════════════════════════════════

@app.route('/api/alerts')
def api_alerts():
    """
    Returns recent alerts as JSON.
    Used by dashboard.js if it polls instead of using WebSocket.
    Returns last 50 alerts by default, or ?n=100 for more.
    """
    n = request.args.get('n', 50, type=int)
    return jsonify(get_recent(n))

@app.route('/api/alerts/all')
def api_alerts_all():
    """Returns ALL alerts — used by logs page."""
    return jsonify(get_all())

@app.route('/api/stats')
def api_stats():
    """
    Returns system statistics.
    Used by dashboard stats cards (total packets, alerts, severity counts).
    """
    sniff_stats = sniffer.get_stats()
    alert_stats = get_stats()

    return jsonify({
        'packets_captured': sniff_stats.get('packets_captured', 0),
        'alerts_total'    : alert_stats.get('total', 0),
        'alerts_high'     : alert_stats.get('high', 0),
        'alerts_medium'   : alert_stats.get('medium', 0),
        'alerts_low'      : alert_stats.get('low', 0),
        'sniffer_running' : sniff_stats.get('is_running', False),
        'interface'       : sniff_stats.get('interface', 'eth0'),
        'ml_ready'        : is_ready(),
    })

@app.route('/api/ml-status')
def api_ml_status():
    """Returns ML model details — used by ml_status page."""
    return jsonify({
        'ml_ready'   : is_ready(),
        'algorithm'  : 'Random Forest',
        'dataset'    : 'NSL-KDD (125,973 rows)',
        'trees'      : 100,
        'classes'    : ['normal', 'dos', 'probe', 'r2l', 'u2r'],
        'accuracy'   : '98.4%',
        'smote_used' : True,
    })

@app.route('/api/alerts/download')
def download_alerts():
    """Downloads alerts.csv file — used by logs page download button."""
    log_file = os.path.join('logs', 'alerts.csv')
    if os.path.exists(log_file):
        return send_file(
            log_file,
            mimetype='text/csv',
            as_attachment=True,
            download_name='alerts.csv'
        )
    return jsonify({'error': 'No alerts file yet'}), 404

@app.route('/api/alerts/clear', methods=['POST'])
def clear_alerts():
    """Clears the in-memory alert queue — used by settings page."""
    alert_logger.clear_queue()
    return jsonify({'status': 'cleared'})

@app.route('/api/sniffer/start', methods=['POST'])
def start_sniffer_api():
    """Starts the sniffer — used by settings page start button."""
    global sniffer_thread, sniffer_running
    if not sniffer_running:
        data      = request.get_json() or {}
        interface = data.get('interface', 'eth0')
        _start_sniffer(interface)
        return jsonify({'status': 'started', 'interface': interface})
    return jsonify({'status': 'already running'})

@app.route('/api/sniffer/stop', methods=['POST'])
def stop_sniffer_api():
    """Stops the sniffer — used by settings page stop button."""
    global sniffer_running
    sniffer_running = False
    return jsonify({'status': 'stopped'})

# ══════════════════════════════════════════════════════════════════════════════
#   WEBSOCKET EVENTS
# ══════════════════════════════════════════════════════════════════════════════

@socketio.on('connect')
def handle_connect():
    """Client browser connected via WebSocket."""
    print(f"[WS] Browser connected")
    # Send last 20 alerts immediately so page is not empty on load
    recent = get_recent(20)
    emit('initial_alerts', recent)
    emit('stats_update', {
        'packets_captured': sniffer.get_stats().get('packets_captured', 0),
        'alerts_total'    : get_stats().get('total', 0),
        'ml_ready'        : is_ready(),
    })

@socketio.on('disconnect')
def handle_disconnect():
    print(f"[WS] Browser disconnected")

@socketio.on('request_stats')
def handle_stats_request():
    """Browser asked for latest stats — send them back."""
    sniff_stats  = sniffer.get_stats()
    alert_stats  = get_stats()
    emit('stats_update', {
        'packets_captured': sniff_stats.get('packets_captured', 0),
        'alerts_total'    : alert_stats.get('total', 0),
        'alerts_high'     : alert_stats.get('high', 0),
        'alerts_medium'   : alert_stats.get('medium', 0),
        'alerts_low'      : alert_stats.get('low', 0),
        'sniffer_running' : sniff_stats.get('is_running', False),
        'ml_ready'        : is_ready(),
    })

# ══════════════════════════════════════════════════════════════════════════════
#   SNIFFER THREAD MANAGEMENT
# ══════════════════════════════════════════════════════════════════════════════

def _start_sniffer(interface='eth0'):
    """Starts the packet sniffer in a background thread."""
    global sniffer_thread, sniffer_running

    def run():
        global sniffer_running
        sniffer_running = True
        try:
            sniffer.start_sniffing(interface=interface)
        except Exception as e:
            print(f"[SNIFFER] Error: {e}")
        finally:
            sniffer_running = False

    sniffer_thread        = threading.Thread(target=run, daemon=True)
    sniffer_thread.start()
    print(f"[APP] Sniffer thread started on interface: {interface}")

# ══════════════════════════════════════════════════════════════════════════════
#   MAIN ENTRY POINT
# ══════════════════════════════════════════════════════════════════════════════

if __name__ == '__main__':
    print("=" * 55)
    print("  NIDS — Network Intrusion Detection System")
    print("  Starting up...")
    print("=" * 55)

    # Start packet sniffer in background thread
    # Change 'eth0' to your actual Kali interface name
    # Run: ip a    to find your interface name
    INTERFACE = 'eth0'
    _start_sniffer(interface=INTERFACE)

    print(f"[APP] ML model ready : {is_ready()}")
    print(f"[APP] Interface      : {INTERFACE}")
    print(f"[APP] Dashboard      : http://localhost:5000")
    print("=" * 55)

    # Run Flask-SocketIO server
    # host='0.0.0.0' makes it accessible from other machines on same network
    socketio.run(
        app,
        host='0.0.0.0',
        port=5000,
        debug=False,        # set True only for development
        use_reloader=False  # must be False when running sniffer thread
    )