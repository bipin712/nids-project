# alert_logger.py
# Handles all alert output:
# 1. Saves every alert to logs/alerts.csv permanently
# 2. Keeps in-memory queue for API polling
# 3. Pushes alert to dashboard via WebSocket (if app.py has set push_callback)

import csv
import os
import threading
from datetime import datetime

# ── Shared alert queue ──────────────────────────────────────────────────────
alert_queue = []
MAX_QUEUE   = 500
lock        = threading.Lock()

# ── CSV file setup ──────────────────────────────────────────────────────────
LOG_DIR  = 'logs'
LOG_FILE = os.path.join(LOG_DIR, 'alerts.csv')
HEADERS  = ['timestamp', 'src_ip', 'attack_type',
            'severity', 'method', 'detail']

# ── WebSocket push callback ─────────────────────────────────────────────────
# app.py sets this to push_alert_to_dashboard() after import
# If not set — alerts still work via polling, just no instant push
push_callback = None

def _ensure_csv():
    """Create logs/ folder and CSV with headers if not exists."""
    os.makedirs(LOG_DIR, exist_ok=True)
    if not os.path.exists(LOG_FILE):
        with open(LOG_FILE, 'w', newline='') as f:
            csv.DictWriter(f, fieldnames=HEADERS).writeheader()

def generate_alert(src_ip, attack_type, severity,
                   method='Rule-Based', detail=''):
    """
    Main function called whenever an attack is detected.
    Called by detector.py and sniffer.py.
    """
    _ensure_csv()

    alert = {
        'timestamp'  : datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'src_ip'     : src_ip,
        'attack_type': attack_type,
        'severity'   : severity,
        'method'     : method,
        'detail'     : detail
    }

    # 1. Save to CSV permanently
    try:
        with open(LOG_FILE, 'a', newline='') as f:
            csv.DictWriter(f, fieldnames=HEADERS).writerow(alert)
    except Exception as e:
        print(f"[LOGGER] CSV write error: {e}")

    # 2. Add to in-memory queue (thread-safe)
    with lock:
        alert_queue.append(alert)
        if len(alert_queue) > MAX_QUEUE:
            alert_queue.pop(0)

    # 3. Push to dashboard via WebSocket instantly
    if push_callback:
        try:
            push_callback(alert)
        except Exception as e:
            print(f"[LOGGER] WebSocket push error: {e}")

    print(f"[ALERT] {alert['timestamp']} | "
          f"{attack_type} | {src_ip} | {severity}")

    return alert

def get_recent(n=50):
    """Returns last n alerts from memory queue."""
    with lock:
        return list(alert_queue[-n:])

def get_all():
    """Returns all alerts from memory queue."""
    with lock:
        return list(alert_queue)

def get_stats():
    """Returns count breakdown by severity."""
    with lock:
        total  = len(alert_queue)
        high   = sum(1 for a in alert_queue if a['severity'] == 'High')
        medium = sum(1 for a in alert_queue if a['severity'] == 'Medium')
        low    = sum(1 for a in alert_queue if a['severity'] == 'Low')
        return {
            'total' : total,
            'high'  : high,
            'medium': medium,
            'low'   : low
        }

def clear_queue():
    """Clears in-memory queue. Does NOT delete CSV file."""
    with lock:
        alert_queue.clear()
    print("[LOGGER] Alert queue cleared")