import csv, os, threading
from datetime import datetime

alert_queue = []
MAX_QUEUE   = 500
lock        = threading.Lock()
LOG_DIR     = 'logs'
LOG_FILE    = os.path.join(LOG_DIR, 'alerts.csv')
HEADERS     = ['timestamp','src_ip','attack_type',
               'severity','method','detail']

def _ensure_csv():
    os.makedirs(LOG_DIR, exist_ok=True)
    if not os.path.exists(LOG_FILE):
        with open(LOG_FILE, 'w', newline='') as f:
            csv.DictWriter(f, fieldnames=HEADERS).writeheader()

def generate_alert(src_ip, attack_type, severity,
                   method='Rule-Based', detail=''):
    _ensure_csv()
    alert = {
        'timestamp'  : datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'src_ip'     : src_ip,
        'attack_type': attack_type,
        'severity'   : severity,
        'method'     : method,
        'detail'     : detail
    }
    with open(LOG_FILE, 'a', newline='') as f:
        csv.DictWriter(f, fieldnames=HEADERS).writerow(alert)
    with lock:
        alert_queue.append(alert)
        if len(alert_queue) > MAX_QUEUE:
            alert_queue.pop(0)
    print(f"[ALERT] {alert['timestamp']} | "
          f"{attack_type} | {src_ip} | {severity}")
    return alert

def get_recent(n=50):
    with lock:
        return list(alert_queue[-n:])

def get_all():
    with lock:
        return list(alert_queue)

def get_stats():
    with lock:
        total = len(alert_queue)
        high  = sum(1 for a in alert_queue if a['severity']=='High')
        med   = sum(1 for a in alert_queue if a['severity']=='Medium')
        low   = sum(1 for a in alert_queue if a['severity']=='Low')
        return {'total':total,'high':high,'medium':med,'low':low}