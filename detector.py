import time
from collections import defaultdict

# ── Thresholds ─────────────────────────────────────────
DOS_THRESHOLD        = 100   # packets/sec  → HIGH
PORTSCAN_THRESHOLD   = 20    # unique ports in 10s → MEDIUM
SYN_THRESHOLD        = 200   # SYN packets in 10s → HIGH
ICMP_THRESHOLD       = 50    # ICMP packets in 5s → MEDIUM
BRUTEFORCE_THRESHOLD = 5     # RST packets in 30s → HIGH

# ── Per-IP counters ────────────────────────────────────
packet_times = defaultdict(list)
port_history = defaultdict(set)
port_times   = defaultdict(list)
syn_times    = defaultdict(list)
icmp_times   = defaultdict(list)
rst_times    = defaultdict(list)

def _clean(timestamps, window):
    now = time.time()
    return [t for t in timestamps if now - t <= window]

def check_dos(src_ip):
    now = time.time()
    packet_times[src_ip].append(now)
    packet_times[src_ip] = _clean(packet_times[src_ip], 1)
    if len(packet_times[src_ip]) > DOS_THRESHOLD:
        return {'src_ip':src_ip,'attack_type':'DoS','severity':'High',
                'method':'Rule-Based',
                'detail':f"{len(packet_times[src_ip])} pkts/sec"}
    return None

def check_port_scan(src_ip, dst_port):
    now = time.time()
    port_times[src_ip].append(now)
    port_times[src_ip] = _clean(port_times[src_ip], 10)
    port_history[src_ip].add(dst_port)
    if len(port_history[src_ip]) > PORTSCAN_THRESHOLD:
        count = len(port_history[src_ip])
        port_history[src_ip].clear()
        return {'src_ip':src_ip,'attack_type':'Port Scan',
                'severity':'Medium','method':'Rule-Based',
                'detail':f"{count} ports in 10s"}
    return None

def check_syn_flood(src_ip):
    now = time.time()
    syn_times[src_ip].append(now)
    syn_times[src_ip] = _clean(syn_times[src_ip], 10)
    if len(syn_times[src_ip]) > SYN_THRESHOLD:
        return {'src_ip':src_ip,'attack_type':'SYN Flood',
                'severity':'High','method':'Rule-Based',
                'detail':f"{len(syn_times[src_ip])} SYN/10s"}
    return None

def check_icmp_flood(src_ip):
    now = time.time()
    icmp_times[src_ip].append(now)
    icmp_times[src_ip] = _clean(icmp_times[src_ip], 5)
    if len(icmp_times[src_ip]) > ICMP_THRESHOLD:
        return {'src_ip':src_ip,'attack_type':'ICMP Flood',
                'severity':'Medium','method':'Rule-Based',
                'detail':f"{len(icmp_times[src_ip])} ICMP/5s"}
    return None

def check_brute_force(src_ip):
    now = time.time()
    rst_times[src_ip].append(now)
    rst_times[src_ip] = _clean(rst_times[src_ip], 30)
    if len(rst_times[src_ip]) > BRUTEFORCE_THRESHOLD:
        return {'src_ip':src_ip,'attack_type':'Brute Force',
                'severity':'High','method':'Rule-Based',
                'detail':f"{len(rst_times[src_ip])} fails/30s"}
    return None

def run_all_rules(src_ip, dst_port=None, flags=None, protocol=None):
    """Called by sniffer.py for every packet. Returns list of alerts."""
    alerts = []
    a = check_dos(src_ip)
    if a: alerts.append(a)
    if dst_port and protocol in ('TCP','UDP'):
        a = check_port_scan(src_ip, dst_port)
        if a: alerts.append(a)
    if flags and 'S' in flags and 'A' not in flags:
        a = check_syn_flood(src_ip)
        if a: alerts.append(a)
    if flags and 'R' in flags:
        a = check_brute_force(src_ip)
        if a: alerts.append(a)
    if protocol == 'ICMP':
        a = check_icmp_flood(src_ip)
        if a: alerts.append(a)
    return alerts