from scapy.all import sniff, IP, TCP, UDP, ICMP
from detector import run_all_rules
from ml_classifier import classify, get_confidence, is_ready
from alert_logger import generate_alert
import threading

# ── Stats counters ─────────────────────────────────────
stats = {
    'packets_captured': 0,
    'alerts_generated': 0,
    'is_running'      : False,
    'interface'       : 'eth0'
}
stats_lock = threading.Lock()

def process_packet(packet):
    """Called by Scapy for every single packet captured."""
    with stats_lock:
        stats['packets_captured'] += 1

    # Only process packets with IP layer
    if not packet.haslayer(IP):
        return

    src_ip   = packet[IP].src
    dst_ip   = packet[IP].dst
    protocol = None
    dst_port = None
    flags    = None

    # Extract protocol-specific fields
    if packet.haslayer(TCP):
        protocol = 'TCP'
        dst_port = packet[TCP].dport
        flags    = str(packet[TCP].flags)
    elif packet.haslayer(UDP):
        protocol = 'UDP'
        dst_port = packet[UDP].dport
    elif packet.haslayer(ICMP):
        protocol = 'ICMP'

    # ── PATH 1: Rule-based detection ───────────────────
    rule_alerts = run_all_rules(
        src_ip   = src_ip,
        dst_port = dst_port,
        flags    = flags,
        protocol = protocol
    )

    for alert in rule_alerts:
        generate_alert(
            src_ip      = alert['src_ip'],
            attack_type = alert['attack_type'],
            severity    = alert['severity'],
            method      = 'Rule-Based',
            detail      = alert['detail']
        )
        with stats_lock:
            stats['alerts_generated'] += 1

    # ── PATH 2: ML classification ──────────────────────
    # Build a simple feature vector from packet fields
    if is_ready() and protocol:
        features = build_features(packet, protocol, dst_port)
        if features:
            prediction = classify(features)
            confidence = get_confidence(features)
            if prediction != 'normal' and prediction != 'unknown':
                # Only alert if not already caught by rules
                already_caught = any(
                    a['attack_type'].lower() in prediction
                    for a in rule_alerts
                )
                if not already_caught:
                    sev = 'High' if prediction in ('dos','u2r') \
                          else 'Medium'
                    generate_alert(
                        src_ip      = src_ip,
                        attack_type = prediction.upper(),
                        severity    = sev,
                        method      = 'ML',
                        detail      = f"Confidence: {int(confidence*100)}%"
                    )
                    with stats_lock:
                        stats['alerts_generated'] += 1

def build_features(packet, protocol, dst_port):
    """
    Build a simplified 41-feature vector from a live packet.
    In a real system this uses flow-level statistics.
    Here we use packet-level fields with defaults.
    """
    try:
        proto_map = {'TCP':6,'UDP':17,'ICMP':1}
        p = proto_map.get(protocol, 0)
        src_bytes = len(packet)
        dst_bytes = 0
        features  = [0]*41
        features[0]  = 0           # duration
        features[1]  = p           # protocol_type
        features[3]  = 0           # flag (simplified)
        features[4]  = src_bytes   # src_bytes
        features[5]  = dst_bytes   # dst_bytes
        return features
    except:
        return None

def start_sniffing(interface='eth0'):
    """Start packet capture — must run on Kali VM with sudo."""
    with stats_lock:
        stats['is_running'] = True
        stats['interface']  = interface
    print(f"[SNIFFER] Starting on interface: {interface}")
    print(f"[SNIFFER] ML model ready: {is_ready()}")
    print(f"[SNIFFER] Listening for packets...")
    sniff(
        iface   = interface,
        prn     = process_packet,
        store   = False      # don't keep packets in RAM
    )

def get_stats():
    with stats_lock:
        return dict(stats)