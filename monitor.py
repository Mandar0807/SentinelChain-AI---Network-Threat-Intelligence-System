import threading
import time
import datetime
import socket
from collections import defaultdict

# Scapy import — requires administrator privileges
try:
    from scapy.all import sniff, IP, IPv6, TCP, UDP, conf
    conf.verb = 0          # suppress scapy output
    SCAPY_AVAILABLE = True
except Exception as e:
    print(f"[monitor] Scapy import warning: {e}")
    SCAPY_AVAILABLE = False


# ── Shared state ───────────────────────────────────────────────────────────
_lock            = threading.Lock()
_packets         = []          # raw packet log
_is_monitoring   = False       # flag to control the sniffer loop
_monitor_thread  = None        # reference to background thread
_start_time      = None        # when monitoring started
_alert_triggered = False       # set to True when anomaly detected
_alert_reason    = ""          # human readable reason for alert

# Cache for Reverse DNS lookups (IP -> Hostname) to avoid slow repeated lookups
_dns_cache = {}


def _resolve_ip_bg(ip):
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        _dns_cache[ip] = hostname
    except Exception:
        _dns_cache[ip] = "Unknown Server"

def _resolve_hostname(ip: str) -> str:
    """Attempt to resolve an IP address to a hostname, with caching."""
    if ip in _dns_cache:
        return _dns_cache[ip]
    
    # Mark as resolving to prevent multiple threads from starting a lookup for the same IP
    _dns_cache[ip] = "Resolving..."
    
    # Start a background thread to resolve it so we don't block the UI
    threading.Thread(target=_resolve_ip_bg, args=(ip,), daemon=True).start()
    
    return "Resolving..."


# ── Packet handler ─────────────────────────────────────────────────────────
def _handle_packet(packet):
    """
    Called by scapy for every captured packet.
    Runs inside the background thread.
    Extracts key fields (including TCP flags for SYN flood detection)
    and stores them in shared _packets list.
    """
    global _is_monitoring

    if not _is_monitoring:
        return

    if IP not in packet and IPv6 not in packet:
        return          # only care about IP or IPv6 packets

    try:
        src_ip   = packet[IP].src if IP in packet else packet[IPv6].src
        dst_ip   = packet[IP].dst if IP in packet else packet[IPv6].dst
        size     = len(packet)
        proto    = "TCP" if TCP in packet else "UDP" if UDP in packet else "OTHER"
        port     = 0
        tcp_flag = ""

        if TCP in packet:
            port = packet[TCP].dport
            tcp_flag = str(packet[TCP].flags) # e.g., 'S' for SYN, 'A' for ACK
        elif UDP in packet:
            port = packet[UDP].dport

        entry = {
            "timestamp" : datetime.datetime.now().strftime("%H:%M:%S"),
            "src_ip"    : src_ip,
            "dst_ip"    : dst_ip,
            "port"      : port,
            "protocol"  : proto,
            "tcp_flag"  : tcp_flag,
            "size"      : size,
        }

        with _lock:
            _packets.append(entry)

    except Exception:
        pass        # never crash the sniffer thread


# ── Sniffer loop ───────────────────────────────────────────────────────────
def _sniffer_loop():
    global _is_monitoring

    while _is_monitoring:
        try:
            sniff(
                prn     = _handle_packet,
                filter  = "ip or ip6",  # capture both IPv4 and IPv6
                store   = False,        
                timeout = 5,            
            )
        except Exception as e:
            print(f"[monitor] Sniffer error: {e}")
            break


# ── Public API ─────────────────────────────────────────────────────────────
def start_monitoring():
    global _is_monitoring, _monitor_thread, _packets
    global _start_time, _alert_triggered, _alert_reason, _dns_cache

    if _is_monitoring:
        print("[monitor] Already monitoring.")
        return

    if not SCAPY_AVAILABLE:
        print("[monitor] Scapy not available — cannot start monitoring.")
        return

    # Reset state
    with _lock:
        _packets.clear()
        _dns_cache.clear()

    _alert_triggered = False
    _alert_reason    = ""
    _is_monitoring   = True
    _start_time      = time.time()

    _monitor_thread = threading.Thread(
        target  = _sniffer_loop,
        daemon  = True,
        name    = "PacketSniffer"
    )
    _monitor_thread.start()
    print(f"[monitor] Deep Background Tracking started...")


def stop_monitoring():
    global _is_monitoring, _monitor_thread

    if not _is_monitoring:
        print("[monitor] Not currently monitoring.")
        return

    _is_monitoring = False

    if _monitor_thread:
        _monitor_thread.join(timeout=8)

    duration = round(time.time() - _start_time, 1) if _start_time else 0
    print(f"[monitor] Monitoring stopped after {duration}s")
    print(f"[monitor] Total packets captured: {len(_packets)}")


def get_status() -> dict:
    """Return current monitoring status and basic stats."""
    with _lock:
        total    = len(_packets)
        duration = round(time.time() - _start_time, 1) \
                   if _start_time and _is_monitoring else 0

        unique_ips = len(set(p["dst_ip"] for p in _packets))
        total_bytes = sum(p["size"] for p in _packets)

    return {
        "is_monitoring"   : _is_monitoring,
        "total_packets"   : total,
        "unique_dst_ips"  : unique_ips,
        "total_bytes"     : total_bytes,
        "duration_seconds": duration,
        "alert_triggered" : _alert_triggered,
        "alert_reason"    : _alert_reason,
    }


def get_traffic_summary() -> dict:
    """
    Aggregate packet data into a deep summary dictionary.
    Calculates SYN counts, extracts hostnames, and tracks ports for attack detection.
    """
    with _lock:
        packets = list(_packets)

    if not packets:
        return {
            "total_packets"   : 0,
            "total_bytes"     : 0,
            "unique_dst_ips"  : 0,
            "bytes_per_second": 0,
            "packets_per_sec" : 0,
            "tcp_syn_count"   : 0,
            "avg_packet_size" : 0,
            "active_connections": []
        }

    total_packets = len(packets)
    total_bytes   = sum(p["size"] for p in packets)
    avg_packet_size = int(total_bytes / total_packets)

    # Variables for Attack Detection
    tcp_syn_count = sum(1 for p in packets if 'S' in p["tcp_flag"])

    # Aggregate by Destination IP
    # We want to build a list of all background servers we are talking to
    connections = {}
    
    for p in packets:
        ip = p["dst_ip"]
        if ip not in connections:
            connections[ip] = {
                "ip": ip,
                "hostname": "Resolving...",
                "bytes": 0,
                "packets": 0,
                "unique_ports": set(),
                "protocols": set()
            }
        
        connections[ip]["bytes"] += p["size"]
        connections[ip]["packets"] += 1
        connections[ip]["unique_ports"].add(p["port"])
        connections[ip]["protocols"].add(p["protocol"])

    # Resolve hostnames and clean up sets for JSON serialization
    active_connections = []
    for ip, data in connections.items():
        data["hostname"] = _resolve_hostname(ip)
        data["port_count"] = len(data["unique_ports"])
        data["ports"] = list(data["unique_ports"])[:5] # Only send first 5 to UI
        data["protocols"] = list(data["protocols"])
        del data["unique_ports"]
        active_connections.append(data)

    # Sort connections by bytes transferred (largest first)
    active_connections.sort(key=lambda x: x["bytes"], reverse=True)

    # Rates (based on monitoring duration)
    duration = time.time() - _start_time if _start_time else 1
    duration = max(duration, 1)

    bytes_per_second  = round(total_bytes   / duration, 2)
    packets_per_sec   = round(total_packets / duration, 2)

    return {
        "total_packets"   : total_packets,
        "total_bytes"     : total_bytes,
        "unique_dst_ips"  : len(active_connections),
        "bytes_per_second": bytes_per_second,
        "packets_per_sec" : packets_per_sec,
        "tcp_syn_count"   : tcp_syn_count,
        "avg_packet_size" : avg_packet_size,
        "active_connections": active_connections[:50] # Top 50 connections
    }


def set_alert(reason: str):
    global _alert_triggered, _alert_reason
    _alert_triggered = True
    _alert_reason    = reason
    print(f"[monitor] ALERT TRIGGERED: {reason}")