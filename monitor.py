import threading
import time
import datetime
from collections import defaultdict

# Scapy import — requires administrator privileges
try:
    from scapy.all import sniff, IP, TCP, UDP, conf
    conf.verb = 0          # suppress scapy output
    SCAPY_AVAILABLE = True
except Exception as e:
    print(f"[monitor] Scapy import warning: {e}")
    SCAPY_AVAILABLE = False


# ── Shared state ───────────────────────────────────────────────────────────
# These are accessed by both the sniffer thread and the main thread
_lock            = threading.Lock()
_packets         = []          # raw packet log
_is_monitoring   = False       # flag to control the sniffer loop
_monitor_thread  = None        # reference to background thread
_start_time      = None        # when monitoring started
_alert_triggered = False       # set to True when anomaly detected
_alert_reason    = ""          # human readable reason for alert


# ── Packet handler ─────────────────────────────────────────────────────────
def _handle_packet(packet):
    """
    Called by scapy for every captured packet.
    Runs inside the background thread.
    Extracts key fields and stores them in shared _packets list.
    """
    global _is_monitoring

    if not _is_monitoring:
        return

    if IP not in packet:
        return          # only care about IP packets

    try:
        src_ip   = packet[IP].src
        dst_ip   = packet[IP].dst
        size     = len(packet)
        proto    = "TCP" if TCP in packet else "UDP" if UDP in packet else "OTHER"
        port     = 0

        if TCP in packet:
            port = packet[TCP].dport
        elif UDP in packet:
            port = packet[UDP].dport

        entry = {
            "timestamp" : datetime.datetime.now().strftime("%H:%M:%S"),
            "src_ip"    : src_ip,
            "dst_ip"    : dst_ip,
            "port"      : port,
            "protocol"  : proto,
            "size"      : size,
        }

        with _lock:
            _packets.append(entry)

    except Exception:
        pass        # never crash the sniffer thread


# ── Sniffer loop ───────────────────────────────────────────────────────────
def _sniffer_loop():
    """
    Runs in background thread.
    Captures packets in 5-second bursts so we can check
    the _is_monitoring flag and stop cleanly.
    """
    global _is_monitoring

    while _is_monitoring:
        try:
            sniff(
                prn     = _handle_packet,
                filter  = "ip",         # only IP packets
                store   = False,        # don't store in scapy memory
                timeout = 5,            # return every 5 seconds
            )
        except Exception as e:
            print(f"[monitor] Sniffer error: {e}")
            break


# ── Public API ─────────────────────────────────────────────────────────────
def start_monitoring():
    """
    Start the background packet sniffer.
    Call this when the user clicks 'Start Monitoring' in the dashboard.
    """
    global _is_monitoring, _monitor_thread, _packets
    global _start_time, _alert_triggered, _alert_reason

    if _is_monitoring:
        print("[monitor] Already monitoring.")
        return

    if not SCAPY_AVAILABLE:
        print("[monitor] Scapy not available — cannot start monitoring.")
        return

    # Reset state
    with _lock:
        _packets.clear()

    _alert_triggered = False
    _alert_reason    = ""
    _is_monitoring   = True
    _start_time      = time.time()

    # Start background thread
    _monitor_thread = threading.Thread(
        target  = _sniffer_loop,
        daemon  = True,         # dies automatically when main program exits
        name    = "PacketSniffer"
    )
    _monitor_thread.start()
    print(f"[monitor] Monitoring started — capturing packets...")


def stop_monitoring():
    """
    Stop the background packet sniffer.
    Call this when the user clicks 'Stop Monitoring'.
    """
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


def get_packets() -> list:
    """Return a copy of all captured packets so far."""
    with _lock:
        return list(_packets)


def get_status() -> dict:
    """Return current monitoring status and basic stats."""
    with _lock:
        total    = len(_packets)
        duration = round(time.time() - _start_time, 1) \
                   if _start_time and _is_monitoring else 0

        # Count unique destination IPs
        unique_ips = len(set(p["dst_ip"] for p in _packets))

        # Total bytes sent
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
    Aggregate packet data into a summary dictionary.
    This is what the anomaly detector consumes on Day 6.
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
            "top_destinations": [],
            "port_counts"     : {},
        }

    total_packets = len(packets)
    total_bytes   = sum(p["size"] for p in packets)

    # Unique destination IPs
    ip_counts = defaultdict(int)
    for p in packets:
        ip_counts[p["dst_ip"]] += 1
    unique_dst_ips = len(ip_counts)

    # Top 5 destination IPs by packet count
    top_destinations = sorted(
        ip_counts.items(), key=lambda x: x[1], reverse=True
    )[:5]

    # Port frequency
    port_counts = defaultdict(int)
    for p in packets:
        port_counts[str(p["port"])] += 1

    # Rates (based on monitoring duration)
    duration = time.time() - _start_time if _start_time else 1
    duration = max(duration, 1)

    bytes_per_second  = round(total_bytes   / duration, 2)
    packets_per_sec   = round(total_packets / duration, 2)

    return {
        "total_packets"   : total_packets,
        "total_bytes"     : total_bytes,
        "unique_dst_ips"  : unique_dst_ips,
        "bytes_per_second": bytes_per_second,
        "packets_per_sec" : packets_per_sec,
        "top_destinations": top_destinations,
        "port_counts"     : dict(port_counts),
    }


def set_alert(reason: str):
    """Called by the anomaly detector on Day 6 to trigger an alert."""
    global _alert_triggered, _alert_reason
    _alert_triggered = True
    _alert_reason    = reason
    print(f"[monitor] ALERT TRIGGERED: {reason}")


# ── Self test ──────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import urllib.request

    print("=" * 55)
    print("  NETWORK MONITOR — LIVE CAPTURE TEST")
    print("=" * 55)
    print("\nThis test will:")
    print("  1. Start the packet sniffer")
    print("  2. Make 3 real HTTP requests to generate traffic")
    print("  3. Wait 15 seconds")
    print("  4. Stop and show what was captured\n")

    # Start monitoring
    start_monitoring()
    print("\n[test] Sniffer running — generating test traffic...\n")

    # Generate some real outgoing traffic
    test_urls = [
        "http://example.com",
        "http://httpbin.org/get",
        "http://neverssl.com",
    ]

    for url in test_urls:
        try:
            urllib.request.urlopen(url, timeout=5)
            print(f"[test] Request sent to: {url}")
        except Exception as e:
            print(f"[test] Request failed (still generates packets): {url}")

    # Wait for packets to accumulate
    print("\n[test] Capturing for 15 seconds...")
    for i in range(15, 0, -1):
        time.sleep(1)
        status = get_status()
        print(f"  {i:2}s remaining — "
              f"packets: {status['total_packets']:4}  "
              f"bytes: {status['total_bytes']:8}  "
              f"unique IPs: {status['unique_dst_ips']}", end="\r")

    print()

    # Stop
    stop_monitoring()

    # Show summary
    summary = get_traffic_summary()
    status  = get_status()

    print(f"\n{'=' * 55}")
    print(f"  CAPTURE SUMMARY")
    print(f"{'=' * 55}")
    print(f"  Total packets    : {summary['total_packets']}")
    print(f"  Total bytes      : {summary['total_bytes']:,}")
    print(f"  Unique dest IPs  : {summary['unique_dst_ips']}")
    print(f"  Bytes / second   : {summary['bytes_per_second']}")
    print(f"  Packets / second : {summary['packets_per_sec']}")

    if summary["top_destinations"]:
        print(f"\n  Top destination IPs:")
        for ip, count in summary["top_destinations"]:
            print(f"    {ip:<20} {count} packets")

    if summary["port_counts"]:
        print(f"\n  Ports contacted:")
        sorted_ports = sorted(
            summary["port_counts"].items(),
            key=lambda x: x[1], reverse=True
        )[:5]
        for port, count in sorted_ports:
            print(f"    Port {port:<8} {count} packets")

    print(f"\n{'=' * 55}")

    if summary["total_packets"] > 0:
        print(f"  monitor.py working correctly.")
        print(f"  Packets captured successfully.")
    else:
        print(f"  WARNING: Zero packets captured.")
        print(f"  Make sure VS Code is running as Administrator.")

    print(f"{'=' * 55}")