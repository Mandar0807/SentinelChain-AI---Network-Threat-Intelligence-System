import time
import threading
import monitor
import anomaly_detector

def run_live_test():
    print("=" * 60)
    print("  LIVE END-TO-END DETECTION TEST")
    print("=" * 60)
    print("\nThis test will:")
    print("  1. Start the network monitor")
    print("  2. Run the exfil simulator for 20 seconds")
    print("  3. Check for anomalies every 5 seconds")
    print("  4. Report whether the attack was detected\n")

    input("Press ENTER to start the test...")

    # ── Phase 1: Capture baseline (10 seconds normal traffic) ──────────────
    print("\n[Phase 1] Capturing baseline normal traffic for 10 seconds...")
    monitor.start_monitoring()
    time.sleep(10)

    baseline = monitor.get_traffic_summary()
    print(f"  Baseline: {baseline['total_packets']} packets, "
          f"{baseline['unique_dst_ips']} unique IPs, "
          f"{baseline['bytes_per_second']} bytes/sec")

    baseline_result = anomaly_detector.analyse_traffic(baseline)
    print(f"  Baseline verdict: {baseline_result['verdict']}")

    # ── Phase 2: Run exfil simulator ───────────────────────────────────────
    print("\n[Phase 2] Starting exfiltration simulator...")
    print("  Watch the packet counts spike...\n")

    from exfil_simulator import simulate_exfiltration
    sim_thread = threading.Thread(
        target   = simulate_exfiltration,
        args     = (20,),
        daemon   = True
    )
    sim_thread.start()

    # ── Phase 3: Check for anomalies every 5 seconds ───────────────────────
    print("\n[Phase 3] Monitoring for anomalies...")
    detected    = False
    check_count = 0

    for check in range(4):
        time.sleep(5)
        check_count += 1
        summary = monitor.get_traffic_summary()
        result  = anomaly_detector.analyse_traffic(summary)

        print(f"\n  Check {check_count}/4 at {check_count * 5}s:")
        print(f"    Packets    : {summary['total_packets']}")
        print(f"    Unique IPs : {summary['unique_dst_ips']}")
        print(f"    Bytes/sec  : {summary['bytes_per_second']}")
        print(f"    Verdict    : {result['verdict']}")

        if result["is_anomaly"]:
            detected = True
            monitor.set_alert(
                f"Anomaly detected at check {check_count}: "
                + (result['flags'][0] if result['flags'] else result['verdict'])
            )
            print(f"    *** ANOMALY DETECTED ***")
            if result["flags"]:
                for flag in result["flags"]:
                    print(f"    FLAG: {flag}")

    # ── Wait for simulator to finish ───────────────────────────────────────
    sim_thread.join(timeout=25)

    # ── Stop monitoring ────────────────────────────────────────────────────
    monitor.stop_monitoring()

    # ── Final report ───────────────────────────────────────────────────────
    final_summary = monitor.get_traffic_summary()
    final_status  = monitor.get_status()

    print(f"\n{'=' * 60}")
    print(f"  FINAL TEST REPORT")
    print(f"{'=' * 60}")
    print(f"  Total packets captured : {final_summary['total_packets']}")
    print(f"  Total bytes            : {final_summary['total_bytes']:,}")
    print(f"  Unique IPs contacted   : {final_summary['unique_dst_ips']}")
    print(f"  Peak bytes/sec         : {final_summary['bytes_per_second']}")
    print(f"  Alert triggered        : {final_status['alert_triggered']}")

    if final_status["alert_triggered"]:
        print(f"  Alert reason           : {final_status['alert_reason']}")

    print(f"\n{'=' * 60}")
    if detected:
        print(f"  RESULT: [✓] ATTACK DETECTED SUCCESSFULLY")
        print(f"  The anomaly detector caught the simulated exfiltration.")
    else:
        print(f"  RESULT: [!] Attack not detected in this run.")
        print(f"  Try running again — network conditions vary.")
    print(f"{'=' * 60}")


if __name__ == "__main__":
    run_live_test()