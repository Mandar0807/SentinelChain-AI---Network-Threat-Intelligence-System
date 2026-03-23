import threading
import time
import urllib.request
import socket

def simulate_exfiltration(duration_seconds: int = 20):
    """
    Simulates data exfiltration behavior on the network.
    Makes rapid connections to multiple external endpoints.
    This generates the kind of traffic pattern our anomaly
    detector is trained to catch.

    IMPORTANT: This only makes real HTTP requests to public
    servers. No actual data is stolen. This is purely for
    testing the detection system.
    """

    # Public endpoints to hit rapidly — simulates C2 communication
    targets = [
        "http://example.com",
        "http://httpbin.org/get",
        "http://icanhazip.com",
        "http://ifconfig.me",
        "http://api.ipify.org",
        "http://checkip.amazonaws.com",
        "http://ip.42.pl/raw",
        "http://jsonip.com",
        "http://wtfismyip.com/text",
        "http://ident.me",
    ]

    print(f"[simulator] Starting exfiltration simulation...")
    print(f"[simulator] Will run for {duration_seconds} seconds")
    print(f"[simulator] Making rapid requests to {len(targets)} targets")

    start     = time.time()
    count     = 0
    errors    = 0

    while time.time() - start < duration_seconds:
        for target in targets:
            try:
                req = urllib.request.Request(
                    target,
                    headers={"User-Agent": "Mozilla/5.0"}
                )
                urllib.request.urlopen(req, timeout=2)
                count += 1
            except Exception:
                errors += 1
                # Even failed requests generate packets — DNS + TCP SYN
                pass

        # No sleep — rapid fire to simulate burst traffic
        elapsed = round(time.time() - start, 1)
        print(f"[simulator] {elapsed}s — requests: {count}, "
              f"errors: {errors}", end="\r")

    print(f"\n[simulator] Done — {count} requests in {duration_seconds}s")
    return count