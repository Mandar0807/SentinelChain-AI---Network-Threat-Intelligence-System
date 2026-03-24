import hashlib
import datetime
from web3 import Web3
from contract_config import CONTRACT_ADDRESS, CONTRACT_ABI

# ── Connect to Ganache ─────────────────────────────────────────────────────
GANACHE_URL = "http://127.0.0.1:7545"

def _get_connection():
    """Create and return a web3 connection to Ganache."""
    w3 = Web3(Web3.HTTPProvider(GANACHE_URL))
    if not w3.is_connected():
        raise ConnectionError(
            "Cannot connect to Ganache. "
            "Make sure Ganache is running on port 7545."
        )
    return w3


def _get_contract(w3):
    """Return the deployed ThreatLog contract instance."""
    return w3.eth.contract(
        address = Web3.to_checksum_address(CONTRACT_ADDRESS),
        abi     = CONTRACT_ABI
    )


def compute_hash(data: str) -> str:
    """
    Compute a SHA-256 hash of any string.
    Used to create a fingerprint of the threat source
    (URL or file path) for the blockchain record.
    """
    return hashlib.sha256(data.encode()).hexdigest()


# ── Write a threat log to the blockchain ──────────────────────────────────
def log_threat(
    threat_type : str,
    source      : str,
    verdict     : str,
    risk_score  : int = 0
) -> dict:
    """
    Write a threat event to the blockchain.
    Called by pre_check.py (Stage 1) and monitor.py (Stage 2).

    Parameters:
        threat_type : "URL_THREAT" or "FILE_THREAT" or "NETWORK_ANOMALY"
        source      : the URL, file path, or IP address
        verdict     : "MALICIOUS", "SUSPICIOUS", or "ANOMALY DETECTED"
        risk_score  : integer 0-100

    Returns a dict with transaction details.
    """
    try:
        w3          = _get_connection()
        contract    = _get_contract(w3)
        account     = w3.eth.accounts[0]
        file_hash   = compute_hash(source)

        # Send transaction to blockchain
        tx_hash = contract.functions.addLog(
            threat_type,
            source[:200],       # truncate very long URLs
            file_hash,
            verdict,
            int(risk_score)
        ).transact({"from": account})

        # Wait for transaction to be mined
        receipt = w3.eth.wait_for_transaction_receipt(tx_hash)

        result = {
            "success"     : True,
            "tx_hash"     : tx_hash.hex(),
            "block_number": receipt["blockNumber"],
            "file_hash"   : file_hash,
            "threat_type" : threat_type,
            "source"      : source,
            "verdict"     : verdict,
            "risk_score"  : risk_score,
            "timestamp"   : datetime.datetime.now().strftime(
                                "%Y-%m-%d %H:%M:%S"
                            ),
        }

        print(f"[blockchain] Logged — {verdict} | {threat_type} | "
              f"block #{receipt['blockNumber']}")
        return result

    except Exception as e:
        print(f"[blockchain] ERROR: {e}")
        return {
            "success" : False,
            "error"   : str(e),
            "source"  : source,
            "verdict" : verdict,
        }


# ── Read all logs from the blockchain ─────────────────────────────────────
def get_all_logs() -> list:
    """
    Read all threat log entries from the blockchain.
    Returns a list of dicts, newest first.
    """
    try:
        w3       = _get_connection()
        contract = _get_contract(w3)
        count    = contract.functions.getLogCount().call()

        if count == 0:
            return []

        logs = []
        for i in range(count):
            entry = contract.functions.getLog(i).call()
            logs.append({
                "id"         : entry[0],
                "threat_type": entry[1],
                "source"     : entry[2],
                "file_hash"  : entry[3],
                "verdict"    : entry[4],
                "risk_score" : entry[5],
                "timestamp"  : datetime.datetime.fromtimestamp(
                                   entry[6]
                               ).strftime("%Y-%m-%d %H:%M:%S"),
            })

        # Return newest first
        return list(reversed(logs))

    except Exception as e:
        print(f"[blockchain] ERROR reading logs: {e}")
        return []


def get_log_count() -> int:
    """Return total number of threat logs on the blockchain."""
    try:
        w3       = _get_connection()
        contract = _get_contract(w3)
        return contract.functions.getLogCount().call()
    except Exception as e:
        print(f"[blockchain] ERROR getting count: {e}")
        return 0


def print_logs():
    """Pretty print all blockchain logs."""
    logs = get_all_logs()
    print(f"\n{'=' * 65}")
    print(f"  BLOCKCHAIN THREAT LOGS")
    print(f"{'=' * 65}")
    print(f"  Total records: {len(logs)}")
    print(f"{'=' * 65}")
    if not logs:
        print("  No logs found.")
    else:
        for log in logs:
            print(f"\n  ID          : {log['id']}")
            print(f"  Timestamp   : {log['timestamp']}")
            print(f"  Verdict     : {log['verdict']}")
            print(f"  Threat type : {log['threat_type']}")
            print(f"  Source      : {log['source']}")
            print(f"  Risk score  : {log['risk_score']}")
            print(f"  File hash   : {log['file_hash'][:32]}...")
            print(f"  {'-' * 60}")
    print(f"{'=' * 65}")


# ── Self test ──────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("=" * 65)
    print("  BLOCKCHAIN LOGGER — CONNECTION + WRITE TEST")
    print("=" * 65)

    # Test connection
    print("\n[1/4] Testing Ganache connection...")
    try:
        w3 = _get_connection()
        print(f"  Connected — chain ID: {w3.eth.chain_id}")
        print(f"  Accounts  : {len(w3.eth.accounts)}")
        print(f"  Balance   : "
              f"{w3.from_wei(w3.eth.get_balance(w3.eth.accounts[0]), 'ether')}"
              f" ETH")
    except Exception as e:
        print(f"  FAILED: {e}")
        exit(1)

    # Test writing logs
    print("\n[2/4] Writing test threat logs to blockchain...")

    result1 = log_threat(
        threat_type = "URL_THREAT",
        source      = "http://192.168.1.1/login/verify?user=admin@bank.com",
        verdict     = "MALICIOUS",
        risk_score  = 90
    )
    print(f"  Log 1: {'OK' if result1['success'] else 'FAILED'} — "
          f"tx: {result1.get('tx_hash', 'N/A')[:20]}...")

    result2 = log_threat(
        threat_type = "FILE_THREAT",
        source      = "tests/fake.pdf",
        verdict     = "MALICIOUS",
        risk_score  = 50
    )
    print(f"  Log 2: {'OK' if result2['success'] else 'FAILED'} — "
          f"tx: {result2.get('tx_hash', 'N/A')[:20]}...")

    result3 = log_threat(
        threat_type = "NETWORK_ANOMALY",
        source      = "192.168.1.5",
        verdict     = "ANOMALY DETECTED",
        risk_score  = 75
    )
    print(f"  Log 3: {'OK' if result3['success'] else 'FAILED'} — "
          f"tx: {result3.get('tx_hash', 'N/A')[:20]}...")

    # Test reading logs
    print("\n[3/4] Reading logs back from blockchain...")
    count = get_log_count()
    print(f"  Total logs on chain: {count}")

    # Print all logs
    print("\n[4/4] Full log display:")
    print_logs()

    print("\n" + "=" * 65)
    if count >= 3:
        print("  blockchain.py working correctly.")
        print("  Threat events stored permanently on Ganache blockchain.")
    else:
        print("  WARNING: Expected 3 logs but found fewer.")
        print("  Check contract address in contract_config.py")
    print("=" * 65)