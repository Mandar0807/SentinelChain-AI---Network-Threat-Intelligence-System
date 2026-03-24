CONTRACT_ADDRESS = "0x78d942867367e86C518E2e97f9dfE688ea9ac34c"

CONTRACT_ABI = [
    {
        "inputs": [
            {"internalType": "string", "name": "_threat_type", "type": "string"},
            {"internalType": "string", "name": "_source",      "type": "string"},
            {"internalType": "string", "name": "_file_hash",   "type": "string"},
            {"internalType": "string", "name": "_verdict",     "type": "string"},
            {"internalType": "uint256","name": "_risk_score",  "type": "uint256"}
        ],
        "name": "addLog",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function"
    },
    {
        "inputs": [],
        "stateMutability": "nonpayable",
        "type": "constructor"
    },
    {
        "anonymous": False,
        "inputs": [
            {"indexed": True,  "internalType": "uint256", "name": "id",          "type": "uint256"},
            {"indexed": False, "internalType": "string",  "name": "threat_type", "type": "string"},
            {"indexed": False, "internalType": "string",  "name": "source",      "type": "string"},
            {"indexed": False, "internalType": "uint256", "name": "timestamp",   "type": "uint256"}
        ],
        "name": "ThreatLogged",
        "type": "event"
    },
    {
        "inputs": [
            {"internalType": "uint256", "name": "index", "type": "uint256"}
        ],
        "name": "getLog",
        "outputs": [
            {"internalType": "uint256", "name": "id",          "type": "uint256"},
            {"internalType": "string",  "name": "threat_type", "type": "string"},
            {"internalType": "string",  "name": "source",      "type": "string"},
            {"internalType": "string",  "name": "file_hash",   "type": "string"},
            {"internalType": "string",  "name": "verdict",     "type": "string"},
            {"internalType": "uint256", "name": "risk_score",  "type": "uint256"},
            {"internalType": "uint256", "name": "timestamp",   "type": "uint256"}
        ],
        "stateMutability": "view",
        "type": "function"
    },
    {
        "inputs": [],
        "name": "getLogCount",
        "outputs": [
            {"internalType": "uint256", "name": "", "type": "uint256"}
        ],
        "stateMutability": "view",
        "type": "function"
    },
    {
        "inputs": [
            {"internalType": "uint256", "name": "n", "type": "uint256"}
        ],
        "name": "getRecentLogs",
        "outputs": [
            {"internalType": "uint256[]", "name": "ids",          "type": "uint256[]"},
            {"internalType": "string[]",  "name": "threat_types", "type": "string[]"},
            {"internalType": "string[]",  "name": "sources",      "type": "string[]"},
            {"internalType": "string[]",  "name": "verdicts",     "type": "string[]"},
            {"internalType": "uint256[]", "name": "timestamps",   "type": "uint256[]"}
        ],
        "stateMutability": "view",
        "type": "function"
    },
    {
        "inputs": [],
        "name": "owner",
        "outputs": [
            {"internalType": "address", "name": "", "type": "address"}
        ],
        "stateMutability": "view",
        "type": "function"
    }
]