// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract ThreatLog {

    struct LogEntry {
        uint256 id;
        string  threat_type;
        string  source;
        string  file_hash;
        string  verdict;
        uint256 risk_score;
        uint256 timestamp;
    }

    LogEntry[] private logs;
    address    public  owner;
    uint256    private counter;

    event ThreatLogged(
        uint256 indexed id,
        string  threat_type,
        string  source,
        uint256 timestamp
    );

    constructor() {
        owner   = msg.sender;
        counter = 0;
    }

    function addLog(
        string memory _threat_type,
        string memory _source,
        string memory _file_hash,
        string memory _verdict,
        uint256       _risk_score
    ) public {
        counter++;

        LogEntry memory entry = LogEntry({
            id          : counter,
            threat_type : _threat_type,
            source      : _source,
            file_hash   : _file_hash,
            verdict     : _verdict,
            risk_score  : _risk_score,
            timestamp   : block.timestamp
        });

        logs.push(entry);

        emit ThreatLogged(counter, _threat_type, _source, block.timestamp);
    }

    function getLogCount() public view returns (uint256) {
        return logs.length;
    }

    function getLog(uint256 index) public view returns (
        uint256 id,
        string memory threat_type,
        string memory source,
        string memory file_hash,
        string memory verdict,
        uint256 risk_score,
        uint256 timestamp
    ) {
        require(index < logs.length, "Index out of bounds");
        LogEntry memory e = logs[index];
        return (
            e.id,
            e.threat_type,
            e.source,
            e.file_hash,
            e.verdict,
            e.risk_score,
            e.timestamp
        );
    }

    function getRecentLogs(uint256 n) public view returns (
        uint256[] memory ids,
        string[]  memory threat_types,
        string[]  memory sources,
        string[]  memory verdicts,
        uint256[] memory timestamps
    ) {
        uint256 total  = logs.length;
        uint256 count  = n > total ? total : n;
        uint256 start  = total - count;

        ids          = new uint256[](count);
        threat_types = new string[](count);
        sources      = new string[](count);
        verdicts     = new string[](count);
        timestamps   = new uint256[](count);

        for (uint256 i = 0; i < count; i++) {
            LogEntry memory e = logs[start + i];
            ids[i]          = e.id;
            threat_types[i] = e.threat_type;
            sources[i]      = e.source;
            verdicts[i]     = e.verdict;
            timestamps[i]   = e.timestamp;
        }
    }
}