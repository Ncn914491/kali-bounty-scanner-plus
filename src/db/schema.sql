-- Database schema for Kali Bounty Scanner Plus

-- Scan runs
CREATE TABLE IF NOT EXISTS runs (
    run_id TEXT PRIMARY KEY,
    target TEXT NOT NULL,
    mode TEXT NOT NULL,
    output_dir TEXT NOT NULL,
    start_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    end_time TIMESTAMP,
    status TEXT DEFAULT 'running',
    findings_count INTEGER DEFAULT 0
);

-- Findings
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL,
    target TEXT NOT NULL,
    name TEXT NOT NULL,
    severity TEXT,
    description TEXT,
    evidence TEXT,
    ml_score REAL,
    llm_score REAL,
    final_score REAL,
    confidence REAL,
    is_false_positive BOOLEAN DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (run_id) REFERENCES runs(run_id)
);

-- Policy decisions (audit trail)
CREATE TABLE IF NOT EXISTS policy_decisions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target TEXT NOT NULL,
    action TEXT NOT NULL,
    decision TEXT NOT NULL,
    reason TEXT,
    confidence REAL,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- LLM responses (optional, for audit)
CREATE TABLE IF NOT EXISTS llm_responses (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    prompt TEXT NOT NULL,
    response TEXT NOT NULL,
    model TEXT DEFAULT 'gemini-1.5-flash',
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_findings_run_id ON findings(run_id);
CREATE INDEX IF NOT EXISTS idx_findings_score ON findings(final_score DESC);
CREATE INDEX IF NOT EXISTS idx_policy_target ON policy_decisions(target);
CREATE INDEX IF NOT EXISTS idx_policy_timestamp ON policy_decisions(timestamp);
