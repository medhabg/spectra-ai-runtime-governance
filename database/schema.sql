-- =============================================================================
-- database/schema.sql
-- Local LLM Hunter — SQLite schema definition
-- =============================================================================
-- Tables:
--   detection_events  : Full AIRuntimeEvent records from the detection pipeline
--   scan_history      : Metadata for each completed scan pass
--   ai_inventory      : Running inventory of observed LLM runtimes per host
--   alerts            : Alert records derived from high/critical detection events
-- =============================================================================


-- ---------------------------------------------------------------------------
-- detection_events
-- One row per AIRuntimeEvent emitted by the agent.
-- lib_match and signals_fired are stored as JSON strings.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS detection_events (
    event_id             TEXT PRIMARY KEY,          -- UUID from AIRuntimeEvent
    host                 TEXT NOT NULL,             -- endpoint hostname
    runtime              TEXT NOT NULL,             -- e.g. 'ollama', 'lm-studio'
    model_file           TEXT,                      -- path to detected model file
    port_detected        INTEGER,                   -- TCP port, if detected
    gpu_spike            INTEGER NOT NULL DEFAULT 0,-- 0/1 boolean
    lib_match            TEXT NOT NULL DEFAULT '[]',-- JSON array of matched libs
    risk_score           TEXT NOT NULL,             -- LOW|MEDIUM|HIGH|CRITICAL
    timestamp            TEXT NOT NULL,             -- ISO-8601 UTC
    user_id              TEXT NOT NULL,             -- OS user running the runtime
    department           TEXT NOT NULL,             -- org department
    approval_status      TEXT NOT NULL,             -- approved|unapproved|pending
    policy_violation     INTEGER NOT NULL DEFAULT 0,-- 0/1 boolean
    vuln_flag            INTEGER NOT NULL DEFAULT 0,-- 0/1 boolean
    signals_fired        TEXT NOT NULL DEFAULT '{}',-- JSON map {signal_name: bool}
    signal_count         INTEGER NOT NULL DEFAULT 0,
    endpoint_criticality INTEGER NOT NULL DEFAULT 0 -- 0/1 boolean
);

-- Index for dashboard queries filtered by host or time window
CREATE INDEX IF NOT EXISTS idx_events_host      ON detection_events(host);
CREATE INDEX IF NOT EXISTS idx_events_timestamp ON detection_events(timestamp);
CREATE INDEX IF NOT EXISTS idx_events_risk      ON detection_events(risk_score);


-- ---------------------------------------------------------------------------
-- scan_history
-- One row per completed agent scan pass.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS scan_history (
    scan_id              TEXT PRIMARY KEY,          -- UUID for the scan run
    host                 TEXT NOT NULL,             -- endpoint hostname
    scan_time            TEXT NOT NULL,             -- ISO-8601 UTC start time
    duration_ms          INTEGER NOT NULL DEFAULT 0,-- wall-clock scan duration
    runtimes_found       INTEGER NOT NULL DEFAULT 0,-- number of runtimes detected
    total_signals_fired  INTEGER NOT NULL DEFAULT 0 -- sum of all signals that fired
);

CREATE INDEX IF NOT EXISTS idx_scan_host ON scan_history(host);


-- ---------------------------------------------------------------------------
-- ai_inventory
-- Deduplicated view of active/resolved LLM runtimes across endpoints.
-- Upserted on (host, runtime) so each runtime per host has one live row.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ai_inventory (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    host        TEXT NOT NULL,
    runtime     TEXT NOT NULL,
    model_file  TEXT,
    last_seen   TEXT NOT NULL,                      -- ISO-8601 UTC
    status      TEXT NOT NULL DEFAULT 'active',     -- active | resolved
    UNIQUE(host, runtime)
);

CREATE INDEX IF NOT EXISTS idx_inventory_host   ON ai_inventory(host);
CREATE INDEX IF NOT EXISTS idx_inventory_status ON ai_inventory(status);


-- ---------------------------------------------------------------------------
-- alerts
-- Alert records created from HIGH/CRITICAL detection events.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS alerts (
    alert_id    TEXT PRIMARY KEY,                   -- UUID for the alert
    event_id    TEXT NOT NULL,                      -- FK → detection_events.event_id
    risk_level  TEXT NOT NULL,                      -- HIGH | CRITICAL
    alerted_at  TEXT NOT NULL,                      -- ISO-8601 UTC
    resolved    INTEGER NOT NULL DEFAULT 0,         -- 0=open, 1=resolved
    FOREIGN KEY (event_id) REFERENCES detection_events(event_id)
);

CREATE INDEX IF NOT EXISTS idx_alerts_event_id ON alerts(event_id);
CREATE INDEX IF NOT EXISTS idx_alerts_resolved ON alerts(resolved);
