CREATE TABLE IF NOT EXISTS missions (
  id INTEGER PRIMARY KEY,
  target_id TEXT NOT NULL,
  request_message TEXT NOT NULL,
  model TEXT NOT NULL,
  policy_hashes TEXT NOT NULL,
  arsenal TEXT NOT NULL,
  started_at TEXT NOT NULL,
  ended_at TEXT,
  status TEXT NOT NULL DEFAULT 'running'
    CHECK (status IN ('running','completed','stopped','emergency_stop','failed')),
  stop_reason TEXT
);

CREATE TABLE IF NOT EXISTS actions (
  id INTEGER PRIMARY KEY,
  mission_id INTEGER NOT NULL REFERENCES missions(id),
  step INTEGER NOT NULL,
  tool TEXT NOT NULL,
  target_id TEXT,
  parameters TEXT NOT NULL,
  level_proposed TEXT,
  level_assigned TEXT CHECK (level_assigned IN ('N0','N1','N2','N3')),
  justification TEXT,
  expected_evidence TEXT,
  status TEXT NOT NULL DEFAULT 'proposed'
    CHECK (status IN ('proposed','blocked','cleared','pending_approval','approved',
                      'refused','executed','failed','timed_out')),
  blocked_by TEXT,
  proposed_at TEXT NOT NULL,
  UNIQUE (mission_id, step)
);

CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY,
  mission_id INTEGER NOT NULL REFERENCES missions(id),
  ts TEXT NOT NULL,
  actor TEXT NOT NULL CHECK (actor IN ('llm','guardrail','tool','operator','system')),
  type TEXT NOT NULL,
  action_id INTEGER REFERENCES actions(id),
  payload TEXT NOT NULL,
  prev_hash TEXT NOT NULL,
  hash TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_mission ON events(mission_id, id);

CREATE TABLE IF NOT EXISTS approvals (
  id INTEGER PRIMARY KEY,
  action_id INTEGER NOT NULL REFERENCES actions(id),
  requested_at TEXT NOT NULL,
  shown_command TEXT NOT NULL,
  risk_text TEXT NOT NULL,
  decided_at TEXT,
  decision TEXT CHECK (decision IN ('approved','refused','modified','timeout')),
  operator TEXT,
  comment TEXT,
  original_parameters TEXT,
  modified_parameters TEXT
);

CREATE TABLE IF NOT EXISTS executions (
  id INTEGER PRIMARY KEY,
  action_id INTEGER NOT NULL REFERENCES actions(id),
  argv TEXT NOT NULL,
  started_at TEXT NOT NULL,
  ended_at TEXT NOT NULL,
  duration_ms INTEGER NOT NULL,
  exit_code INTEGER,
  timed_out INTEGER NOT NULL DEFAULT 0,
  stdout TEXT,
  stderr TEXT,
  stdout_sha256 TEXT,
  truncated INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS llm_calls (
  id INTEGER PRIMARY KEY,
  mission_id INTEGER NOT NULL REFERENCES missions(id),
  step INTEGER NOT NULL,
  attempt INTEGER NOT NULL,
  ts TEXT NOT NULL,
  model TEXT NOT NULL,
  prompt_sha256 TEXT NOT NULL,
  response_raw TEXT,
  valid INTEGER NOT NULL,
  error TEXT,
  duration_ms INTEGER
);

CREATE TABLE IF NOT EXISTS hosts (
  id INTEGER PRIMARY KEY,
  mission_id INTEGER NOT NULL REFERENCES missions(id),
  ip TEXT NOT NULL,
  hostname TEXT,
  os TEXT,
  first_seen TEXT NOT NULL,
  UNIQUE (mission_id, ip)
);

CREATE TABLE IF NOT EXISTS services (
  id INTEGER PRIMARY KEY,
  host_id INTEGER NOT NULL REFERENCES hosts(id),
  port INTEGER NOT NULL,
  proto TEXT NOT NULL DEFAULT 'tcp',
  name TEXT,
  product TEXT,
  version TEXT,
  execution_id INTEGER REFERENCES executions(id),
  first_seen TEXT NOT NULL,
  UNIQUE (host_id, port, proto)
);

CREATE TABLE IF NOT EXISTS observations (
  id INTEGER PRIMARY KEY,
  mission_id INTEGER NOT NULL REFERENCES missions(id),
  kind TEXT NOT NULL
    CHECK (kind IN ('observation','hypothesis','injection_attempt','out_of_scope_discovery')),
  subject TEXT,
  content TEXT NOT NULL,
  execution_id INTEGER REFERENCES executions(id),
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS tasks (
  id INTEGER PRIMARY KEY,
  mission_id INTEGER NOT NULL REFERENCES missions(id),
  description TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending'
    CHECK (status IN ('pending','in_progress','done','dropped')),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS cve_cache (
  query TEXT PRIMARY KEY,
  response TEXT NOT NULL,
  fetched_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS findings (
  id INTEGER PRIMARY KEY,
  mission_id INTEGER NOT NULL REFERENCES missions(id),
  title TEXT NOT NULL,
  category TEXT,
  host TEXT,
  port INTEGER,
  cve_id TEXT,
  cve_execution_id INTEGER REFERENCES executions(id),
  cvss_score REAL,
  cvss_source TEXT NOT NULL DEFAULT 'none'
    CHECK (cvss_source IN ('cve_lookup','estimated','none')),
  confidence TEXT NOT NULL CHECK (confidence IN ('confirmed','probable','to_verify')),
  evidence_execution_id INTEGER NOT NULL REFERENCES executions(id),
  evidence_excerpt TEXT NOT NULL,
  remediation TEXT,
  created_at TEXT NOT NULL,
  CHECK (cve_id IS NULL OR cve_execution_id IS NOT NULL),
  CHECK (cvss_source <> 'cve_lookup' OR cve_execution_id IS NOT NULL)
);

CREATE TRIGGER IF NOT EXISTS events_no_update BEFORE UPDATE ON events
BEGIN SELECT RAISE(ABORT, 'events are append-only'); END;
CREATE TRIGGER IF NOT EXISTS events_no_delete BEFORE DELETE ON events
BEGIN SELECT RAISE(ABORT, 'events are append-only'); END;

CREATE TRIGGER IF NOT EXISTS executions_no_update BEFORE UPDATE ON executions
BEGIN SELECT RAISE(ABORT, 'executions are immutable'); END;
CREATE TRIGGER IF NOT EXISTS executions_no_delete BEFORE DELETE ON executions
BEGIN SELECT RAISE(ABORT, 'executions are immutable'); END;

CREATE TRIGGER IF NOT EXISTS llm_calls_no_update BEFORE UPDATE ON llm_calls
BEGIN SELECT RAISE(ABORT, 'llm_calls are immutable'); END;
CREATE TRIGGER IF NOT EXISTS llm_calls_no_delete BEFORE DELETE ON llm_calls
BEGIN SELECT RAISE(ABORT, 'llm_calls are immutable'); END;

CREATE TRIGGER IF NOT EXISTS approvals_no_delete BEFORE DELETE ON approvals
BEGIN SELECT RAISE(ABORT, 'approvals cannot be deleted'); END;
CREATE TRIGGER IF NOT EXISTS approvals_decision_final BEFORE UPDATE ON approvals
WHEN OLD.decision IS NOT NULL
BEGIN SELECT RAISE(ABORT, 'a decision cannot be changed'); END;

CREATE TRIGGER IF NOT EXISTS actions_no_delete BEFORE DELETE ON actions
BEGIN SELECT RAISE(ABORT, 'actions cannot be deleted'); END;
CREATE TRIGGER IF NOT EXISTS actions_blocked_final BEFORE UPDATE OF status ON actions
WHEN OLD.status = 'blocked'
BEGIN SELECT RAISE(ABORT, 'a blocked action cannot be reopened'); END;
