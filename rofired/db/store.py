import hashlib
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

SCHEMA = Path(__file__).with_name("schema.sql")
GENESIS = "0" * 64
MAX_OUTPUT = 2_000_000


def now():
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def dumps(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


class Store:
    def __init__(self, path):
        self.con = sqlite3.connect(path, timeout=5)
        self.con.row_factory = sqlite3.Row
        self.con.execute("PRAGMA journal_mode=WAL")
        self.con.execute("PRAGMA synchronous=FULL")
        self.con.execute("PRAGMA foreign_keys=ON")
        self.con.executescript(SCHEMA.read_text(encoding="utf-8"))

    def close(self):
        self.con.close()

    def _event(self, mission_id, actor, type_, payload, action_id=None):
        row = self.con.execute(
            "SELECT hash FROM events WHERE mission_id=? ORDER BY id DESC LIMIT 1",
            (mission_id,),
        ).fetchone()
        prev = row["hash"] if row else GENESIS
        ts = now()
        body = dumps(payload)
        digest = sha256(dumps([mission_id, ts, actor, type_, action_id, body, prev]))
        cur = self.con.execute(
            "INSERT INTO events (mission_id, ts, actor, type, action_id, payload, prev_hash, hash)"
            " VALUES (?,?,?,?,?,?,?,?)",
            (mission_id, ts, actor, type_, action_id, body, prev, digest),
        )
        return cur.lastrowid

    def log(self, mission_id, actor, type_, payload, action_id=None):
        with self.con:
            return self._event(mission_id, actor, type_, payload, action_id)

    def start_mission(self, target_id, request_message, model, policy_hashes, arsenal):
        with self.con:
            cur = self.con.execute(
                "INSERT INTO missions (target_id, request_message, model, policy_hashes,"
                " arsenal, started_at) VALUES (?,?,?,?,?,?)",
                (
                    target_id,
                    request_message,
                    model,
                    dumps(policy_hashes),
                    dumps(arsenal),
                    now(),
                ),
            )
            mid = cur.lastrowid
            self._event(
                mid,
                "system",
                "mission_started",
                {
                    "target_id": target_id,
                    "model": model,
                    "policy_hashes": policy_hashes,
                    "arsenal": arsenal,
                },
            )
            return mid

    def end_mission(self, mission_id, status, reason=None):
        with self.con:
            self.con.execute(
                "UPDATE missions SET status=?, stop_reason=?, ended_at=? WHERE id=?",
                (status, reason, now(), mission_id),
            )
            actor = "operator" if status == "emergency_stop" else "system"
            self._event(
                mission_id, actor, "mission_ended", {"status": status, "reason": reason}
            )

    def record_llm_call(
        self,
        mission_id,
        step,
        attempt,
        model,
        prompt,
        response_raw,
        valid,
        error=None,
        duration_ms=None,
    ):
        with self.con:
            cur = self.con.execute(
                "INSERT INTO llm_calls (mission_id, step, attempt, ts, model, prompt_sha256,"
                " response_raw, valid, error, duration_ms) VALUES (?,?,?,?,?,?,?,?,?,?)",
                (
                    mission_id,
                    step,
                    attempt,
                    now(),
                    model,
                    sha256(prompt),
                    response_raw,
                    int(valid),
                    error,
                    duration_ms,
                ),
            )
            self._event(
                mission_id,
                "llm",
                "llm_response" if valid else "llm_invalid_output",
                {"step": step, "attempt": attempt, "error": error},
            )
            return cur.lastrowid

    def propose_action(
        self,
        mission_id,
        step,
        tool,
        target_id,
        parameters,
        level_proposed,
        justification,
        expected_evidence,
    ):
        with self.con:
            cur = self.con.execute(
                "INSERT INTO actions (mission_id, step, tool, target_id, parameters,"
                " level_proposed, justification, expected_evidence, proposed_at)"
                " VALUES (?,?,?,?,?,?,?,?,?)",
                (
                    mission_id,
                    step,
                    tool,
                    target_id,
                    dumps(parameters),
                    level_proposed,
                    justification,
                    expected_evidence,
                    now(),
                ),
            )
            aid = cur.lastrowid
            self._event(
                mission_id,
                "llm",
                "action_proposed",
                {
                    "tool": tool,
                    "target_id": target_id,
                    "parameters": parameters,
                    "level": level_proposed,
                    "justification": justification,
                },
                aid,
            )
            return aid

    def guardrail_verdict(
        self, action_id, level_assigned, allowed, rule=None, reason=None
    ):
        with self.con:
            mid = self._mission_of(action_id)
            if not allowed or level_assigned == "N3":
                status = "blocked"
            elif level_assigned == "N2":
                status = "pending_approval"
            else:
                status = "cleared"
            self.con.execute(
                "UPDATE actions SET level_assigned=?, status=?, blocked_by=? WHERE id=?",
                (
                    level_assigned,
                    status,
                    rule if status == "blocked" else None,
                    action_id,
                ),
            )
            self._event(
                mid,
                "guardrail",
                "guardrail_" + status,
                {
                    "level": level_assigned,
                    "rule": rule,
                    "reason": reason,
                },
                action_id,
            )
            return status

    def request_approval(self, action_id, shown_command, risk_text):
        with self.con:
            mid = self._mission_of(action_id)
            row = self.con.execute(
                "SELECT parameters FROM actions WHERE id=?", (action_id,)
            ).fetchone()
            cur = self.con.execute(
                "INSERT INTO approvals (action_id, requested_at, shown_command, risk_text,"
                " original_parameters) VALUES (?,?,?,?,?)",
                (action_id, now(), shown_command, risk_text, row["parameters"]),
            )
            self._event(
                mid,
                "system",
                "approval_requested",
                {
                    "approval_id": cur.lastrowid,
                    "command": shown_command,
                    "risk": risk_text,
                },
                action_id,
            )
            return cur.lastrowid

    def decide(
        self, approval_id, decision, operator, comment=None, modified_parameters=None
    ):
        if decision == "modified" and modified_parameters is None:
            raise ValueError("modified decision needs modified_parameters")
        with self.con:
            row = self.con.execute(
                "SELECT action_id FROM approvals WHERE id=?", (approval_id,)
            ).fetchone()
            aid = row["action_id"]
            mid = self._mission_of(aid)
            self.con.execute(
                "UPDATE approvals SET decided_at=?, decision=?, operator=?, comment=?,"
                " modified_parameters=? WHERE id=?",
                (
                    now(),
                    decision,
                    operator,
                    comment,
                    dumps(modified_parameters)
                    if modified_parameters is not None
                    else None,
                    approval_id,
                ),
            )
            if decision == "approved":
                new_status = "approved"
            elif decision == "modified":
                new_status = "proposed"
                self.con.execute(
                    "UPDATE actions SET parameters=? WHERE id=?",
                    (dumps(modified_parameters), aid),
                )
            else:
                new_status = "refused"
            self.con.execute(
                "UPDATE actions SET status=? WHERE id=?", (new_status, aid)
            )
            self._event(
                mid,
                "operator" if decision != "timeout" else "system",
                "approval_" + decision,
                {
                    "approval_id": approval_id,
                    "operator": operator,
                    "comment": comment,
                    "modified_parameters": modified_parameters,
                },
                aid,
            )
            return new_status

    def record_execution(
        self,
        action_id,
        argv,
        started_at,
        ended_at,
        duration_ms,
        exit_code,
        timed_out,
        stdout,
        stderr,
    ):
        stdout = stdout or ""
        stderr = stderr or ""
        truncated = int(len(stdout) > MAX_OUTPUT or len(stderr) > MAX_OUTPUT)
        with self.con:
            mid = self._mission_of(action_id)
            cur = self.con.execute(
                "INSERT INTO executions (action_id, argv, started_at, ended_at, duration_ms,"
                " exit_code, timed_out, stdout, stderr, stdout_sha256, truncated)"
                " VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (
                    action_id,
                    dumps(argv),
                    started_at,
                    ended_at,
                    duration_ms,
                    exit_code,
                    int(timed_out),
                    stdout[:MAX_OUTPUT],
                    stderr[:MAX_OUTPUT],
                    sha256(stdout),
                    truncated,
                ),
            )
            status = (
                "timed_out"
                if timed_out
                else ("executed" if exit_code == 0 else "failed")
            )
            self.con.execute(
                "UPDATE actions SET status=? WHERE id=?", (status, action_id)
            )
            self._event(
                mid,
                "tool",
                "execution_" + status,
                {
                    "execution_id": cur.lastrowid,
                    "argv": argv,
                    "exit_code": exit_code,
                    "duration_ms": duration_ms,
                    "stdout_sha256": sha256(stdout),
                },
                action_id,
            )
            return cur.lastrowid

    def remember_service(
        self,
        mission_id,
        ip,
        port,
        proto="tcp",
        name=None,
        product=None,
        version=None,
        execution_id=None,
        hostname=None,
        os=None,
    ):
        with self.con:
            ts = now()
            self.con.execute(
                "INSERT INTO hosts (mission_id, ip, hostname, os, first_seen) VALUES (?,?,?,?,?)"
                " ON CONFLICT(mission_id, ip) DO UPDATE SET"
                " hostname=COALESCE(excluded.hostname, hostname), os=COALESCE(excluded.os, os)",
                (mission_id, ip, hostname, os, ts),
            )
            host_id = self.con.execute(
                "SELECT id FROM hosts WHERE mission_id=? AND ip=?", (mission_id, ip)
            ).fetchone()["id"]
            self.con.execute(
                "INSERT INTO services (host_id, port, proto, name, product, version,"
                " execution_id, first_seen) VALUES (?,?,?,?,?,?,?,?)"
                " ON CONFLICT(host_id, port, proto) DO UPDATE SET"
                " name=excluded.name, product=excluded.product, version=excluded.version",
                (host_id, port, proto, name, product, version, execution_id, ts),
            )

    def add_observation(
        self, mission_id, kind, content, subject=None, execution_id=None
    ):
        with self.con:
            cur = self.con.execute(
                "INSERT INTO observations (mission_id, kind, subject, content, execution_id,"
                " created_at) VALUES (?,?,?,?,?,?)",
                (mission_id, kind, subject, content, execution_id, now()),
            )
            self._event(
                mission_id,
                "system",
                "observation_" + kind,
                {"subject": subject, "content": content},
            )
            return cur.lastrowid

    def add_finding(
        self,
        mission_id,
        title,
        confidence,
        evidence_execution_id,
        evidence_excerpt,
        category=None,
        host=None,
        port=None,
        cve_id=None,
        cve_execution_id=None,
        cvss_score=None,
        cvss_source="none",
        remediation=None,
    ):
        with self.con:
            cur = self.con.execute(
                "INSERT INTO findings (mission_id, title, category, host, port, cve_id,"
                " cve_execution_id, cvss_score, cvss_source, confidence, evidence_execution_id,"
                " evidence_excerpt, remediation, created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    mission_id,
                    title,
                    category,
                    host,
                    port,
                    cve_id,
                    cve_execution_id,
                    cvss_score,
                    cvss_source,
                    confidence,
                    evidence_execution_id,
                    evidence_excerpt,
                    remediation,
                    now(),
                ),
            )
            self._event(
                mission_id,
                "system",
                "finding_added",
                {
                    "finding_id": cur.lastrowid,
                    "title": title,
                    "confidence": confidence,
                    "cve_id": cve_id,
                },
            )
            return cur.lastrowid

    def cache_cve(self, query, response):
        with self.con:
            self.con.execute(
                "INSERT INTO cve_cache (query, response, fetched_at) VALUES (?,?,?)"
                " ON CONFLICT(query) DO UPDATE SET response=excluded.response,"
                " fetched_at=excluded.fetched_at",
                (query, dumps(response), now()),
            )

    def cached_cve(self, query):
        row = self.con.execute(
            "SELECT response, fetched_at FROM cve_cache WHERE query=?", (query,)
        ).fetchone()
        return (json.loads(row["response"]), row["fetched_at"]) if row else None

    def replay(self, mission_id):
        rows = self.con.execute(
            "SELECT * FROM events WHERE mission_id=? ORDER BY id", (mission_id,)
        ).fetchall()
        return [dict(r, payload=json.loads(r["payload"])) for r in rows]

    def verify_chain(self, mission_id):
        prev = GENESIS
        for r in self.con.execute(
            "SELECT * FROM events WHERE mission_id=? ORDER BY id", (mission_id,)
        ):
            expected = sha256(
                dumps(
                    [
                        r["mission_id"],
                        r["ts"],
                        r["actor"],
                        r["type"],
                        r["action_id"],
                        r["payload"],
                        prev,
                    ]
                )
            )
            if r["prev_hash"] != prev or r["hash"] != expected:
                return False, r["id"]
            prev = r["hash"]
        return True, None

    def chain_head(self, mission_id):
        row = self.con.execute(
            "SELECT hash FROM events WHERE mission_id=? ORDER BY id DESC LIMIT 1",
            (mission_id,),
        ).fetchone()
        return row["hash"] if row else GENESIS

    def _mission_of(self, action_id):
        return self.con.execute(
            "SELECT mission_id FROM actions WHERE id=?", (action_id,)
        ).fetchone()["mission_id"]
