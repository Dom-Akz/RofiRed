import sqlite3

import pytest

from rofired.db.store import Store, now


@pytest.fixture
def db(tmp_path):
    s = Store(tmp_path / "t.db")
    yield s
    s.close()


@pytest.fixture
def mission(db):
    return db.start_mission(
        "WebApp", "start", "test-model", {"policy.json": "ab"}, {"nmap": "7.9"}
    )


def action(db, mission, step=1, tool="nmap", level="N1"):
    return db.propose_action(
        mission, step, tool, "WebApp", {"target": "10.77.0.10"}, level, "why", "ports"
    )


def execute(db, aid, code=0):
    t = now()
    return db.record_execution(
        aid, ["nmap", "-sV", "10.77.0.10"], t, t, 12, code, False, "out", ""
    )


def test_auto_cleared_and_executed(db, mission):
    a = action(db, mission)
    assert db.guardrail_verdict(a, "N1", True) == "cleared"
    eid = execute(db, a)
    assert (
        db.con.execute("SELECT status FROM actions WHERE id=?", (a,)).fetchone()[0]
        == "executed"
    )
    assert eid > 0


def test_blocked_action_never_reopens(db, mission):
    a = action(db, mission)
    assert (
        db.guardrail_verdict(a, "N1", False, rule="G02", reason="out of scope")
        == "blocked"
    )
    with pytest.raises(sqlite3.IntegrityError):
        db.con.execute("UPDATE actions SET status='approved' WHERE id=?", (a,))


def test_n3_is_always_blocked(db, mission):
    a = action(db, mission, level="N3")
    assert db.guardrail_verdict(a, "N3", True) == "blocked"


def test_human_refusal_is_logged_and_final(db, mission):
    a = action(db, mission, tool="http_client", level="N2")
    assert db.guardrail_verdict(a, "N2", True) == "pending_approval"
    ap = db.request_approval(a, "POST /users/v1/register", "creates a user")
    assert db.decide(ap, "refused", "soufiane", "not needed") == "refused"
    with pytest.raises(sqlite3.IntegrityError):
        db.decide(ap, "approved", "soufiane")
    types = [e["type"] for e in db.replay(mission)]
    assert "approval_requested" in types and "approval_refused" in types


def test_human_approval_then_execution(db, mission):
    a = action(db, mission, level="N2")
    db.guardrail_verdict(a, "N2", True)
    ap = db.request_approval(a, "nmap --script vuln", "intrusive")
    assert db.decide(ap, "approved", "soufiane") == "approved"
    execute(db, a)
    assert (
        db.con.execute("SELECT status FROM actions WHERE id=?", (a,)).fetchone()[0]
        == "executed"
    )


def test_modified_goes_back_to_guardrails(db, mission):
    a = action(db, mission, level="N2")
    db.guardrail_verdict(a, "N2", True)
    ap = db.request_approval(a, "cmd", "risk")
    assert (
        db.decide(
            ap,
            "modified",
            "soufiane",
            modified_parameters={"target": "10.77.0.10", "port": 5000},
        )
        == "proposed"
    )
    row = db.con.execute(
        "SELECT original_parameters, modified_parameters FROM approvals WHERE id=?",
        (ap,),
    ).fetchone()
    assert (
        "port" not in row["original_parameters"]
        and "port" in row["modified_parameters"]
    )


def test_timeout_counts_as_refusal(db, mission):
    a = action(db, mission, level="N2")
    db.guardrail_verdict(a, "N2", True)
    ap = db.request_approval(a, "cmd", "risk")
    assert db.decide(ap, "timeout", "system") == "refused"


def test_chain_verifies_and_detects_tampering(db, mission):
    a = action(db, mission)
    db.guardrail_verdict(a, "N1", True)
    execute(db, a)
    assert db.verify_chain(mission) == (True, None)
    db.con.execute("DROP TRIGGER events_no_update")
    db.con.execute("UPDATE events SET payload='{}' WHERE id=2")
    db.con.commit()
    ok, bad = db.verify_chain(mission)
    assert not ok and bad == 2


def test_events_and_executions_are_immutable(db, mission):
    a = action(db, mission)
    eid = execute(db, a)
    for sql in (
        "DELETE FROM events",
        "UPDATE events SET type='x'",
        f"DELETE FROM executions WHERE id={eid}",
        f"UPDATE executions SET stdout='x' WHERE id={eid}",
    ):
        with pytest.raises(sqlite3.IntegrityError):
            db.con.execute(sql)


def test_finding_requires_evidence(db, mission):
    with pytest.raises(sqlite3.IntegrityError):
        db.con.execute(
            "INSERT INTO findings (mission_id, title, confidence, evidence_execution_id, evidence_excerpt, created_at)"
            " VALUES (?,?,?,?,?,?)",
            (mission, "x", "probable", None, "e", now()),
        )


def test_cve_must_come_from_a_lookup(db, mission):
    a = action(db, mission)
    eid = execute(db, a)
    with pytest.raises(sqlite3.IntegrityError):
        db.add_finding(
            mission, "old ftp", "probable", eid, "vsftpd 2.3.4", cve_id="CVE-2011-2523"
        )
    lookup = action(db, mission, step=2, tool="cve_lookup", level="N0")
    leid = execute(db, lookup)
    fid = db.add_finding(
        mission,
        "old ftp",
        "probable",
        eid,
        "vsftpd 2.3.4",
        cve_id="CVE-2011-2523",
        cve_execution_id=leid,
        cvss_score=9.8,
        cvss_source="cve_lookup",
    )
    assert fid > 0


def test_memory_upsert_and_cache(db, mission):
    db.remember_service(mission, "10.77.0.10", 5000, name="http", product="Werkzeug")
    db.remember_service(
        mission, "10.77.0.10", 5000, name="http", product="Werkzeug", version="2.0"
    )
    assert db.con.execute("SELECT COUNT(*) FROM services").fetchone()[0] == 1
    assert db.cached_cve("vsftpd 2.3.4") is None
    db.cache_cve("vsftpd 2.3.4", {"cves": ["CVE-2011-2523"]})
    assert db.cached_cve("vsftpd 2.3.4")[0] == {"cves": ["CVE-2011-2523"]}


def test_emergency_stop_and_llm_calls(db, mission):
    db.record_llm_call(
        mission, 1, 1, "m", "prompt", "not json", False, error="invalid json"
    )
    db.end_mission(mission, "emergency_stop", "operator pressed stop")
    events = db.replay(mission)
    assert events[-1]["type"] == "mission_ended" and events[-1]["actor"] == "operator"
    assert any(e["type"] == "llm_invalid_output" for e in events)
    assert db.verify_chain(mission)[0]
