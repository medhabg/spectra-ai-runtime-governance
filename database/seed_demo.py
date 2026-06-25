"""
database/seed_demo.py
---------------------
Inserts capstone demo runtimes into llm_hunter.db.
All rows carry department='DEMO' for easy identification / cleanup.
Run:  python database/seed_demo.py
"""
import json
import sqlite3
import uuid
from pathlib import Path

DB_PATH = Path(__file__).parent / "llm_hunter.db"

# ---------------------------------------------------------------------------
# Demo runtimes: (host, runtime, port, risk_score_num, risk_level,
#                 status, interface, model, user, pid, policy_violation,
#                 gpu_spike, signal_count, endpoint_criticality)
# ---------------------------------------------------------------------------
DEMO_RUNTIMES = [
    # host           runtime     port   risk_num  risk_lvl  status    iface           model                                                  user    pid    polv  gpu  sigs  crit
    ("ENDPOINT-017", "Jan",      1337,  7,        "HIGH",   "Active", "127.0.0.1",    r"C:\Users\Admin\.jan\models\mistral-7b-q4.gguf",      "user2", 9201,  1,    0,   2,   1),
    ("ENDPOINT-017", "Ollama",   11434, 8,        "HIGH",   "Active", "0.0.0.0",      "mistral:7b",                                          "user2", 9450,  1,    1,   3,   1),
    ("ENDPOINT-031", "LMDeploy", 23333, 9,        "HIGH",   "Active", "0.0.0.0",      r"C:\Users\Admin\lmdeploy\models\llama3-8b.gguf",      "admin", 11200, 1,    1,   3,   1),
    ("ENDPOINT-031", "GPT4All",  4891,  2,        "LOW",    "Active", "127.0.0.1",    "orca-mini-3b.gguf",                                   "admin", 11350, 0,    0,   1,   0),
    ("ENDPOINT-055", "LM Studio",1234,  1,        "LOW",    "Inactive","127.0.0.1",   "tinyllama-1.1b.gguf",                                 "user3", None,  0,    0,   0,   0),
]

# Scan timestamps spread across 2026-05-29 to 2026-05-31
TIMESTAMPS = [
    "2026-05-29T08:14:22",
    "2026-05-29T21:30:05",
    "2026-05-30T09:45:11",
    "2026-05-30T17:22:33",
    "2026-05-31T03:10:44",
    "2026-05-31T06:55:01",
    "2026-05-31T08:30:17",
    "2026-05-31T10:12:59",
    "2026-05-31T11:05:38",
]

def run():
    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()

    events_inserted = 0
    alerts_inserted = 0
    inv_upserted    = 0

    for idx, (host, runtime, port, risk_num, risk_lvl, status, iface,
               model, user, pid, polv, gpu, sigs, crit) in enumerate(DEMO_RUNTIMES):

        # Pick 2 timestamps per runtime (stagger by index)
        ts_pair = TIMESTAMPS[idx * 2 : idx * 2 + 2]
        if len(ts_pair) < 2:
            ts_pair = TIMESTAMPS[-2:]

        for ts in ts_pair:
            eid = str(uuid.uuid4())
            signals = json.dumps({
                "port_scan":    port is not None,
                "lib_match":    sigs > 0,
                "model_file":   bool(model),
                "gpu_spike":    bool(gpu),
            })
            libs = json.dumps(["llama_cpp"] if sigs > 0 else [])

            cur.execute("""
                INSERT OR IGNORE INTO detection_events (
                    event_id, host, runtime, model_file, port_detected,
                    gpu_spike, lib_match, risk_score, timestamp,
                    user_id, department, approval_status, policy_violation,
                    vuln_flag, signals_fired, signal_count, endpoint_criticality
                ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """, (
                eid, host, runtime, model, port,
                gpu, libs, risk_lvl, ts,
                user, "DEMO",
                "unapproved" if polv else "approved",
                polv, 0, signals, sigs, crit,
            ))
            events_inserted += cur.rowcount

            # Create alert for HIGH / CRITICAL events
            if risk_lvl in ("HIGH", "CRITICAL") and polv:
                alert_id = str(uuid.uuid4())
                cur.execute("""
                    INSERT OR IGNORE INTO alerts (alert_id, event_id, risk_level, alerted_at, resolved)
                    VALUES (?,?,?,?,0)
                """, (alert_id, eid, risk_lvl, ts))
                alerts_inserted += cur.rowcount

        # Upsert ai_inventory (most recent timestamp)
        last_ts = ts_pair[-1]
        cur.execute("""
            INSERT INTO ai_inventory (host, runtime, model_file, last_seen, status)
            VALUES (?,?,?,?,?)
            ON CONFLICT(host, runtime) DO UPDATE SET
                model_file = excluded.model_file,
                last_seen  = excluded.last_seen,
                status     = excluded.status
        """, (host, runtime, model, last_ts, status.lower()))
        inv_upserted += 1

    con.commit()
    con.close()

    print(f"[seed_demo] Done.")
    print(f"  detection_events inserted : {events_inserted}")
    print(f"  alerts inserted           : {alerts_inserted}")
    print(f"  ai_inventory upserted     : {inv_upserted}")

    # Quick verification
    con2 = sqlite3.connect(DB_PATH)
    cur2 = con2.cursor()
    cur2.execute("SELECT runtime, risk_score, COUNT(*) FROM detection_events WHERE department='DEMO' GROUP BY runtime, risk_score")
    rows = cur2.fetchall()
    print("\n[verify] DEMO events by runtime + risk:")
    for r in rows:
        print(f"  {r[0]:<14} {r[1]:<10} {r[2]} event(s)")

    cur2.execute("SELECT risk_score, COUNT(*) FROM detection_events GROUP BY risk_score")
    print("\n[verify] ALL events by risk level:")
    for r in cur2.fetchall():
        print(f"  {r[0]:<10} {r[1]}")

    cur2.execute("SELECT runtime, COUNT(*) FROM detection_events GROUP BY runtime ORDER BY COUNT(*) DESC")
    print("\n[verify] ALL events by runtime:")
    for r in cur2.fetchall():
        print(f"  {r[0]:<20} {r[1]}")
    con2.close()

if __name__ == "__main__":
    run()
