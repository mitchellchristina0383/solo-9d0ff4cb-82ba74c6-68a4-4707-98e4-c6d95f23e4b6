"""Reflection-amplification risk monitoring for the slave DNS node.

The on-call operator wants traffic that could be used for DNS reflection /
amplification attacks. The UDP *source address is only a claimed source*
(spoofable), so statistics are aggregated by the claimed source IPv4 /24.

Model
-----
Every parseable DNS transaction (one query datagram and the answer it got)
is evaluated:

- amplification factor = response wire bytes / query wire bytes;
- a transaction "qualifies" when its factor >= the configured minimum factor;
- qualifying transactions are counted per source /24 over a rolling
  ``window_seconds`` (default 60 s) window;
- when a /24's window count reaches ``min_events`` (default threshold) an
  *event* is opened. Further qualifying traffic only updates the open event;
  when the count drops below the threshold the event is closed; if the /24
  crosses the threshold again later a brand-new event is opened.

Dedup
-----
A retransmission carrying the same 5-tuple, transaction id and question
within ``dedup_seconds`` (default 2 s) is counted once: it is neither stored
as a new transaction nor added to any event's counters.

Persistence / concurrency
-------------------------
Transactions, events and the configuration live in the same SQLite database
as the zone data, so a process restart resumes both the rolling window (from
the transactions still inside it) and the open/closed state of every event.
All SQLite access is serialized on one dedicated monitor worker thread; the
asyncio event loop (DNS/UDP path) only enqueues jobs and never blocks on the
store, while SQLite itself serializes access across connections.

Failure isolation
-----------------
If a monitoring write fails, ``available`` flips to false and every
``/monitor/*`` read reports 503. The DNS answer path never raises on
monitoring failures — queries are still answered exactly as before. The
store retries the connection on the next write and flips back to available
once writes succeed again.
"""

from __future__ import annotations

import ipaddress
import os
import queue
import sqlite3
import threading
import time
from typing import Callable, Optional

# Configurable via env at boot; changeable at runtime through the HTTP API.
DEFAULT_MIN_FACTOR = float(os.environ.get("MONITOR_MIN_FACTOR", "2.0"))
DEFAULT_MIN_EVENTS = int(os.environ.get("MONITOR_MIN_EVENTS", "5"))
WINDOW_SECONDS = float(os.environ.get("MONITOR_WINDOW_SECONDS", "60"))
DEDUP_SECONDS = float(os.environ.get("MONITOR_DEDUP_SECONDS", "2"))
SWEEP_INTERVAL = float(os.environ.get("MONITOR_SWEEP_INTERVAL", "1"))


def now_ts() -> float:
    return time.time()


def iso(ts: Optional[float]) -> Optional[str]:
    if ts is None:
        return None
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts))


def source_subnet(ip: str) -> str:
    """The claimed source IPv4 /24, e.g. '203.0.113.0/24'."""
    addr = ipaddress.IPv4Address(ip)
    return str(ipaddress.IPv4Network((int(addr) & ~0xFF, 24), strict=False))


class MonitorUnavailable(Exception):
    """Raised by API handlers when the monitoring store cannot write/read."""


class MonitorStore:
    """SQLite-backed rolling window + event state machine."""

    def __init__(self, db_path: str) -> None:
        self.db_path = db_path
        self._conn: Optional[sqlite3.Connection] = None
        self.available = True
        self.last_error: Optional[str] = None
        self._fail_open = False  # test-only fault injection: next writes fail

    # ------------------------------------------------------------------
    # connection / schema
    # ------------------------------------------------------------------

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA busy_timeout=5000")
        return conn

    def init_db(self) -> None:
        """Create the schema and seed default config. Best-effort reconnect."""
        try:
            if self._conn is None:
                self._conn = self._connect()
            with self._conn:
                self._conn.executescript(
                    """
                    CREATE TABLE IF NOT EXISTS monitor_config(
                        key   TEXT PRIMARY KEY,
                        value TEXT NOT NULL
                    );
                    CREATE TABLE IF NOT EXISTS monitor_txn(
                        ts          REAL NOT NULL,
                        src_ip      TEXT NOT NULL,
                        src_port    INTEGER NOT NULL,
                        dst_ip      TEXT NOT NULL,
                        dst_port    INTEGER NOT NULL,
                        proto       INTEGER NOT NULL,
                        xid         INTEGER NOT NULL,
                        question    TEXT NOT NULL,
                        req_bytes   INTEGER NOT NULL,
                        resp_bytes  INTEGER NOT NULL,
                        factor      REAL NOT NULL
                    );
                    CREATE INDEX IF NOT EXISTS idx_txn_ts
                        ON monitor_txn(ts);
                    CREATE INDEX IF NOT EXISTS idx_txn_dedup
                        ON monitor_txn(src_ip, src_port, dst_ip, dst_port,
                                       proto, xid, question, ts);
                    CREATE TABLE IF NOT EXISTS monitor_event(
                        id            INTEGER PRIMARY KEY AUTOINCREMENT,
                        subnet        TEXT NOT NULL,
                        status        TEXT NOT NULL,
                        min_factor    REAL NOT NULL,
                        min_events    INTEGER NOT NULL,
                        count         INTEGER NOT NULL,
                        req_bytes     INTEGER NOT NULL,
                        resp_bytes    INTEGER NOT NULL,
                        started_at    REAL NOT NULL,
                        ended_at      REAL
                    );
                    CREATE INDEX IF NOT EXISTS idx_event_status
                        ON monitor_event(status, subnet);
                    """
                )
                self._seed_config(self._conn, "min_factor", str(DEFAULT_MIN_FACTOR))
                self._seed_config(self._conn, "min_events", str(DEFAULT_MIN_EVENTS))
            self.available = True
            self.last_error = None
        except sqlite3.Error as exc:
            # A broken file handle must not be reused.
            self._mark_failed(f"init: {exc}")
            raise

    @staticmethod
    def _seed_config(conn: sqlite3.Connection, key: str, default: str) -> None:
        conn.execute(
            "INSERT OR IGNORE INTO monitor_config(key, value) VALUES(?, ?)",
            (key, default),
        )

    def _mark_failed(self, message: str) -> None:
        self.available = False
        self.last_error = f"{time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())} {message}"
        try:
            if self._conn is not None:
                self._conn.close()
        except sqlite3.Error:
            pass
        self._conn = None

    def _get_conn(self) -> sqlite3.Connection:
        """Hand back a live connection, reconnecting after a previous failure."""
        if self._fail_open:
            raise sqlite3.OperationalError("injected monitoring write failure")
        if self._conn is None:
            self._conn = self._connect()
        return self._conn

    # ------------------------------------------------------------------
    # test-only fault injection
    # ------------------------------------------------------------------

    def set_fault(self, enabled: bool) -> None:
        """Break (or restore) the write path. Test/debug use only."""
        self._fail_open = enabled
        if not enabled and self._conn is None:
            try:
                self._conn = self._connect()
                self.available = True
                self.last_error = None
            except sqlite3.Error as exc:
                self._mark_failed(f"reconnect: {exc}")

    # ------------------------------------------------------------------
    # configuration
    # ------------------------------------------------------------------

    def get_config(self) -> dict:
        try:
            conn = self._get_conn()
            row_f = conn.execute(
                "SELECT value FROM monitor_config WHERE key='min_factor'"
            ).fetchone()
            row_n = conn.execute(
                "SELECT value FROM monitor_config WHERE key='min_events'"
            ).fetchone()
            self.available = True
            return {
                "min_factor": float(row_f["value"]),
                "min_events": int(row_n["value"]),
                "window_seconds": WINDOW_SECONDS,
                "dedup_seconds": DEDUP_SECONDS,
            }
        except sqlite3.Error as exc:
            self._mark_failed(f"get_config: {exc}")
            raise

    def update_config(self, min_factor: Optional[float],
                      min_events: Optional[int]) -> dict:
        """Apply new thresholds atomically.

        Per the operating rule, changing a threshold closes every currently
        open event and re-judges the raw transactions still inside the
        window against the new thresholds, opening fresh events where the
        new bar is met.
        """
        try:
            conn = self._get_conn()
            with conn:
                if min_factor is not None:
                    conn.execute(
                        "INSERT INTO monitor_config(key, value) VALUES('min_factor', ?) "
                        "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                        (str(float(min_factor)),),
                    )
                if min_events is not None:
                    conn.execute(
                        "INSERT INTO monitor_config(key, value) VALUES('min_events', ?) "
                        "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                        (str(int(min_events)),),
                    )
                cutoff = now_ts() - WINDOW_SECONDS
                conn.execute("DELETE FROM monitor_txn WHERE ts < ?", (cutoff,))
                conn.execute(
                    "UPDATE monitor_event SET status='closed', ended_at=? "
                    "WHERE status='open'",
                    (now_ts(),),
                )
                self._open_events_for_window(conn, now_ts())
            self.available = True
            self.last_error = None
            return self.get_config()
        except sqlite3.Error as exc:
            self._mark_failed(f"update_config: {exc}")
            raise

    # ------------------------------------------------------------------
    # transaction recording
    # ------------------------------------------------------------------

    def record_transaction(self, *, src_ip: str, src_port: int, dst_ip: str,
                           dst_port: int, proto: int, xid: int, question: str,
                           req_bytes: int, resp_bytes: int) -> None:
        """Record one query/answer pair; no-op for in-window retransmissions.

        Raises sqlite3.Error on a failed write; the caller must isolate that
        from the DNS answer path.
        """
        try:
            conn = self._get_conn()
            now = now_ts()
            with conn:
                cfg = self._read_config(conn)
                # Retransmission check: identical 5-tuple + txid + question
                # seen within the dedup window counts as one transaction.
                dup = conn.execute(
                    "SELECT 1 FROM monitor_txn WHERE src_ip=? AND src_port=? "
                    "AND dst_ip=? AND dst_port=? AND proto=? AND xid=? "
                    "AND question=? AND ts >= ? LIMIT 1",
                    (src_ip, src_port, dst_ip, dst_port, proto, xid, question,
                     now - DEDUP_SECONDS),
                ).fetchone()
                if dup is not None:
                    self.available = True
                    return
                factor = (resp_bytes / req_bytes) if req_bytes > 0 else 0.0
                subnet = source_subnet(src_ip)
                conn.execute(
                    "INSERT INTO monitor_txn(ts, src_ip, src_port, dst_ip, dst_port, "
                    "proto, xid, question, req_bytes, resp_bytes, factor) "
                    "VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                    (now, src_ip, src_port, dst_ip, dst_port, proto, xid, question,
                     req_bytes, resp_bytes, factor),
                )
                if factor >= cfg["min_factor"]:
                    self._evaluate_subnet(conn, subnet, now, cfg)
            self.available = True
            self.last_error = None
        except sqlite3.Error as exc:
            self._mark_failed(f"record: {exc}")
            raise

    @staticmethod
    def _read_config(conn: sqlite3.Connection) -> dict:
        rows = conn.execute("SELECT key, value FROM monitor_config").fetchall()
        cfg = {r["key"]: r["value"] for r in rows}
        return {
            "min_factor": float(cfg["min_factor"]),
            "min_events": int(cfg["min_events"]),
        }

    # ------------------------------------------------------------------
    # window statistics + event state machine
    # ------------------------------------------------------------------

    def _subnet_stats(self, conn: sqlite3.Connection, subnet: str,
                      now: float, min_factor: float) -> Optional[sqlite3.Row]:
        prefix = subnet.split("/", 1)[0].rsplit(".", 1)[0] + "."
        return conn.execute(
            "SELECT COUNT(*) AS n, COALESCE(SUM(req_bytes),0) AS req_bytes, "
            "COALESCE(SUM(resp_bytes),0) AS resp_bytes FROM monitor_txn "
            "WHERE ts >= ? AND factor >= ? AND substr(src_ip,1,?) = ?",
            (now - WINDOW_SECONDS, min_factor, len(prefix), prefix),
        ).fetchone()

    def _evaluate_subnet(self, conn: sqlite3.Connection, subnet: str,
                         now: float, cfg: dict) -> None:
        """Open/update the event for one /24 from its current window stats."""
        stats = self._subnet_stats(conn, subnet, now, cfg["min_factor"])
        n = stats["n"]
        open_row = conn.execute(
            "SELECT id FROM monitor_event WHERE subnet=? AND status='open'",
            (subnet,),
        ).fetchone()
        if n >= cfg["min_events"]:
            if open_row is None:
                conn.execute(
                    "INSERT INTO monitor_event(subnet, status, min_factor, min_events, "
                    "count, req_bytes, resp_bytes, started_at, ended_at) "
                    "VALUES(?, 'open', ?, ?, ?, ?, ?, ?, NULL)",
                    (subnet, cfg["min_factor"], cfg["min_events"], n,
                     stats["req_bytes"], stats["resp_bytes"], now),
                )
            else:
                # Persistent excess: only the counters move, the event stays one.
                conn.execute(
                    "UPDATE monitor_event SET count=?, req_bytes=?, resp_bytes=? "
                    "WHERE id=?",
                    (n, stats["req_bytes"], stats["resp_bytes"], open_row["id"]),
                )
        # Counts below the threshold are closed by the sweeper, never here:
        # a single qualifying transaction can only raise the window count.

    def _open_events_for_window(self, conn: sqlite3.Connection, now: float) -> None:
        """Re-judge every /24 from raw window transactions (restart / config)."""
        cfg = self._read_config(conn)
        rows = conn.execute(
            "SELECT DISTINCT src_ip FROM monitor_txn "
            "WHERE ts >= ? AND factor >= ?",
            (now - WINDOW_SECONDS, cfg["min_factor"]),
        ).fetchall()
        prefixes = sorted({self._prefix(r["src_ip"]) for r in rows})
        for prefix in prefixes:
            subnet = prefix + "0/24"
            stats = conn.execute(
                "SELECT COUNT(*) AS n, COALESCE(SUM(req_bytes),0) AS req_bytes, "
                "COALESCE(SUM(resp_bytes),0) AS resp_bytes FROM monitor_txn "
                "WHERE ts >= ? AND factor >= ? AND substr(src_ip,1,?) = ?",
                (now - WINDOW_SECONDS, cfg["min_factor"], len(prefix), prefix),
            ).fetchone()
            if stats["n"] >= cfg["min_events"]:
                already = conn.execute(
                    "SELECT 1 FROM monitor_event WHERE subnet=? AND status='open'",
                    (subnet,),
                ).fetchone()
                if already is None:
                    conn.execute(
                        "INSERT INTO monitor_event(subnet, status, min_factor, "
                        "min_events, count, req_bytes, resp_bytes, started_at, ended_at) "
                        "VALUES(?, 'open', ?, ?, ?, ?, ?, ?, NULL)",
                        (subnet, cfg["min_factor"], cfg["min_events"], stats["n"],
                         stats["req_bytes"], stats["resp_bytes"], now),
                    )

    def sweep(self) -> None:
        """Drop expired transactions, then reconcile every open event.

        Runs roughly once per second: closes events whose window count has
        fallen below the threshold and refreshes counters of the still-open
        ones.
        """
        try:
            conn = self._get_conn()
            now = now_ts()
            with conn:
                conn.execute(
                    "DELETE FROM monitor_txn WHERE ts < ?", (now - WINDOW_SECONDS,)
                )
                cfg = self._read_config(conn)
                open_rows = conn.execute(
                    "SELECT id, subnet FROM monitor_event WHERE status='open'"
                ).fetchall()
                for row in open_rows:
                    stats = self._subnet_stats(
                        conn, row["subnet"], now, cfg["min_factor"]
                    )
                    if stats["n"] < cfg["min_events"]:
                        conn.execute(
                            "UPDATE monitor_event SET status='closed', "
                            "ended_at=?, count=?, req_bytes=?, resp_bytes=? WHERE id=?",
                            (now, stats["n"], stats["req_bytes"],
                             stats["resp_bytes"], row["id"]),
                        )
                    else:
                        conn.execute(
                            "UPDATE monitor_event SET count=?, req_bytes=?, "
                            "resp_bytes=? WHERE id=?",
                            (stats["n"], stats["req_bytes"],
                             stats["resp_bytes"], row["id"]),
                        )
            self.available = True
            self.last_error = None
        except sqlite3.Error as exc:
            self._mark_failed(f"sweep: {exc}")

    def reconcile_on_startup(self) -> None:
        """Re-judge the persisted window/events after a process restart."""
        try:
            conn = self._get_conn()
            now = now_ts()
            with conn:
                conn.execute(
                    "DELETE FROM monitor_txn WHERE ts < ?",
                    (now - WINDOW_SECONDS,),
                )
                cfg = self._read_config(conn)
                open_rows = conn.execute(
                    "SELECT id, subnet FROM monitor_event WHERE status='open'"
                ).fetchall()
                # Close persisted open events that no longer meet the bar;
                # refresh the ones that do.
                for row in open_rows:
                    stats = self._subnet_stats(
                        conn, row["subnet"], now, cfg["min_factor"]
                    )
                    if stats["n"] < cfg["min_events"]:
                        conn.execute(
                            "UPDATE monitor_event SET status='closed', ended_at=?, "
                            "count=?, req_bytes=?, resp_bytes=? WHERE id=?",
                            (now, stats["n"], stats["req_bytes"],
                             stats["resp_bytes"], row["id"]),
                        )
                    else:
                        conn.execute(
                            "UPDATE monitor_event SET count=?, req_bytes=?, "
                            "resp_bytes=? WHERE id=?",
                            (stats["n"], stats["req_bytes"],
                             stats["resp_bytes"], row["id"]),
                        )
                # Open fresh events for /24s that qualify but have none open.
                self._open_events_for_window(conn, now)
            self.available = True
            self.last_error = None
        except sqlite3.Error as exc:
            self._mark_failed(f"reconcile: {exc}")

    # ------------------------------------------------------------------
    # read models
    # ------------------------------------------------------------------

    def list_events(self, status: Optional[str] = None) -> list[dict]:
        try:
            conn = self._get_conn()
            if status in (None, "all"):
                rows = conn.execute(
                    "SELECT * FROM monitor_event ORDER BY id DESC"
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM monitor_event WHERE status=? ORDER BY id DESC",
                    (status,),
                ).fetchall()
            self.available = True
            return [self._event_dict(r) for r in rows]
        except sqlite3.Error as exc:
            self._mark_failed(f"list_events: {exc}")
            raise

    def window_stats(self) -> list[dict]:
        """Per-/24 breakdown of the current rolling window (for /docs & tests)."""
        try:
            conn = self._get_conn()
            now = now_ts()
            cfg = self._read_config(conn)
            rows = conn.execute(
                "SELECT src_ip FROM monitor_txn WHERE ts >= ?",
                (now - WINDOW_SECONDS,),
            ).fetchall()
            prefixes = sorted({self._prefix(r["src_ip"]) for r in rows})
            out = []
            for prefix in prefixes:
                subnet = prefix + "0/24"
                total = conn.execute(
                    "SELECT COUNT(*) AS n, COALESCE(SUM(req_bytes),0) AS req_bytes, "
                    "COALESCE(SUM(resp_bytes),0) AS resp_bytes FROM monitor_txn "
                    "WHERE ts >= ? AND substr(src_ip,1,?) = ?",
                    (now - WINDOW_SECONDS, len(prefix), prefix),
                ).fetchone()
                qual = conn.execute(
                    "SELECT COUNT(*) AS n, COALESCE(SUM(req_bytes),0) AS req_bytes, "
                    "COALESCE(SUM(resp_bytes),0) AS resp_bytes, "
                    "COALESCE(MAX(factor),0) AS max_factor FROM monitor_txn "
                    "WHERE ts >= ? AND factor >= ? AND substr(src_ip,1,?) = ?",
                    (now - WINDOW_SECONDS, cfg["min_factor"], len(prefix), prefix),
                ).fetchone()
                out.append({
                    "subnet": subnet,
                    "total_transactions": total["n"],
                    "qualifying_transactions": qual["n"],
                    "req_bytes": total["req_bytes"],
                    "resp_bytes": total["resp_bytes"],
                    "qualifying_req_bytes": qual["req_bytes"],
                    "qualifying_resp_bytes": qual["resp_bytes"],
                    "max_factor": round(qual["max_factor"], 3),
                    "threshold": cfg["min_events"],
                    "in_event": qual["n"] >= cfg["min_events"],
                })
            self.available = True
            return out
        except sqlite3.Error as exc:
            self._mark_failed(f"window_stats: {exc}")
            raise

    @staticmethod
    def _prefix(ip: str) -> str:
        parts = ip.split(".")
        return ".".join(parts[:3]) + "."

    def _event_dict(self, row: sqlite3.Row) -> dict:
        return {
            "id": row["id"],
            "subnet": row["subnet"],
            "status": row["status"],
            "min_factor": row["min_factor"],
            "min_events": row["min_events"],
            "count": row["count"],
            "req_bytes": row["req_bytes"],
            "resp_bytes": row["resp_bytes"],
            "started_at": iso(row["started_at"]),
            "ended_at": iso(row["ended_at"]),
        }

    def health(self) -> dict:
        return {
            "available": self.available,
            "last_error": self.last_error,
            "window_seconds": WINDOW_SECONDS,
            "dedup_seconds": DEDUP_SECONDS,
        }


# --------------------------------------------------------------------------
# threaded service: all SQLite access happens on one worker thread
# --------------------------------------------------------------------------

class _Job:
    __slots__ = ("func", "event", "result", "exc")

    def __init__(self, func: Callable[[], object]) -> None:
        self.func = func
        self.event = threading.Event()
        self.result: object = None
        self.exc: Optional[BaseException] = None


class MonitorService:
    """Serializes every MonitorStore call on a single daemon thread.

    The DNS/UDP path (asyncio event loop) only enqueues a job and never
    blocks on it: a monitoring write failure or a slow disk cannot delay an
    answer. HTTP handlers need results and wait bounded time; on timeout
    they report the monitoring interface unavailable.
    """

    def __init__(self, db_path: str, job_timeout: float = 5.0) -> None:
        self.store = MonitorStore(db_path)
        self._queue: "queue.Queue[Optional[_Job]]" = queue.Queue()
        self._worker = threading.Thread(
            target=self._run, name="monitor-worker", daemon=True
        )
        self.job_timeout = job_timeout
        self._started = False

    def start(self) -> None:
        if self._started:
            return
        self._worker.start()
        self._started = True
        # A broken monitoring store must never block DNS startup: the worker
        # keeps running and retries the connection on every later job.
        try:
            self._call(lambda: self.store.init_db())
            self._call(lambda: self.store.reconcile_on_startup())
        except sqlite3.Error:
            pass

    def _run(self) -> None:
        while True:
            job = self._queue.get()
            if job is None:
                return
            try:
                job.result = job.func()
            except BaseException as exc:  # surface to the caller, keep alive
                job.exc = exc
            job.event.set()

    def _call(self, func: Callable[[], object], timeout: Optional[float] = None):
        if not self._started:
            raise MonitorUnavailable("monitor not started")
        job = _Job(func)
        self._queue.put(job)
        if not job.event.wait(timeout if timeout is not None else self.job_timeout):
            raise MonitorUnavailable("monitor store timed out")
        if job.exc is not None:
            raise job.exc
        return job.result

    def submit(self, func: Callable[[], object]) -> None:
        """Fire-and-forget: failures flip availability inside the store."""
        if not self._started:
            return
        self._queue.put(_Job(func))

    # The remaining methods are thin, serialized wrappers.

    def record_transaction(self, **kwargs) -> None:
        self.submit(lambda: self.store.record_transaction(**kwargs))

    def sweep(self) -> None:
        self.submit(self.store.sweep)

    def get_config(self) -> dict:
        return self._call(self.store.get_config)

    def update_config(self, min_factor: Optional[float],
                      min_events: Optional[int]) -> dict:
        return self._call(
            lambda: self.store.update_config(min_factor, min_events)
        )

    def list_events(self, status: Optional[str] = None) -> list[dict]:
        return self._call(lambda: self.store.list_events(status))

    def window_stats(self) -> list[dict]:
        return self._call(self.store.window_stats)

    def health(self) -> dict:
        try:
            return self._call(self.store.health, timeout=2.0)
        except MonitorUnavailable:
            return {
                "available": False,
                "last_error": "monitor store timed out",
                "window_seconds": WINDOW_SECONDS,
                "dedup_seconds": DEDUP_SECONDS,
            }

    def set_fault(self, enabled: bool) -> None:
        self._call(lambda: self.store.set_fault(enabled))

    def stop(self) -> None:
        if not self._started:
            return
        self._queue.put(None)
        self._worker.join(timeout=5)
        self._started = False
