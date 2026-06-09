import json
import re
import sqlite3
from datetime import datetime


class KnowledgeBase:
    """Manage the local SOC AutoPilot SQLite knowledge base."""

    def __init__(self, db_path="soc_autopilot.db"):
        """Open a SQLite connection and ensure required tables exist."""
        self.db_path = db_path
        self.conn = sqlite3.connect(self.db_path)
        self.conn.row_factory = sqlite3.Row
        self._init_tables()

    def _init_tables(self):
        """Create the investigations and false positive pattern tables."""
        cursor = self.conn.cursor()
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS investigations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                alert_description TEXT,
                iocs TEXT,
                verdict TEXT,
                severity TEXT,
                summary TEXT,
                analyst_feedback TEXT
            )
            """
        )
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS false_positive_patterns (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                pattern TEXT,
                source_ip TEXT,
                alert_type TEXT,
                confirmed_count INTEGER DEFAULT 1,
                last_seen TEXT
            )
            """
        )
        self.conn.commit()

    def save_investigation(self, alert_description, iocs, verdict, severity, summary) -> int:
        """Insert an investigation and return its generated row ID."""
        cursor = self.conn.cursor()
        cursor.execute(
            """
            INSERT INTO investigations (
                timestamp,
                alert_description,
                iocs,
                verdict,
                severity,
                summary
            )
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                datetime.utcnow().isoformat(),
                alert_description,
                json.dumps(iocs),
                verdict,
                severity,
                summary,
            ),
        )
        self.conn.commit()
        return cursor.lastrowid

    def get_similar_investigations(self, alert_description, limit=5) -> list:
        """Return past investigations with simple overlapping word matches."""
        search_words = self._extract_words(alert_description)
        if not search_words:
            return []

        cursor = self.conn.cursor()
        cursor.execute(
            """
            SELECT *
            FROM investigations
            ORDER BY id DESC
            """
        )

        matches = []
        for row in cursor.fetchall():
            row_words = self._extract_words(row["alert_description"] or "")
            overlap_count = len(search_words & row_words)
            if overlap_count:
                investigation = self._row_to_dict(row)
                investigation["iocs"] = json.loads(investigation["iocs"] or "[]")
                investigation["_overlap_count"] = overlap_count
                matches.append(investigation)

        matches.sort(key=lambda item: item["_overlap_count"], reverse=True)
        results = matches[:limit]
        for item in results:
            item.pop("_overlap_count", None)
        return results

    def add_analyst_feedback(self, investigation_id, feedback, correct_verdict=None):
        """Store analyst feedback and optionally correct the investigation verdict."""
        cursor = self.conn.cursor()
        if correct_verdict is None:
            cursor.execute(
                """
                UPDATE investigations
                SET analyst_feedback = ?
                WHERE id = ?
                """,
                (feedback, investigation_id),
            )
        else:
            cursor.execute(
                """
                UPDATE investigations
                SET analyst_feedback = ?, verdict = ?
                WHERE id = ?
                """,
                (feedback, correct_verdict, investigation_id),
            )
        self.conn.commit()

    def check_false_positive(self, source_ip=None, alert_type=None) -> dict:
        """Check whether a source IP or alert type is a known false positive."""
        clauses = []
        params = []

        if source_ip is not None:
            clauses.append("source_ip = ?")
            params.append(source_ip)
        if alert_type is not None:
            clauses.append("alert_type = ?")
            params.append(alert_type)

        if not clauses:
            return {"is_known_fp": False, "count": 0, "pattern": None}

        cursor = self.conn.cursor()
        cursor.execute(
            f"""
            SELECT *
            FROM false_positive_patterns
            WHERE {" OR ".join(clauses)}
            ORDER BY confirmed_count DESC, last_seen DESC
            LIMIT 1
            """,
            params,
        )
        row = cursor.fetchone()
        if row is None:
            return {"is_known_fp": False, "count": 0, "pattern": None}

        return {
            "is_known_fp": True,
            "count": row["confirmed_count"],
            "pattern": row["pattern"],
        }

    def add_false_positive_pattern(self, pattern, source_ip, alert_type):
        """Insert or update a false-positive pattern by source IP and alert type."""
        now = datetime.utcnow().isoformat()
        cursor = self.conn.cursor()
        cursor.execute(
            """
            SELECT id
            FROM false_positive_patterns
            WHERE source_ip = ? AND alert_type = ?
            LIMIT 1
            """,
            (source_ip, alert_type),
        )
        existing = cursor.fetchone()

        if existing:
            cursor.execute(
                """
                UPDATE false_positive_patterns
                SET pattern = ?,
                    confirmed_count = confirmed_count + 1,
                    last_seen = ?
                WHERE id = ?
                """,
                (pattern, now, existing["id"]),
            )
        else:
            cursor.execute(
                """
                INSERT INTO false_positive_patterns (
                    pattern,
                    source_ip,
                    alert_type,
                    last_seen
                )
                VALUES (?, ?, ?, ?)
                """,
                (pattern, source_ip, alert_type, now),
            )
        self.conn.commit()

    def _extract_words(self, text):
        """Return normalized words from text for simple similarity checks."""
        return set(re.findall(r"\w+", text.lower()))

    def _row_to_dict(self, row):
        """Convert a SQLite row into a plain dictionary."""
        return dict(row)
