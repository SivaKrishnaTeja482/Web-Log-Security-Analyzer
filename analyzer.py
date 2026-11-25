"""Pure log parsing and rule-based security analysis.

The module intentionally has no network or persistence dependencies. That keeps
the detector deterministic, testable, and suitable for a stateless container.
"""

from __future__ import annotations

import re
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any
from urllib.parse import unquote, urlsplit


MAX_INPUT_BYTES = 100_000
MAX_LOG_LINES = 250

LOG_PATTERN = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+\S+\s+'
    r'\[(?P<timestamp>[^\]]+)\]\s+'
    r'"(?P<method>[A-Z]+)\s+(?P<target>\S+)(?:\s+HTTP/(?P<http_version>[\d.]+))?"\s+'
    r'(?P<status>\d{3})\s+(?P<size>\S+)'
    r'(?:\s+"(?P<referrer>[^"]*)"\s+"(?P<user_agent>[^"]*)")?$'
)

SQL_INJECTION_PATTERNS = (
    re.compile(r"\bunion\s+(?:all\s+)?select\b", re.IGNORECASE),
    re.compile(r"(?:'|%27)\s*or\s+(?:'1'='1|1=1)", re.IGNORECASE),
    re.compile(r"\b(?:sleep|benchmark)\s*\(", re.IGNORECASE),
    re.compile(r"\binformation_schema\b", re.IGNORECASE),
)

SENSITIVE_PATHS = (
    "/.env",
    "/.git",
    "/admin",
    "/phpmyadmin",
    "/wp-admin",
    "/wp-login.php",
)

SCANNER_USER_AGENTS = (
    "sqlmap",
    "nikto",
    "nmap",
    "masscan",
    "gobuster",
    "dirbuster",
    "wpscan",
)

SAMPLE_LOG = '''198.51.100.10 - - [25/Nov/2026:10:00:01 +0000] "GET / HTTP/1.1" 200 4210 "-" "Mozilla/5.0"
198.51.100.10 - - [25/Nov/2026:10:00:02 +0000] "GET /assets/app.css HTTP/1.1" 200 1820 "https://example.test/" "Mozilla/5.0"
203.0.113.50 - - [25/Nov/2026:10:01:10 +0000] "POST /login HTTP/1.1" 401 312 "-" "Mozilla/5.0"
203.0.113.50 - - [25/Nov/2026:10:01:14 +0000] "POST /login HTTP/1.1" 401 312 "-" "Mozilla/5.0"
203.0.113.50 - - [25/Nov/2026:10:01:19 +0000] "POST /login HTTP/1.1" 401 312 "-" "Mozilla/5.0"
192.0.2.77 - - [25/Nov/2026:10:02:01 +0000] "GET /.env HTTP/1.1" 404 153 "-" "sqlmap/1.8"
192.0.2.77 - - [25/Nov/2026:10:02:02 +0000] "GET /admin HTTP/1.1" 404 153 "-" "sqlmap/1.8"
192.0.2.77 - - [25/Nov/2026:10:02:03 +0000] "GET /wp-login.php HTTP/1.1" 404 153 "-" "sqlmap/1.8"
192.0.2.77 - - [25/Nov/2026:10:02:04 +0000] "GET /phpmyadmin HTTP/1.1" 404 153 "-" "sqlmap/1.8"
192.0.2.77 - - [25/Nov/2026:10:02:05 +0000] "GET /backup.zip HTTP/1.1" 404 153 "-" "sqlmap/1.8"
192.0.2.88 - - [25/Nov/2026:10:03:01 +0000] "GET /download?file=../../etc/passwd HTTP/1.1" 400 221 "-" "curl/8.5"
192.0.2.99 - - [25/Nov/2026:10:04:01 +0000] "GET /products?id=1%20UNION%20SELECT%20password%20FROM%20users HTTP/1.1" 400 221 "-" "curl/8.5"
192.0.2.44 - - [25/Nov/2026:10:05:01 +0000] "DELETE /api/users/42 HTTP/1.1" 405 198 "-" "curl/8.5"'''


class AnalysisError(ValueError):
    """A user-correctable analysis error with an HTTP-friendly status."""

    def __init__(self, message: str, status_code: int = 400) -> None:
        super().__init__(message)
        self.status_code = status_code


@dataclass(frozen=True)
class LogEntry:
    ip: str
    timestamp: str
    method: str
    target: str
    path: str
    status: int
    size: int | None
    referrer: str
    user_agent: str


def parse_log_line(line: str) -> LogEntry | None:
    """Parse one Apache/Nginx common or combined-format access-log line."""

    match = LOG_PATTERN.match(line.strip())
    if not match:
        return None

    data = match.groupdict(default="")
    try:
        status = int(data["status"])
        size = None if data["size"] == "-" else int(data["size"])
    except ValueError:
        return None

    decoded_target = unquote(data["target"])
    path = urlsplit(decoded_target).path or "/"
    return LogEntry(
        ip=data["ip"],
        timestamp=data["timestamp"],
        method=data["method"],
        target=data["target"],
        path=path,
        status=status,
        size=size,
        referrer=data["referrer"],
        user_agent=data["user_agent"],
    )


def _status_group(status: int) -> str:
    return f"{status // 100}xx" if 100 <= status <= 599 else "other"


def _record_alert(
    alerts: dict[tuple[str, str], dict[str, Any]],
    alert_type: str,
    severity: str,
    source_ip: str,
    description: str,
    evidence: str,
) -> None:
    key = (alert_type, source_ip)
    if key not in alerts:
        alerts[key] = {
            "type": alert_type,
            "severity": severity,
            "source_ip": source_ip,
            "description": description,
            "count": 0,
            "evidence": [],
        }

    alert = alerts[key]
    alert["count"] += 1
    if evidence not in alert["evidence"] and len(alert["evidence"]) < 3:
        alert["evidence"].append(evidence)


def _detect_alerts(entries: list[LogEntry]) -> list[dict[str, Any]]:
    alerts: dict[tuple[str, str], dict[str, Any]] = {}
    auth_failures: dict[str, list[str]] = defaultdict(list)
    not_found_paths: dict[str, set[str]] = defaultdict(set)

    for entry in entries:
        decoded_target = unquote(entry.target).lower()
        lower_path = entry.path.lower()
        lower_agent = entry.user_agent.lower()

        if any(lower_path == path or lower_path.startswith(f"{path}/") for path in SENSITIVE_PATHS):
            _record_alert(
                alerts,
                "sensitive_resource_probe",
                "medium",
                entry.ip,
                "A request targeted a commonly exposed administrative or secret resource.",
                entry.target,
            )

        if "../" in decoded_target or "%2e%2e" in entry.target.lower():
            _record_alert(
                alerts,
                "path_traversal_attempt",
                "high",
                entry.ip,
                "The request contains a directory-traversal sequence.",
                entry.target,
            )

        if any(pattern.search(decoded_target) for pattern in SQL_INJECTION_PATTERNS):
            _record_alert(
                alerts,
                "sql_injection_pattern",
                "critical",
                entry.ip,
                "The request contains a common SQL-injection signature.",
                entry.target,
            )

        if "<script" in decoded_target or "javascript:" in decoded_target:
            _record_alert(
                alerts,
                "cross_site_scripting_pattern",
                "high",
                entry.ip,
                "The request contains a common cross-site scripting signature.",
                entry.target,
            )

        if any(scanner in lower_agent for scanner in SCANNER_USER_AGENTS):
            _record_alert(
                alerts,
                "scanner_user_agent",
                "medium",
                entry.ip,
                "The user agent identifies a common reconnaissance or scanning tool.",
                entry.user_agent,
            )

        if entry.method not in {"GET", "POST", "HEAD", "OPTIONS"}:
            _record_alert(
                alerts,
                "unusual_http_method",
                "medium",
                entry.ip,
                "The request used a method outside the configured common web-method set.",
                f"{entry.method} {entry.target}",
            )

        if entry.status in {401, 403} and any(
            token in lower_path for token in ("login", "signin", "auth", "admin")
        ):
            auth_failures[entry.ip].append(entry.target)

        if entry.status == 404:
            not_found_paths[entry.ip].add(entry.path)

        if entry.status >= 500:
            _record_alert(
                alerts,
                "server_error",
                "low",
                entry.ip,
                "The request resulted in a server-side error that may need operational review.",
                f"{entry.status} {entry.target}",
            )

    for source_ip, targets in auth_failures.items():
        if len(targets) >= 3:
            for target in targets:
                _record_alert(
                    alerts,
                    "repeated_authentication_failures",
                    "high",
                    source_ip,
                    "Three or more authentication failures came from one source.",
                    target,
                )

    for source_ip, paths in not_found_paths.items():
        if len(paths) >= 5:
            for path in sorted(paths):
                _record_alert(
                    alerts,
                    "possible_path_enumeration",
                    "medium",
                    source_ip,
                    "Five or more distinct missing paths were requested by one source.",
                    path,
                )

    severity_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    return sorted(
        alerts.values(),
        key=lambda item: (severity_rank[item["severity"]], -item["count"], item["type"]),
    )


def _risk_summary(alerts: list[dict[str, Any]]) -> tuple[int, str]:
    weights = {"critical": 32, "high": 20, "medium": 9, "low": 3}
    score = min(
        100,
        sum(weights[alert["severity"]] + min(alert["count"] - 1, 5) for alert in alerts),
    )
    if score == 0:
        return score, "none"
    if score < 20:
        return score, "low"
    if score < 45:
        return score, "medium"
    if score < 70:
        return score, "high"
    return score, "critical"


def analyse_log(log_text: str) -> dict[str, Any]:
    """Validate and analyse a bounded batch of web access-log text."""

    if not isinstance(log_text, str) or not log_text.strip():
        raise AnalysisError("log_text must be a non-empty string")
    if len(log_text.encode("utf-8")) > MAX_INPUT_BYTES:
        raise AnalysisError(
            f"Input exceeds the {MAX_INPUT_BYTES // 1000} KB analysis limit", 413
        )

    lines = [line.strip() for line in log_text.splitlines() if line.strip()]
    if len(lines) > MAX_LOG_LINES:
        raise AnalysisError(f"Input exceeds the {MAX_LOG_LINES}-line analysis limit", 413)

    entries: list[LogEntry] = []
    rejected_line_numbers: list[int] = []
    for line_number, line in enumerate(lines, start=1):
        parsed = parse_log_line(line)
        if parsed is None:
            rejected_line_numbers.append(line_number)
        else:
            entries.append(parsed)

    if not entries:
        raise AnalysisError(
            "No supported access-log lines were found; use Apache/Nginx common or combined format"
        )

    methods = Counter(entry.method for entry in entries)
    statuses = Counter(str(entry.status) for entry in entries)
    status_groups = Counter(_status_group(entry.status) for entry in entries)
    paths = Counter(entry.path for entry in entries)
    alerts = _detect_alerts(entries)
    risk_score, risk_level = _risk_summary(alerts)
    severity_counts = Counter(alert["severity"] for alert in alerts)

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "format": "Apache/Nginx common or combined access log",
        "summary": {
            "total_lines": len(lines),
            "parsed_lines": len(entries),
            "rejected_lines": len(rejected_line_numbers),
            "rejected_line_numbers": rejected_line_numbers[:10],
            "unique_ips": len({entry.ip for entry in entries}),
            "method_counts": dict(sorted(methods.items())),
            "status_counts": dict(sorted(statuses.items())),
            "status_groups": {
                group: status_groups.get(group, 0)
                for group in ("1xx", "2xx", "3xx", "4xx", "5xx", "other")
            },
            "top_paths": [
                {"path": path, "count": count} for path, count in paths.most_common(8)
            ],
        },
        "risk": {
            "score": risk_score,
            "level": risk_level,
            "severity_counts": {
                severity: severity_counts.get(severity, 0)
                for severity in ("critical", "high", "medium", "low")
            },
        },
        "alerts": alerts,
    }
