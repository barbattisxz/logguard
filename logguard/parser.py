"""Parser do Combined Log Format (Apache / Nginx).

Formato:
    %h %l %u %t "%r" %>s %b "%{Referer}i" "%{User-Agent}i"

Exemplo:
    203.0.113.10 - - [05/Oct/2026:10:00:01 -0300] "GET /index.html HTTP/1.1" 200 1024 "-" "Mozilla/5.0"
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime
from typing import Optional

# Referer e User-Agent são opcionais para também aceitar o "Common Log Format".
_LOG_RE = re.compile(
    r"^(?P<ip>\S+)\s+\S+\s+(?P<user>\S+)\s+\[(?P<time>[^\]]+)\]\s+"
    r'"(?P<request>(?:[^"\\]|\\.)*)"\s+(?P<status>\d{3})\s+(?P<size>\S+)'
    r'(?:\s+"(?P<referer>(?:[^"\\]|\\.)*)"\s+"(?P<ua>(?:[^"\\]|\\.)*)")?'
)


@dataclass(frozen=True)
class LogEntry:
    lineno: int
    ip: str
    user: str
    time_raw: str
    time: Optional[datetime]
    method: str
    target: str  # caminho + query string, exatamente como veio no log
    path: str
    query: str
    protocol: str
    status: int
    size: int
    referer: str
    user_agent: str
    raw: str


def _parse_time(raw: str) -> Optional[datetime]:
    try:
        return datetime.strptime(raw, "%d/%b/%Y:%H:%M:%S %z")
    except ValueError:
        return None


def parse_line(line: str, lineno: int = 0) -> Optional[LogEntry]:
    """Converte uma linha de log em LogEntry. Retorna None se for inválida."""
    line = line.strip()
    match = _LOG_RE.match(line)
    if not match:
        return None

    request = match.group("request")
    parts = request.split(" ")
    method = protocol = ""
    if len(parts) >= 3 and parts[-1].upper().startswith("HTTP/"):
        # Une o meio: ataques costumam deixar espaços crus na URL.
        method, protocol, target = parts[0], parts[-1], " ".join(parts[1:-1])
    elif len(parts) >= 2:
        method, target = parts[0], " ".join(parts[1:])
    else:
        target = request  # ex.: "-" (requisição vazia / timeout 408)

    path, _, query = target.partition("?")
    size_raw = match.group("size")

    return LogEntry(
        lineno=lineno,
        ip=match.group("ip"),
        user=match.group("user"),
        time_raw=match.group("time"),
        time=_parse_time(match.group("time")),
        method=method,
        target=target,
        path=path,
        query=query,
        protocol=protocol,
        status=int(match.group("status")),
        size=int(size_raw) if size_raw.isdigit() else 0,
        referer=match.group("referer") or "",
        user_agent=match.group("ua") or "",
        raw=line,
    )
