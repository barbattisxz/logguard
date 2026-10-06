"""Motor de detecção: regras por linha + comportamento por IP."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import asdict, dataclass, field
from typing import Dict, Iterable, List, Optional, Set

from .parser import LogEntry, parse_line
from .rules import (CAT_BRUTE, CAT_DIRSCAN, RULES, SEVERITIES, Rule, normalize)

AUTH_FAIL_STATUSES = (401, 403)
NOT_FOUND_STATUS = 404


@dataclass
class Finding:
    lineno: int
    ip: str
    rule_id: str
    category: str
    severity: str
    description: str
    evidence: str
    status: int = 0
    timestamp: str = ""
    target: str = ""

    @property
    def possible_success(self) -> bool:
        """Ataque que o servidor respondeu com 2xx merece atenção extra."""
        return 200 <= self.status < 300

    def to_dict(self) -> dict:
        data = asdict(self)
        data["possible_success"] = self.possible_success
        return data


@dataclass
class AnalysisResult:
    total_lines: int = 0
    parsed_lines: int = 0
    malformed_lines: int = 0
    unique_ips: int = 0
    findings: List[Finding] = field(default_factory=list)

    def filtered(self, min_severity: str = "low") -> List[Finding]:
        floor = SEVERITIES[min_severity]
        return [f for f in self.findings if SEVERITIES[f.severity] >= floor]


class Analyzer:
    """Analisa entradas uma a uma e mantém contadores por IP."""

    def __init__(self, brute_threshold: int = 10, scan_threshold: int = 20,
                 rules: Optional[List[Rule]] = None) -> None:
        if brute_threshold < 1 or scan_threshold < 1:
            raise ValueError("Os limiares devem ser >= 1")
        self.brute_threshold = brute_threshold
        self.scan_threshold = scan_threshold
        self.rules = RULES if rules is None else rules

        self._auth_fail: Dict[str, int] = defaultdict(int)
        self._not_found: Dict[str, int] = defaultdict(int)
        self._auth_cross: Dict[str, Finding] = {}
        self._scan_cross: Dict[str, Finding] = {}
        self._scan_paths: Dict[str, List[str]] = defaultdict(list)
        self.ips: Set[str] = set()

    # ------------------------------------------------------------ por linha
    def process(self, entry: LogEntry) -> List[Finding]:
        self.ips.add(entry.ip)
        findings = self._match_rules(entry)
        self._track_behavior(entry)
        return findings

    def _match_rules(self, entry: LogEntry) -> List[Finding]:
        targets = {
            "request": normalize(entry.target),
            "path": normalize(entry.path),
            "user_agent": entry.user_agent,
        }
        findings: List[Finding] = []
        for rule in self.rules:
            match = rule.regex.search(targets[rule.target])
            if match:
                findings.append(Finding(
                    lineno=entry.lineno, ip=entry.ip, rule_id=rule.id,
                    category=rule.category, severity=rule.severity,
                    description=rule.description,
                    evidence=match.group(0).strip()[:80],
                    status=entry.status, timestamp=entry.time_raw,
                    target=entry.target[:120],
                ))
        return findings

    # ----------------------------------------------------- por padrão de IP
    def _track_behavior(self, entry: LogEntry) -> None:
        ip = entry.ip
        if entry.status in AUTH_FAIL_STATUSES:
            self._auth_fail[ip] += 1
            if self._auth_fail[ip] == self.brute_threshold:
                self._auth_cross[ip] = Finding(
                    lineno=entry.lineno, ip=ip, rule_id="BEHAV-001",
                    category=CAT_BRUTE, severity="high",
                    description="Muitas respostas 401/403 do mesmo IP",
                    evidence="", status=entry.status, timestamp=entry.time_raw,
                )
        elif entry.status == NOT_FOUND_STATUS:
            self._not_found[ip] += 1
            if len(self._scan_paths[ip]) < 3 and entry.path not in self._scan_paths[ip]:
                self._scan_paths[ip].append(entry.path)
            if self._not_found[ip] == self.scan_threshold:
                self._scan_cross[ip] = Finding(
                    lineno=entry.lineno, ip=ip, rule_id="BEHAV-002",
                    category=CAT_DIRSCAN, severity="medium",
                    description="Pico de 404 do mesmo IP (varredura de diretórios)",
                    evidence="", status=entry.status, timestamp=entry.time_raw,
                )

    def finalize(self) -> List[Finding]:
        """Fecha os achados comportamentais com as contagens finais."""
        findings: List[Finding] = []
        for ip, finding in self._auth_cross.items():
            finding.evidence = (f"{self._auth_fail[ip]} respostas 401/403 "
                                f"(limiar {self.brute_threshold})")
            findings.append(finding)
        for ip, finding in self._scan_cross.items():
            sample = ", ".join(self._scan_paths[ip])
            finding.evidence = (f"{self._not_found[ip]} respostas 404 "
                                f"(limiar {self.scan_threshold}); ex.: {sample}")
            findings.append(finding)
        return findings


def analyze_lines(lines: Iterable[str], brute_threshold: int = 10,
                  scan_threshold: int = 20) -> AnalysisResult:
    analyzer = Analyzer(brute_threshold, scan_threshold)
    result = AnalysisResult()

    for lineno, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        result.total_lines += 1
        entry = parse_line(line, lineno)
        if entry is None:
            result.malformed_lines += 1
            continue
        result.parsed_lines += 1
        result.findings.extend(analyzer.process(entry))

    result.findings.extend(analyzer.finalize())
    result.findings.sort(key=lambda f: f.lineno)
    result.unique_ips = len(analyzer.ips)
    return result


def analyze_file(path: str, brute_threshold: int = 10,
                 scan_threshold: int = 20) -> AnalysisResult:
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        return analyze_lines(handle, brute_threshold, scan_threshold)
