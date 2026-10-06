"""Renderização do relatório (texto colorido e JSON)."""

from __future__ import annotations

import json
from collections import Counter, defaultdict
from typing import Dict, List, Optional

from . import __version__
from .detector import AnalysisResult, Finding
from .rules import SEVERITIES

_COLORS = {
    "critical": "1;31", "high": "31", "medium": "33", "low": "36",
    "bold": "1", "dim": "2", "green": "32",
}


def _paint(text: str, style: str, enabled: bool) -> str:
    if not enabled:
        return text
    return f"\033[{_COLORS[style]}m{text}\033[0m"


def summarize(result: AnalysisResult, findings: List[Finding]) -> dict:
    by_severity = Counter(f.severity for f in findings)
    by_category = Counter(f.category for f in findings)
    by_ip: Dict[str, List[Finding]] = defaultdict(list)
    for f in findings:
        by_ip[f.ip].append(f)
    top_ips = sorted(by_ip.items(), key=lambda kv: -len(kv[1]))
    return {
        "total_lines": result.total_lines,
        "parsed_lines": result.parsed_lines,
        "malformed_lines": result.malformed_lines,
        "unique_ips": result.unique_ips,
        "total_findings": len(findings),
        "possible_success": sum(1 for f in findings if f.possible_success),
        "by_severity": {s: by_severity.get(s, 0)
                        for s in sorted(SEVERITIES, key=SEVERITIES.get, reverse=True)},
        "by_category": dict(by_category.most_common()),
        "top_ips": [
            {"ip": ip, "findings": len(items),
             "categories": sorted({f.category for f in items})}
            for ip, items in top_ips
        ],
    }


def render_json(result: AnalysisResult, findings: List[Finding], source: str) -> str:
    payload = {
        "tool": "LogGuard", "version": __version__, "source": source,
        "summary": summarize(result, findings),
        "findings": [f.to_dict() for f in findings],
    }
    return json.dumps(payload, ensure_ascii=False, indent=2)


def render_text(result: AnalysisResult, findings: List[Finding], source: str,
                color: bool = True, limit: int = 0, summary_only: bool = False,
                top: int = 5) -> str:
    s = summarize(result, findings)
    out: List[str] = []
    line = "=" * 72

    out += [line, _paint(f"LogGuard v{__version__} - Relatório de análise", "bold", color), line]
    out.append(f"Fonte .............. {source}")
    out.append(f"Linhas ............. {s['total_lines']} "
               f"(interpretadas: {s['parsed_lines']}, malformadas: {s['malformed_lines']})")
    out.append(f"IPs únicos ......... {s['unique_ips']}")
    sev = "  ".join(_paint(f"{k}: {v}", k, color) if v else f"{k}: {v}"
                    for k, v in s["by_severity"].items())
    out.append(f"Achados ............ {s['total_findings']}  ({sev})")
    if s["possible_success"]:
        out.append(_paint(f"Atenção ............ {s['possible_success']} ataque(s) com "
                          "resposta HTTP 2xx (podem ter funcionado!)", "critical", color))
    out.append("")

    if not findings:
        out.append(_paint("Nenhuma atividade suspeita encontrada.", "green", color))
        return "\n".join(out)

    if not summary_only:
        out.append(_paint("DETALHES", "bold", color))
        out.append("-" * 72)
        shown = findings if limit <= 0 else findings[:limit]
        for f in shown:
            tag = _paint(f"[{f.severity.upper():8}]", f.severity, color)
            flag = _paint(" 2xx!", "critical", color) if f.possible_success else ""
            out.append(f"{tag} linha {f.lineno:<5} {f.ip:<15} {f.rule_id:<8} "
                       f"{f.category} | HTTP {f.status}{flag}")
            out.append(_paint(f"           -> {f.description}: {f.evidence}", "dim", color))
        if limit > 0 and len(findings) > limit:
            out.append(f"... e mais {len(findings) - limit} achados (use --limit 0 para ver todos)")
        out.append("")

    out.append(_paint("POR CATEGORIA", "bold", color))
    out.append("-" * 72)
    for category, count in s["by_category"].items():
        out.append(f"  {category:<26} {count}")
    out.append("")

    out.append(_paint(f"TOP {top} IPs SUSPEITOS", "bold", color))
    out.append("-" * 72)
    for item in s["top_ips"][:top]:
        out.append(f"  {item['ip']:<16} {item['findings']:>3} achados  "
                   f"{', '.join(item['categories'])}")
    return "\n".join(out)
