"""Utilitários compartilhados pelos testes."""

from logguard.detector import Analyzer
from logguard.parser import parse_line

DEFAULT_UA = "Mozilla/5.0"


def make_line(target="/index.html", ip="203.0.113.10", status=200,
              ua=DEFAULT_UA, method="GET"):
    return (f'{ip} - - [05/Oct/2026:10:00:01 -0300] "{method} {target} HTTP/1.1" '
            f'{status} 512 "-" "{ua}"')


def findings_for(line):
    """Roda só as regras por linha e devolve a lista de achados."""
    entry = parse_line(line, 1)
    assert entry is not None, f"linha não parseou: {line}"
    return Analyzer().process(entry)


def categories_for(target, **kwargs):
    return {f.category for f in findings_for(make_line(target, **kwargs))}
