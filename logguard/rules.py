"""Regras de detecção linha a linha (assinaturas).

Cada regra é uma expressão regular aplicada a um "alvo" da requisição:
    request     -> caminho + query string, já normalizados
    path        -> somente o caminho, já normalizado
    user_agent  -> cabeçalho User-Agent

Para adicionar uma regra nova, basta incluir uma linha em RULES.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List, Pattern
from urllib.parse import unquote_plus

SEVERITIES = {"low": 1, "medium": 2, "high": 3, "critical": 4}

CAT_SQLI = "SQL Injection"
CAT_XSS = "XSS"
CAT_TRAVERSAL = "Path Traversal"
CAT_CMDI = "Command Injection"
CAT_SCANNER = "Scanner Conhecido"
CAT_PATH = "Caminho Sensível"
CAT_BRUTE = "Brute Force"
CAT_DIRSCAN = "Varredura de Diretórios"

_HEX_ESCAPE = re.compile(r"\\x([0-9a-fA-F]{2})")
_SQL_COMMENT = re.compile(r"/\*.*?\*/")


def normalize(value: str, max_rounds: int = 3) -> str:
    """Desfaz as ofuscações mais comuns antes de aplicar as regras.

    - escapes \\xHH do Apache
    - URL-decode repetido (pega %2e e também %252e, o "double encoding")
    - '+' vira espaço
    - comentários SQL /**/ viram espaço (UNION/**/SELECT)
    - bytes nulos removidos
    """
    value = _HEX_ESCAPE.sub(lambda m: chr(int(m.group(1), 16)), value)
    for _ in range(max_rounds):
        decoded = unquote_plus(value)
        if decoded == value:
            break
        value = decoded
    value = value.replace("\x00", "")
    return _SQL_COMMENT.sub(" ", value)


@dataclass(frozen=True)
class Rule:
    id: str
    category: str
    severity: str
    description: str
    target: str  # "request" | "path" | "user_agent"
    regex: Pattern[str]


def _r(rule_id: str, category: str, severity: str, description: str,
       target: str, pattern: str) -> Rule:
    return Rule(rule_id, category, severity, description, target,
                re.compile(pattern, re.IGNORECASE))


RULES: List[Rule] = [
    # ---------------------------------------------------------- SQL Injection
    _r("SQLI-001", CAT_SQLI, "critical", "UNION SELECT", "request",
       r"\bunion\s+(?:all\s+|distinct\s+)?select\b"),
    _r("SQLI-002", CAT_SQLI, "high", "Tautologia numérica (OR 1=1)", "request",
       r"\b(?:or|and)\s+(\d+)\s*=\s*\1\b"),
    _r("SQLI-003", CAT_SQLI, "high", "Tautologia com aspas (OR '1'='1')", "request",
       r"\b(?:or|and)\s+(['\"])[^'\"]*\1\s*=\s*\1"),
    _r("SQLI-004", CAT_SQLI, "high", "Terminador/comentário SQL (;-- ou '--)", "request",
       r"(?:[;'\"]\s*--|['\"]\s*#)"),
    _r("SQLI-005", CAT_SQLI, "high", "Time-based blind (SLEEP/BENCHMARK/WAITFOR)", "request",
       r"\b(?:sleep|benchmark|pg_sleep)\s*\(\s*\d|\bwaitfor\s+delay\b"),
    _r("SQLI-006", CAT_SQLI, "high", "Enumeração via INFORMATION_SCHEMA", "request",
       r"\binformation_schema\b"),

    # --------------------------------------------------------------------- XSS
    _r("XSS-001", CAT_XSS, "high", "Tag <script>", "request",
       r"<\s*/?\s*script"),
    _r("XSS-002", CAT_XSS, "high", "Event handler (onerror=, onload=...)", "request",
       r"\bon(?:error|load|mouseover|focus)\s*="),
    _r("XSS-003", CAT_XSS, "medium", "Chamada alert()", "request",
       r"\balert\s*\("),
    _r("XSS-004", CAT_XSS, "high", "Roubo de cookie (document.cookie)", "request",
       r"document\.cookie"),
    _r("XSS-005", CAT_XSS, "medium", "URI javascript:", "request",
       r"javascript\s*:"),

    # --------------------------------------------------------- Path Traversal
    _r("TRAV-001", CAT_TRAVERSAL, "high", "Sequência ../ (inclui %2e%2e%2f e %252e)", "request",
       r"\.\.[/\\]"),
    _r("TRAV-002", CAT_TRAVERSAL, "high", "Arquivo de sistema sensível", "request",
       r"/etc/(?:passwd|shadow)|\b(?:boot|win)\.ini\b"),

    # ------------------------------------------------------ Command Injection
    _r("CMDI-001", CAT_CMDI, "critical", "Encadeamento de comando (; cat, | ls...)", "request",
       r"[;|]\s*(?:cat|ls|id|whoami|uname|pwd|wget|curl|nc|netcat|bash|sh|ping|ifconfig|rm)\b(?!\s*=)"),
    _r("CMDI-002", CAT_CMDI, "critical", "Substituição com crases (`id`)", "request",
       r"`\s*[a-z/][^`]{0,80}`"),
    _r("CMDI-003", CAT_CMDI, "critical", "Substituição $(comando)", "request",
       r"\$\(\s*[^)]{1,80}\)"),

    # ------------------------------------------------------ Scanners (User-Agent)
    _r("SCAN-001", CAT_SCANNER, "medium", "Ferramenta de ataque no User-Agent", "user_agent",
       r"sqlmap|nikto|nmap|dirbuster|gobuster|feroxbuster|burp|acunetix|wpscan|"
       r"masscan|havij|hydra|w3af|nuclei|owasp[ _-]?zap|zaproxy"),

    # ------------------------------------------------------- Caminhos sensíveis
    _r("PATH-001", CAT_PATH, "high", "Arquivo de segredo/repositório (.env, .git...)", "path",
       r"(?:^|/)\.env(?:\.[\w-]+)?(?:$|/)|/\.(?:git|svn|hg)(?:/|$)|/\.aws/credentials|"
       r"/id_rsa|/\.htpasswd|/\.ds_store"),
    _r("PATH-002", CAT_PATH, "medium", "Painel administrativo (phpMyAdmin, wp-login...)", "path",
       r"/phpmyadmin|/wp-login\.php|/xmlrpc\.php|/server-status|/adminer"),
    _r("PATH-003", CAT_PATH, "high", "Backup / dump de banco", "path",
       r"/backup\.(?:sql|zip|tar|gz|bak)|/(?:dump|database|db)\.sql|\.(?:bak|old|orig)$"),
]
