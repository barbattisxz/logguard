#!/usr/bin/env python3
"""Gera um access.log de demonstração (tráfego legítimo + ataques simulados).

Os IPs usados pertencem às faixas reservadas para documentação (RFC 5737),
então nada aqui aponta para máquinas reais. Os "ataques" são apenas linhas de
texto: o LogGuard só LÊ logs, nunca envia requisições.

Uso:
    python samples/generate_sample_log.py [saida.log]
"""

import random
import sys
from datetime import datetime, timedelta, timezone

MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
          "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]
BROWSER = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
           "(KHTML, like Gecko) Chrome/126.0 Safari/537.36")

LEGIT_PATHS = [
    "/", "/index.html", "/sobre", "/contato", "/produtos?id=12", "/produtos?id=48",
    "/css/app.css", "/js/app.js", "/img/logo.png", "/api/v1/items?page=2",
    "/blog/post-1", "/blog/post-2", "/search?q=select+a+plan",
    "/search?q=how+to+alert+users", "/login",
]


def stamp(moment: datetime) -> str:
    tz = moment.strftime("%z")
    return (f"{moment.day:02d}/{MONTHS[moment.month - 1]}/{moment.year}:"
            f"{moment.strftime('%H:%M:%S')} {tz}")


def line(ip, moment, target, status, ua=BROWSER, method="GET", size=None, rng=None):
    size = size if size is not None else (rng or random).randint(200, 9000)
    return (f'{ip} - - [{stamp(moment)}] "{method} {target} HTTP/1.1" '
            f'{status} {size} "-" "{ua}"')


def generate(path: str, seed: int = 42) -> int:
    rng = random.Random(seed)
    start = datetime(2026, 10, 5, 10, 0, 0, tzinfo=timezone(timedelta(hours=-3)))
    events = []  # (segundos_desde_início, texto)

    def add(sec, ip, target, status, **kw):
        events.append((sec, line(ip, start + timedelta(seconds=sec), target,
                                 status, rng=rng, **kw)))

    # 1) Tráfego legítimo (inclui alguns 404 e 401 isolados, abaixo dos limiares)
    legit_ips = [f"203.0.113.{n}" for n in range(10, 22)]
    for _ in range(120):
        ip = rng.choice(legit_ips)
        status = rng.choices([200, 304, 404, 401], weights=[85, 8, 5, 2])[0]
        add(rng.randint(0, 900), ip, rng.choice(LEGIT_PATHS), status)

    # 2) SQL Injection com sqlmap
    sqli = [
        "/produtos?id=1%20UNION%20SELECT%20username,password%20FROM%20users",
        "/produtos?id=1%20OR%201=1",
        "/login?user=admin'%20OR%20'1'='1&pass=x",
        "/produtos?id=1;--",
        "/produtos?id=1%20AND%20SLEEP(5)",
        "/produtos?id=1%20UNION%20SELECT%20table_name%20FROM%20INFORMATION_SCHEMA.TABLES",
        "/produtos?id=1%20UNION/**/SELECT%20null,null",
    ]
    for i, target in enumerate(sqli):
        add(100 + i * 3, "198.51.100.23", target, rng.choice([200, 500, 403]),
            ua="sqlmap/1.8#stable (https://sqlmap.org)")

    # 3) XSS
    xss = [
        "/search?q=<script>alert(1)</script>",
        "/search?q=%3Cscript%3Edocument.cookie%3C/script%3E",
        "/comentario?t=<img%20src=x%20onerror=alert(1)>",
        "/search?q=javascript:alert(document.cookie)",
    ]
    for i, target in enumerate(xss):
        add(200 + i * 4, "198.51.100.77", target, rng.choice([200, 200, 400]))

    # 4) Path Traversal
    trav = [
        "/download?file=../../../../etc/passwd",
        "/download?file=%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "/download?file=%252e%252e%252f%252e%252e%252fetc%252fshadow",
    ]
    for i, target in enumerate(trav):
        add(300 + i * 5, "198.51.100.99", target, rng.choice([200, 403, 404]))

    # 5) Command Injection
    cmdi = [
        "/ping?host=8.8.8.8;%20cat%20/etc/passwd",
        "/ping?host=8.8.8.8%20|%20ls%20-la",
        "/ping?host=%60id%60",
        "/ping?host=$(whoami)",
    ]
    for i, target in enumerate(cmdi):
        add(400 + i * 4, "192.0.2.55", target, rng.choice([200, 500]))

    # 6) Scanners por User-Agent
    for i, ua in enumerate(["Nikto/2.5.0", "Nmap Scripting Engine; https://nmap.org/book/nse.html",
                            "DirBuster-1.0-RC1 (http://www.owasp.org)",
                            "Mozilla/5.0 (compatible; Burp Suite)"]):
        add(500 + i * 6, "192.0.2.77", "/", 200, ua=ua)

    # 7) Caminhos sensíveis
    for i, (target, status) in enumerate([
            ("/.env", 200), ("/.git/config", 200), ("/phpmyadmin/", 404),
            ("/wp-login.php", 404), ("/backup.sql", 403)]):
        add(600 + i * 4, "192.0.2.66", target, status)

    # 8) Brute force: 15 falhas de login no mesmo IP
    for i in range(15):
        add(700 + i * 2, "203.0.113.200", "/login", rng.choice([401, 401, 403]),
            method="POST")

    # 9) Varredura de diretórios: 30 x 404 com UA de navegador comum
    for i in range(30):
        add(800 + i, "203.0.113.201", f"/dir{i:02d}/", 404)

    events.sort(key=lambda e: e[0])
    with open(path, "w", encoding="utf-8") as handle:
        handle.write("\n".join(text for _, text in events) + "\n")
    return len(events)


if __name__ == "__main__":
    out = sys.argv[1] if len(sys.argv) > 1 else "samples/access_demo.log"
    total = generate(out)
    print(f"{total} linhas gravadas em {out}")
