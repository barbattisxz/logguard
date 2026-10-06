"""Interface de linha de comando.

Códigos de saída:
    0 -> nenhum achado
    1 -> achados encontrados (útil em pipelines de CI)
    2 -> erro de uso (arquivo inexistente, parâmetro inválido)
"""

from __future__ import annotations

import argparse
import os
import sys
from typing import List, Optional

from . import __version__
from .detector import analyze_file, analyze_lines
from .report import render_json, render_text
from .rules import SEVERITIES


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="logguard",
        description="Mini-WAF: detecta ataques em logs Apache/Nginx (Combined Log Format).",
    )
    p.add_argument("logfile", help="caminho do access.log (use '-' para ler da entrada padrão)")
    p.add_argument("--brute-threshold", type=int, default=10, metavar="N",
                   help="respostas 401/403 por IP para acusar brute force (padrão: 10)")
    p.add_argument("--scan-threshold", type=int, default=20, metavar="N",
                   help="respostas 404 por IP para acusar varredura (padrão: 20)")
    p.add_argument("--min-severity", choices=sorted(SEVERITIES, key=SEVERITIES.get),
                   default="low", help="mostra apenas achados desta severidade para cima")
    p.add_argument("--json", action="store_true", help="saída em JSON")
    p.add_argument("--summary-only", action="store_true", help="mostra só o resumo")
    p.add_argument("--limit", type=int, default=0, metavar="N",
                   help="máximo de achados detalhados (0 = todos)")
    p.add_argument("--top", type=int, default=5, metavar="N", help="tamanho do ranking de IPs")
    p.add_argument("--no-color", action="store_true", help="desativa cores ANSI")
    p.add_argument("--version", action="version", version=f"LogGuard {__version__}")
    return p


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)

    if args.brute_threshold < 1 or args.scan_threshold < 1:
        print("Erro: os limiares devem ser >= 1", file=sys.stderr)
        return 2

    try:
        if args.logfile == "-":
            result = analyze_lines(sys.stdin, args.brute_threshold, args.scan_threshold)
            source = "<stdin>"
        else:
            result = analyze_file(args.logfile, args.brute_threshold, args.scan_threshold)
            source = args.logfile
    except OSError as exc:
        print(f"Erro ao ler '{args.logfile}': {exc.strerror}", file=sys.stderr)
        return 2

    findings = result.filtered(args.min_severity)

    if args.json:
        print(render_json(result, findings, source))
    else:
        color = (not args.no_color and sys.stdout.isatty()
                 and "NO_COLOR" not in os.environ)
        print(render_text(result, findings, source, color=color, limit=args.limit,
                          summary_only=args.summary_only, top=args.top))

    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
