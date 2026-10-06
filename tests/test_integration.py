"""Testes de ponta a ponta: gerador de log de demonstração + CLI."""

import contextlib
import importlib.util
import io
import json
import os
import tempfile
import unittest

from logguard.cli import main
from logguard.detector import analyze_file
from logguard.rules import (CAT_BRUTE, CAT_CMDI, CAT_DIRSCAN, CAT_PATH,
                            CAT_SCANNER, CAT_SQLI, CAT_TRAVERSAL, CAT_XSS)
from tests.helpers import make_line

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def load_generator():
    path = os.path.join(ROOT, "samples", "generate_sample_log.py")
    spec = importlib.util.spec_from_file_location("generate_sample_log", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def run_cli(*argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            code = main(list(argv))
        except SystemExit as exc:  # argparse
            code = exc.code
    return code, out.getvalue(), err.getvalue()


class DemoLogTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.log = os.path.join(cls.tmp.name, "demo.log")
        load_generator().generate(cls.log)
        cls.result = analyze_file(cls.log)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_all_eight_categories_are_detected(self):
        found = {f.category for f in self.result.findings}
        self.assertEqual(found, {CAT_SQLI, CAT_XSS, CAT_TRAVERSAL, CAT_CMDI,
                                 CAT_SCANNER, CAT_PATH, CAT_BRUTE, CAT_DIRSCAN})

    def test_attackers_are_attributed_to_the_right_ip(self):
        by_cat = {}
        for f in self.result.findings:
            by_cat.setdefault(f.category, set()).add(f.ip)
        self.assertEqual(by_cat[CAT_SQLI], {"198.51.100.23"})
        self.assertEqual(by_cat[CAT_XSS], {"198.51.100.77"})
        # "; cat /etc/passwd" (command injection) também toca em arquivo de sistema
        self.assertEqual(by_cat[CAT_TRAVERSAL], {"198.51.100.99", "192.0.2.55"})
        self.assertEqual(by_cat[CAT_CMDI], {"192.0.2.55"})
        self.assertEqual(by_cat[CAT_BRUTE], {"203.0.113.200"})
        self.assertEqual(by_cat[CAT_DIRSCAN], {"203.0.113.201"})

    def test_legitimate_visitors_have_zero_findings(self):
        legit = {f"203.0.113.{n}" for n in range(10, 22)}
        flagged = {f.ip for f in self.result.findings}
        self.assertEqual(legit & flagged, set())


class CliTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def write(self, name, lines):
        path = os.path.join(self.tmp.name, name)
        with open(path, "w", encoding="utf-8") as handle:
            handle.write("\n".join(lines) + "\n")
        return path

    def test_clean_log_exit_0(self):
        path = self.write("ok.log", [make_line(), make_line("/sobre")])
        code, out, _ = run_cli(path, "--no-color")
        self.assertEqual(code, 0)
        self.assertIn("Nenhuma atividade suspeita", out)

    def test_attack_log_exit_1(self):
        path = self.write("bad.log", [make_line("/p?id=1%20OR%201=1")])
        code, out, _ = run_cli(path, "--no-color")
        self.assertEqual(code, 1)
        self.assertIn("SQLI-002", out)

    def test_json_output_is_valid(self):
        path = self.write("bad.log", [make_line("/.env", status=200)])
        code, out, _ = run_cli(path, "--json")
        data = json.loads(out)
        self.assertEqual(code, 1)
        self.assertEqual(data["summary"]["total_findings"], 1)
        self.assertEqual(data["summary"]["possible_success"], 1)
        self.assertEqual(data["findings"][0]["rule_id"], "PATH-001")

    def test_min_severity_filters_findings(self):
        path = self.write("sev.log", [make_line("/wp-login.php", status=404)])  # medium
        self.assertEqual(run_cli(path, "--min-severity", "high")[0], 0)
        self.assertEqual(run_cli(path, "--min-severity", "medium")[0], 1)

    def test_missing_file_exit_2(self):
        code, _, err = run_cli(os.path.join(self.tmp.name, "nao_existe.log"))
        self.assertEqual(code, 2)
        self.assertIn("Erro", err)

    def test_invalid_threshold_exit_2(self):
        path = self.write("ok.log", [make_line()])
        self.assertEqual(run_cli(path, "--brute-threshold", "0")[0], 2)

    def test_threshold_flags_change_behavior(self):
        path = self.write("b.log", [make_line("/login", ip="9.9.9.9", status=401)] * 3)
        self.assertEqual(run_cli(path)[0], 0)
        self.assertEqual(run_cli(path, "--brute-threshold", "3")[0], 1)


if __name__ == "__main__":
    unittest.main()
