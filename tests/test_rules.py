import unittest

from logguard.rules import CAT_CMDI, CAT_PATH, CAT_SCANNER, CAT_SQLI, CAT_TRAVERSAL, CAT_XSS, normalize
from tests.helpers import categories_for, findings_for, make_line


class NormalizeTests(unittest.TestCase):
    def test_url_decoding_and_double_encoding(self):
        self.assertEqual(normalize("%2e%2e%2f"), "../")
        self.assertEqual(normalize("%252e%252e%252f"), "../")

    def test_plus_and_sql_comment(self):
        self.assertEqual(normalize("a+b"), "a b")
        self.assertEqual(normalize("UNION/**/SELECT"), "UNION SELECT")

    def test_apache_hex_escape(self):
        self.assertEqual(normalize(r"\x3cscript\x3e"), "<script>")


class SqlInjectionTests(unittest.TestCase):
    CASES = {
        "UNION SELECT": "/p?id=1%20UNION%20SELECT%20user,pass%20FROM%20users",
        "UNION ALL SELECT": "/p?id=1+UNION+ALL+SELECT+1,2",
        "OR 1=1": "/p?id=1%20OR%201=1",
        "OR '1'='1'": "/login?u=admin'%20OR%20'1'='1",
        ";--": "/p?id=1;--",
        "SLEEP()": "/p?id=1%20AND%20SLEEP(5)",
        "INFORMATION_SCHEMA": "/p?q=information_schema.tables",
        "comentario /**/": "/p?id=1%20UNION/**/SELECT%20null",
    }

    def test_detected(self):
        for name, target in self.CASES.items():
            with self.subTest(name):
                self.assertIn(CAT_SQLI, categories_for(target))


class XssTests(unittest.TestCase):
    CASES = {
        "<script> cru": "/s?q=<script>alert(1)</script>",
        "<script> encoded": "/s?q=%3Cscript%3E",
        "onerror=": "/s?q=<img%20src=x%20onerror=x>",
        "alert(": "/s?q=alert(1)",
        "document.cookie": "/s?q=document.cookie",
    }

    def test_detected(self):
        for name, target in self.CASES.items():
            with self.subTest(name):
                self.assertIn(CAT_XSS, categories_for(target))


class PathTraversalTests(unittest.TestCase):
    CASES = {
        "../": "/d?f=../../etc/hosts",
        "%2e%2e%2f": "/d?f=%2e%2e%2f%2e%2e%2fapp.conf",
        "%252e (double encoding)": "/d?f=%252e%252e%252fapp.conf",
        "..\\ (windows)": "/d?f=..%5c..%5cwindows",
        "/etc/passwd": "/d?f=/etc/passwd",
    }

    def test_detected(self):
        for name, target in self.CASES.items():
            with self.subTest(name):
                self.assertIn(CAT_TRAVERSAL, categories_for(target))


class CommandInjectionTests(unittest.TestCase):
    CASES = {
        "; cat": "/ping?h=1.1.1.1;%20cat%20/tmp/x",
        "| ls": "/ping?h=1.1.1.1%20|%20ls",
        "`id`": "/ping?h=%60id%60",
        "$(whoami)": "/ping?h=$(whoami)",
    }

    def test_detected(self):
        for name, target in self.CASES.items():
            with self.subTest(name):
                self.assertIn(CAT_CMDI, categories_for(target))


class ScannerTests(unittest.TestCase):
    def test_known_user_agents(self):
        for ua in ["sqlmap/1.8#stable", "Nikto/2.5.0", "Nmap Scripting Engine",
                   "DirBuster-1.0-RC1", "Mozilla/5.0 (compatible; Burp Suite)",
                   "gobuster/3.6", "WPScan v3.8"]:
            with self.subTest(ua):
                self.assertIn(CAT_SCANNER, categories_for("/", ua=ua))


class SensitivePathTests(unittest.TestCase):
    def test_sensitive_paths(self):
        for path in ["/.env", "/.env.production", "/.git/config", "/phpmyadmin/",
                     "/wp-login.php", "/backup.sql", "/app/.git/HEAD"]:
            with self.subTest(path):
                self.assertIn(CAT_PATH, categories_for(path))

    def test_success_flag_on_2xx(self):
        found = findings_for(make_line("/.env", status=200))
        self.assertTrue(all(f.possible_success for f in found))
        found = findings_for(make_line("/.env", status=404))
        self.assertFalse(any(f.possible_success for f in found))


class FalsePositiveTests(unittest.TestCase):
    BENIGN = [
        "/", "/index.html", "/produtos?id=12", "/css/app.css?v=1.2.3",
        "/search?q=select+a+plan", "/search?q=how+to+alert+users",
        "/search?q=union+of+states", "/api/v1/items?page=2&sort=name",
        "/blog/2026/10/meu-post", "/produtos?a=1&id=5&b=2", "/shop?x=1;shop=2",
        "/files/relatorio-2026.pdf", "/img/photo.jpg?w=200&h=100",
    ]

    def test_benign_requests_are_clean(self):
        for target in self.BENIGN:
            with self.subTest(target):
                self.assertEqual(findings_for(make_line(target)), [])

    def test_regular_browser_is_clean(self):
        ua = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/126.0 Safari/537.36")
        self.assertEqual(findings_for(make_line("/", ua=ua)), [])


if __name__ == "__main__":
    unittest.main()
