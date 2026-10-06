import unittest

from logguard.parser import parse_line
from tests.helpers import make_line


class ParserTests(unittest.TestCase):
    def test_combined_format(self):
        e = parse_line(make_line("/produtos?id=12", ip="203.0.113.5", status=404), 7)
        self.assertEqual(e.lineno, 7)
        self.assertEqual(e.ip, "203.0.113.5")
        self.assertEqual(e.method, "GET")
        self.assertEqual(e.path, "/produtos")
        self.assertEqual(e.query, "id=12")
        self.assertEqual(e.protocol, "HTTP/1.1")
        self.assertEqual(e.status, 404)
        self.assertEqual(e.size, 512)
        self.assertEqual(e.user_agent, "Mozilla/5.0")
        self.assertIsNotNone(e.time)

    def test_common_format_without_referer_and_agent(self):
        raw = '10.0.0.1 - bob [05/Oct/2026:10:00:01 -0300] "GET / HTTP/1.1" 200 -'
        e = parse_line(raw)
        self.assertIsNotNone(e)
        self.assertEqual(e.user, "bob")
        self.assertEqual(e.size, 0)
        self.assertEqual(e.user_agent, "")

    def test_raw_spaces_inside_url_are_preserved(self):
        raw = ('1.2.3.4 - - [05/Oct/2026:10:00:01 -0300] '
               '"GET /a?id=1 UNION SELECT 1 HTTP/1.1" 200 10 "-" "x"')
        e = parse_line(raw)
        self.assertEqual(e.target, "/a?id=1 UNION SELECT 1")

    def test_empty_request_dash(self):
        raw = '1.2.3.4 - - [05/Oct/2026:10:00:01 -0300] "-" 408 0 "-" "-"'
        e = parse_line(raw)
        self.assertEqual(e.status, 408)
        self.assertEqual(e.target, "-")

    def test_malformed_lines_return_none(self):
        for bad in ["", "lixo qualquer", "1.2.3.4 - - sem colchetes", "GET / HTTP/1.1"]:
            self.assertIsNone(parse_line(bad), bad)


if __name__ == "__main__":
    unittest.main()
