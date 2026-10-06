import unittest

from logguard.detector import analyze_lines
from logguard.rules import CAT_BRUTE, CAT_DIRSCAN
from tests.helpers import make_line


def behavioral(result, category):
    return [f for f in result.findings if f.category == category]


class BruteForceTests(unittest.TestCase):
    def test_below_threshold_is_clean(self):
        lines = [make_line("/login", ip="9.9.9.9", status=401, method="POST")] * 9
        self.assertEqual(behavioral(analyze_lines(lines), CAT_BRUTE), [])

    def test_at_threshold_triggers_once(self):
        lines = [make_line("/login", ip="9.9.9.9", status=401, method="POST")] * 10
        found = behavioral(analyze_lines(lines), CAT_BRUTE)
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].ip, "9.9.9.9")
        self.assertEqual(found[0].lineno, 10)

    def test_counts_401_and_403_together(self):
        lines = ([make_line("/login", ip="9.9.9.9", status=401)] * 5 +
                 [make_line("/admin", ip="9.9.9.9", status=403)] * 5)
        self.assertEqual(len(behavioral(analyze_lines(lines), CAT_BRUTE)), 1)

    def test_custom_threshold(self):
        lines = [make_line("/login", ip="9.9.9.9", status=401)] * 3
        self.assertEqual(len(behavioral(analyze_lines(lines, brute_threshold=3), CAT_BRUTE)), 1)

    def test_ips_are_not_mixed(self):
        lines = []
        for i in range(10):
            lines.append(make_line("/login", ip=f"9.9.9.{i}", status=401))
        self.assertEqual(behavioral(analyze_lines(lines), CAT_BRUTE), [])


class DirectoryScanTests(unittest.TestCase):
    def test_below_threshold_is_clean(self):
        lines = [make_line(f"/x{i}", ip="8.8.8.8", status=404) for i in range(19)]
        self.assertEqual(behavioral(analyze_lines(lines), CAT_DIRSCAN), [])

    def test_at_threshold_triggers_with_sample_paths(self):
        lines = [make_line(f"/x{i}", ip="8.8.8.8", status=404) for i in range(20)]
        found = behavioral(analyze_lines(lines), CAT_DIRSCAN)
        self.assertEqual(len(found), 1)
        self.assertIn("/x0", found[0].evidence)
        self.assertIn("20 respostas 404", found[0].evidence)

    def test_custom_threshold(self):
        lines = [make_line(f"/x{i}", ip="8.8.8.8", status=404) for i in range(5)]
        self.assertEqual(len(behavioral(analyze_lines(lines, scan_threshold=5), CAT_DIRSCAN)), 1)

    def test_invalid_threshold_rejected(self):
        with self.assertRaises(ValueError):
            analyze_lines([make_line()], brute_threshold=0)


class CountersTests(unittest.TestCase):
    def test_line_counters(self):
        lines = [make_line(), "lixo", "", make_line(ip="1.1.1.1")]
        r = analyze_lines(lines)
        self.assertEqual((r.total_lines, r.parsed_lines, r.malformed_lines), (3, 2, 1))
        self.assertEqual(r.unique_ips, 2)


if __name__ == "__main__":
    unittest.main()
