import os
import sys
import tempfile
import subprocess
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from src.rsa_helper import parse_rsa_text, run_rsa_mode, generate_rsa_report, RSAInput, wiener_attack, decode_plaintext

PROJECT_ROOT = os.path.join(os.path.dirname(__file__), "..")
SMALL_TROUBLE_TEXT = open(os.path.join(PROJECT_ROOT, "samples", "small-trouble-message.txt"), encoding="utf-8").read()
EXPECTED_FLAG = "picoCTF{sm4ll_d_57cacc98}"


class TestRSAParser(unittest.TestCase):
    def test_parse_rsa_text(self):
        rsa_input = parse_rsa_text(SMALL_TROUBLE_TEXT)
        self.assertIsInstance(rsa_input.n, int)
        self.assertIsInstance(rsa_input.e, int)
        self.assertIsInstance(rsa_input.c, int)

    def test_parse_rsa_missing_field(self):
        with self.assertRaises(ValueError):
            parse_rsa_text("n = 1\ne = 2\n")

    def test_parse_indexed_groups(self):
        rsa_input = parse_rsa_text("n1=3233\ne1=3\nc1=1\nn2=4757\ne2=3\nc2=2\n")
        self.assertEqual(len(rsa_input.groups), 2)
        self.assertEqual(rsa_input.groups[0]["n"], 3233)


class TestWienerAttack(unittest.TestCase):
    def test_wiener_attack_success_small_trouble(self):
        rsa_input = parse_rsa_text(SMALL_TROUBLE_TEXT)
        d = wiener_attack(rsa_input.n, rsa_input.e)
        self.assertIsNotNone(d)
        result = run_rsa_mode(rsa_input)
        self.assertEqual(result.status, "success")
        self.assertEqual(result.attack, "Wiener")
        self.assertEqual(result.found_flag, EXPECTED_FLAG)
        self.assertEqual(result.plaintext_text, EXPECTED_FLAG)

    def test_no_fabricated_flag(self):
        plaintext_bytes, plaintext_text, found_flag = decode_plaintext(int.from_bytes(b"hello world", "big"))
        self.assertEqual(plaintext_text, "hello world")
        self.assertIsNone(found_flag)

    def test_known_pq_success(self):
        rsa_input = RSAInput(p=61, q=53, n=61 * 53, e=17, c=pow(65, 17, 61 * 53))
        result = run_rsa_mode(rsa_input)
        self.assertEqual(result.status, "success")
        self.assertEqual(result.attack, "known-pq")
        self.assertEqual(result.plaintext_int, 65)
        self.assertEqual(result.plaintext_text, "A")


class TestRSAAdditionalAttacks(unittest.TestCase):
    def _run_sample(self, filename):
        text = open(os.path.join(PROJECT_ROOT, "samples", filename), encoding="utf-8").read()
        return run_rsa_mode(parse_rsa_text(text))

    def test_fermat_factorization(self):
        result = self._run_sample("rsa_fermat_test.txt")
        self.assertEqual(result.status, "success")
        self.assertEqual(result.attack, "fermat-factor")
        self.assertEqual(result.plaintext_int, 12345)

    def test_common_modulus_attack(self):
        result = self._run_sample("rsa_common_modulus_test.txt")
        self.assertEqual(result.status, "success")
        self.assertEqual(result.attack, "common-modulus")
        self.assertEqual(result.plaintext_int, 65)

    def test_broadcast_attack(self):
        result = self._run_sample("rsa_broadcast_test.txt")
        self.assertEqual(result.status, "success")
        self.assertEqual(result.attack, "broadcast")
        self.assertEqual(result.plaintext_int, 42)

    def test_small_n_factor(self):
        result = self._run_sample("rsa_small_n_factor_test.txt")
        self.assertEqual(result.status, "success")
        self.assertIn(result.attack, {"small-n-factor", "fermat-factor"})
        self.assertEqual(result.plaintext_int, 123456)


class TestRSAReportAndCLI(unittest.TestCase):
    def test_rsa_report_generation(self):
        rsa_input = parse_rsa_text(SMALL_TROUBLE_TEXT)
        result = run_rsa_mode(rsa_input)
        with tempfile.TemporaryDirectory() as tmpdir:
            report_path = os.path.join(tmpdir, "rsa-report.md")
            generate_rsa_report(rsa_input, result, report_path)
            content = open(report_path, encoding="utf-8").read()
            self.assertIn(EXPECTED_FLAG, content)
            self.assertIn("Wiener", content)

    def test_rsa_cli_small_trouble(self):
        message_path = os.path.join(PROJECT_ROOT, "samples", "small-trouble-message.txt")
        result = subprocess.run(
            [sys.executable, "main.py", "--mode", "rsa", "--file", message_path],
            cwd=PROJECT_ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        self.assertIn(EXPECTED_FLAG, result.stdout)
        self.assertNotIn("small_trouble_solved", result.stdout)

    def test_rsa_cli_report_generation(self):
        message_path = os.path.join(PROJECT_ROOT, "samples", "small-trouble-message.txt")
        with tempfile.TemporaryDirectory() as tmpdir:
            report_path = os.path.join(tmpdir, "rsa-small-trouble.md")
            result = subprocess.run(
                [sys.executable, "main.py", "--mode", "rsa", "--file", message_path, "--report", report_path],
                cwd=PROJECT_ROOT,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(result.returncode, 0, msg=result.stderr)
            self.assertTrue(os.path.exists(report_path))
            self.assertIn(EXPECTED_FLAG, open(report_path, encoding="utf-8").read())

    def test_rsa_cli_broadcast(self):
        message_path = os.path.join(PROJECT_ROOT, "samples", "rsa_broadcast_test.txt")
        result = subprocess.run(
            [sys.executable, "main.py", "--mode", "crypto-rsa", "--file", message_path],
            cwd=PROJECT_ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        self.assertIn("broadcast", result.stdout)
        self.assertIn("42", result.stdout)
