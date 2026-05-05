import sys
import os
import unittest
import subprocess

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from src.decoders import (
    decode_base64,
    decode_hex,
    decode_binary,
    decode_ascii_decimal,
    decode_rot13,
    decode_reverse,
    decode_url,
    decode_caesar,
    decode_a1z26,
)
from src.detector import detect_flags, flag_score, readability_score
from src.reporter import generate_report


class TestBase64(unittest.TestCase):
    def test_valid_base64(self):
        result = decode_base64("cGljb0NURnt0ZXN0fQ==")
        self.assertEqual(result.status, "success")
        self.assertIn("picoCTF{test}", result.output)

    def test_invalid_base64(self):
        result = decode_base64("not!!valid!!base64")
        self.assertEqual(result.status, "skipped")


class TestHex(unittest.TestCase):
    def test_valid_hex(self):
        result = decode_hex("7069636f4354467b746573747d")
        self.assertEqual(result.status, "success")
        self.assertIn("picoCTF{test}", result.output)

    def test_invalid_hex_odd_length(self):
        result = decode_hex("7069636f4354467b746573747")
        self.assertEqual(result.status, "skipped")

    def test_invalid_hex_non_hex_chars(self):
        result = decode_hex("xyz123")
        self.assertEqual(result.status, "skipped")


class TestBinary(unittest.TestCase):
    def test_valid_binary_with_spaces(self):
        result = decode_binary("01110000 01101001 01100011 01101111")
        self.assertEqual(result.status, "success")
        self.assertIn("pico", result.output)

    def test_valid_binary_continuous(self):
        result = decode_binary("01110000011010010110001101101111")
        self.assertEqual(result.status, "success")
        self.assertIn("pico", result.output)

    def test_invalid_binary(self):
        result = decode_binary("01210000")
        self.assertEqual(result.status, "skipped")


class TestAsciiDecimal(unittest.TestCase):
    def test_valid_ascii_decimal(self):
        result = decode_ascii_decimal("112 105 99 111 67 84 70 123 116 101 115 116 125")
        self.assertEqual(result.status, "success")
        self.assertIn("picoCTF{test}", result.output)

    def test_invalid_ascii_decimal(self):
        result = decode_ascii_decimal("300 105 99")
        self.assertEqual(result.status, "skipped")


class TestRot13(unittest.TestCase):
    def test_rot13(self):
        result = decode_rot13("cvpbPGS{grfg}")
        self.assertEqual(result.status, "success")
        self.assertIn("picoCTF{test}", result.output)


class TestReverse(unittest.TestCase):
    def test_reverse(self):
        result = decode_reverse("}tset{FTCocip")
        self.assertEqual(result.status, "success")
        self.assertIn("picoCTF{test}", result.output)


class TestUrlDecode(unittest.TestCase):
    def test_url_encoded(self):
        result = decode_url("%70%69%63%6F")
        self.assertEqual(result.status, "success")
        self.assertIn("pico", result.output)

    def test_no_url_encoding(self):
        result = decode_url("hello world")
        self.assertEqual(result.status, "success")
        self.assertIn("no URL encoding detected", result.reason)


class TestFlagDetector(unittest.TestCase):
    def test_picoctf_does_not_match_ctf_substring(self):
        flags = detect_flags("picoCTF{test}")
        self.assertEqual(flags, ["picoCTF{test}"])
        self.assertNotIn("CTF{test}", flags)

    def test_standalone_ctf_matches(self):
        flags = detect_flags("CTF{standalone}")
        self.assertEqual(flags, ["CTF{standalone}"])

    def test_flag_score_picoctf(self):
        score, flags = flag_score("picoCTF{test}")
        self.assertEqual(score, 1000)
        self.assertEqual(flags, ["picoCTF{test}"])

    def test_readability_good(self):
        score = readability_score("picoCTF{test}")
        self.assertGreater(score, 0)

    def test_readability_bad(self):
        score = readability_score("\x00\x01\x02\x03\x04\x05\x06\x07")
        self.assertLess(score, 0)


class TestHexReadability(unittest.TestCase):
    def test_binary_input_not_readable(self):
        binary_input = "01110000 01101001 01100011 01101111"
        result = decode_hex(binary_input)
        self.assertEqual(result.status, "skipped")
        self.assertIn("not readable", result.reason.lower())


class TestCaesar(unittest.TestCase):
    def test_caesar_shift_13_matches_rot13(self):
        result = decode_caesar("cvpbPGS{grfg}", 13)
        self.assertEqual(result.status, "success")
        self.assertIn("picoCTF{test}", result.output)

    def test_caesar_shift_1(self):
        result = decode_caesar("abc", 1)
        self.assertEqual(result.status, "success")
        self.assertEqual(result.output, "bcd")

    def test_caesar_shift_25(self):
        result = decode_caesar("abc", 25)
        self.assertEqual(result.status, "success")
        self.assertEqual(result.output, "zab")

    def test_caesar_method_name(self):
        result = decode_caesar("test", 5)
        self.assertEqual(result.method, "CAESAR_SHIFT_5")


class TestA1Z26(unittest.TestCase):
    def test_basic_a1z26(self):
        result = decode_a1z26("16 9 3 15")
        self.assertEqual(result.status, "success")
        self.assertIn("pico", result.output)

    def test_the_numbers_challenge(self):
        result = decode_a1z26("16 9 3 15 3 20 6 { 20 8 5 14 21 13 2 5 18 19 13 1 19 15 14 }")
        self.assertEqual(result.status, "success")
        self.assertEqual(result.output, "picoctf{thenumbersmason}")

    def test_invalid_a1z26_out_of_range(self):
        result = decode_a1z26("99 100 300")
        self.assertEqual(result.status, "skipped")

    def test_invalid_a1z26_bad_token(self):
        result = decode_a1z26("1 2 @ 4")
        self.assertEqual(result.status, "skipped")

    def test_empty_a1z26(self):
        result = decode_a1z26("")
        self.assertEqual(result.status, "skipped")

    def test_a1z26_method_name(self):
        result = decode_a1z26("1")
        self.assertEqual(result.method, "A1Z26")


class TestCaseInsensitiveFlags(unittest.TestCase):
    def test_lowercase_picoctf_detected(self):
        flags = detect_flags("picoctf{thenumbersmason}")
        self.assertEqual(flags, ["picoCTF{thenumbersmason}"])

    def test_uppercase_picoctf_detected(self):
        flags = detect_flags("PICOCTF{TEST}")
        self.assertEqual(flags, ["picoCTF{TEST}"])

    def test_mixed_case_picoctf_detected(self):
        flags = detect_flags("PiCoCtF{hello}")
        self.assertEqual(flags, ["picoCTF{hello}"])

    def test_lowercase_flag_detected(self):
        flags = detect_flags("flag{hello}")
        self.assertEqual(flags, ["flag{hello}"])

    def test_flag_score_lowercase(self):
        score, flags = flag_score("picoctf{test}")
        self.assertEqual(score, 1000)
        self.assertEqual(flags, ["picoCTF{test}"])


class TestCLI(unittest.TestCase):
    def _run_cli(self, *args):
        main_dir = os.path.join(os.path.dirname(__file__), "..")
        cmd = [sys.executable, os.path.join(main_dir, "main.py")] + list(args)
        result = subprocess.run(cmd, capture_output=True, text=True, cwd=main_dir)
        return result

    def test_file_input(self):
        sample_path = os.path.join(os.path.dirname(__file__), "..", "samples", "base64.txt")
        result = self._run_cli("--file", sample_path)
        self.assertEqual(result.returncode, 0)
        self.assertIn("picoCTF{test}", result.stdout)

    def test_file_not_found(self):
        result = self._run_cli("--file", "nonexistent_file.txt")
        self.assertEqual(result.returncode, 1)
        self.assertIn("file not found", result.stderr)

    def test_text_and_file_conflict(self):
        result = self._run_cli("some_text", "--file", "samples/base64.txt")
        self.assertEqual(result.returncode, 1)
        self.assertIn("cannot specify both", result.stderr)


class TestBase64Utf8Fallback(unittest.TestCase):
    def test_hex_input_not_failed_utf8(self):
        result = decode_base64("7069636f4354467b746573747d")
        self.assertNotEqual(result.status, "failed")
        self.assertNotIn("utf-8", (result.error or "").lower())

    def test_hex_input_skipped_or_readable(self):
        result = decode_base64("7069636f4354467b746573747d")
        if result.status == "skipped":
            self.assertIn("not readable", result.reason.lower())


class TestReporter(unittest.TestCase):
    def _make_results(self, method, status, output="", flags=None):
        from src.models import DecodeResult
        return DecodeResult(
            method=method,
            status=status,
            output=output,
            score=100 if flags else 10,
            flags=flags or [],
        )

    def test_duplicate_flags_deduplicated(self):
        results = [
            self._make_results("ROT13", "success", "picoCTF{test}", ["picoCTF{test}"]),
            self._make_results("CAESAR_SHIFT_13", "success", "picoCTF{test}", ["picoCTF{test}"]),
        ]
        report_path = os.path.join(os.path.dirname(__file__), "test_report_flags.md")
        generate_report("test", results, report_path)
        with open(report_path, "r") as f:
            content = f.read()
        flag_count = content.count("- `picoCTF{test}`")
        in_found_flags = False
        found_flags_count = 0
        for line in content.split("\n"):
            if "## Found Flags" in line:
                in_found_flags = True
                continue
            if in_found_flags and line.startswith("## "):
                break
            if in_found_flags and "- `picoCTF{test}`" in line:
                found_flags_count += 1
        self.assertEqual(found_flags_count, 1)
        os.remove(report_path)

    def test_report_top_n_limits_results(self):
        results = [
            self._make_results(f"M{i}", "success", f"output{i}")
            for i in range(20)
        ]
        report_path = os.path.join(os.path.dirname(__file__), "test_report_top.md")
        generate_report("test", results, report_path, top_n=5)
        with open(report_path, "r") as f:
            content = f.read()
        self.assertIn("Displayed results: 5", content)
        self.assertIn("### 1. M0", content)
        self.assertIn("### 5. M4", content)
        self.assertNotIn("### 6. M5", content)
        os.remove(report_path)

    def test_report_top_zero_shows_all(self):
        results = [
            self._make_results(f"M{i}", "success", f"output{i}")
            for i in range(5)
        ]
        report_path = os.path.join(os.path.dirname(__file__), "test_report_all.md")
        generate_report("test", results, report_path, top_n=0)
        with open(report_path, "r") as f:
            content = f.read()
        self.assertIn("Displayed results: 5", content)
        self.assertIn("### 5. M4", content)
        os.remove(report_path)


class TestTopN(unittest.TestCase):
    def _run_cli(self, *args):
        main_dir = os.path.join(os.path.dirname(__file__), "..")
        cmd = [sys.executable, os.path.join(main_dir, "main.py")] + list(args)
        result = subprocess.run(cmd, capture_output=True, text=True, cwd=main_dir)
        return result

    def test_top_5_limits_results(self):
        result = self._run_cli("--top", "5", "cvpbPGS{grfg}")
        self.assertEqual(result.returncode, 0)
        self.assertIn("[5]", result.stdout)
        self.assertNotIn("[6]", result.stdout)

    def test_top_0_shows_all(self):
        result = self._run_cli("--top", "0", "cvpbPGS{grfg}")
        self.assertEqual(result.returncode, 0)
        self.assertIn("CAESAR_SHIFT_25", result.stdout)


class TestBytesLiteralExtract(unittest.TestCase):
    def test_bytes_literal_single_quotes(self):
        from src.decoders import decode_bytes_literal
        result = decode_bytes_literal("b'd3BqdkpBTXtqaGx6aHlfazNqeTl3YTNrXzc4MjUwaG1qfQ=='")
        self.assertEqual(result.status, "success")
        self.assertEqual(result.output, "d3BqdkpBTXtqaGx6aHlfazNqeTl3YTNrXzc4MjUwaG1qfQ==")

    def test_bytes_literal_double_quotes(self):
        from src.decoders import decode_bytes_literal
        result = decode_bytes_literal('b"d3BqdkpBTXtqaGx6aHlfazNqeTl3YTNrXzc4MjUwaG1qfQ=="')
        self.assertEqual(result.status, "success")
        self.assertEqual(result.output, "d3BqdkpBTXtqaGx6aHlfazNqeTl3YTNrXzc4MjUwaG1qfQ==")

    def test_not_bytes_literal(self):
        from src.decoders import decode_bytes_literal
        result = decode_bytes_literal("d3BqdkpBTXtqaGx6aHlfazNqeTl3YTNrXzc4MjUwaG1qfQ==")
        self.assertEqual(result.status, "skipped")

    def test_method_name(self):
        from src.decoders import decode_bytes_literal
        result = decode_bytes_literal("b'hello'")
        self.assertEqual(result.method, "BYTES_LITERAL_EXTRACT")


class TestRecursiveMode(unittest.TestCase):
    INTERENDEC_INPUT = "YidkM0JxZGtwQlRYdHFhR3g2YUhsZmF6TnFlVGwzWVROclh6YzRNalV3YUcxcWZRPT0nCg=="

    def _run_cli(self, *args):
        main_dir = os.path.join(os.path.dirname(__file__), "..")
        cmd = [sys.executable, os.path.join(main_dir, "main.py")] + list(args)
        result = subprocess.run(cmd, capture_output=True, text=True, cwd=main_dir)
        return result

    def test_recursive_finds_flag(self):
        result = self._run_cli(
            self.INTERENDEC_INPUT,
            "--recursive",
            "--depth",
            "4",
        )
        self.assertEqual(result.returncode, 0)
        self.assertIn("picoCTF{caesar_d3cr9pt3d_78250afc}", result.stdout)

    def test_recursive_chain_contains_all_steps(self):
        from src.decoder_engine import run_recursive_decoders
        results = run_recursive_decoders(self.INTERENDEC_INPUT, max_depth=4)
        flag_results = [r for r in results if r.flags]
        self.assertGreater(len(flag_results), 0)
        flag_result = flag_results[0]
        self.assertIn("BASE64", flag_result.chain)
        self.assertIn("BYTES_LITERAL_EXTRACT", flag_result.chain)
        self.assertIn("CAESAR_SHIFT_19", flag_result.chain)

    def test_single_pass_does_not_find_final_flag(self):
        from src.decoder_engine import run_all_decoders
        results = run_all_decoders(self.INTERENDEC_INPUT)
        flag_results = [r for r in results if r.flags]
        for r in flag_results:
            self.assertNotEqual(r.output, "picoCTF{caesar_d3cr9pt3d_78250afc}")

    def test_depth_3_does_not_find_flag(self):
        result = self._run_cli(
            self.INTERENDEC_INPUT,
            "--recursive",
            "--depth",
            "3",
        )
        self.assertEqual(result.returncode, 0)
        self.assertNotIn("picoCTF{caesar_d3cr9pt3d_78250afc}", result.stdout)

    def test_recursive_cli_with_report(self):
        report_path = os.path.join(os.path.dirname(__file__), "test_recursive_report.md")
        sample_path = os.path.join(os.path.dirname(__file__), "..", "samples", "interencdec-enc_flag.txt")
        result = self._run_cli(
            "--file", sample_path,
            "--recursive",
            "--depth", "4",
            "--max-branch", "4",
            "--top", "10",
            "--report", report_path,
        )
        self.assertEqual(result.returncode, 0)
        self.assertIn("picoCTF{caesar_d3cr9pt3d_78250afc}", result.stdout)
        self.assertIn("[Recursive", result.stdout)
        self.assertIn("Depth 4", result.stdout)
        self.assertTrue(os.path.exists(report_path))
        with open(report_path, "r") as f:
            content = f.read()
        self.assertIn("Chain:", content)
        self.assertIn("picoCTF{caesar_d3cr9pt3d_78250afc}", content)
        os.remove(report_path)

    def test_chain_display_in_terminal(self):
        result = self._run_cli(
            self.INTERENDEC_INPUT,
            "--recursive",
            "--depth",
            "4",
            "--top",
            "1",
        )
        self.assertEqual(result.returncode, 0)
        self.assertIn("Chain:", result.stdout)

    def test_best_candidate_ranking(self):
        from src.decoder_engine import run_recursive_decoders
        results = run_recursive_decoders(self.INTERENDEC_INPUT, max_depth=4)
        self.assertGreater(len(results), 0)
        best = results[0]
        self.assertEqual(best.output, "picoCTF{caesar_d3cr9pt3d_78250afc}")
        self.assertIn("picoCTF", best.flags[0] if best.flags else "")

    def test_confidence_classification(self):
        from src.detector import classify_confidence
        self.assertEqual(
            classify_confidence("picoCTF{test}", 1200, ["picoCTF{test}"]),
            "HIGH",
        )
        self.assertEqual(
            classify_confidence("flag{test}", 700, ["flag{test}"]),
            "HIGH",
        )
        self.assertEqual(
            classify_confidence("hello world readable text", 150, []),
            "MEDIUM",
        )
        self.assertEqual(
            classify_confidence("\x00\x01\x02\x03", -50, []),
            "NOISE",
        )


class TestApplicability(unittest.TestCase):
    def test_base64_applicability(self):
        from src.policy import get_applicability
        results = get_applicability("cGljb0NURnt0ZXN0fQ==")
        b64 = [r for r in results if r.decoder_name == "BASE64"][0]
        rot13 = [r for r in results if r.decoder_name == "ROT13"][0]
        a1z26 = [r for r in results if r.decoder_name == "A1Z26"][0]
        self.assertGreater(b64.applicability_score, rot13.applicability_score)
        self.assertGreater(b64.applicability_score, a1z26.applicability_score)
        self.assertTrue(b64.applicable)

    def test_a1z26_applicability(self):
        from src.policy import get_applicability
        results = get_applicability("16 9 3 15 3 20 6")
        a1z26 = [r for r in results if r.decoder_name == "A1Z26"][0]
        b64 = [r for r in results if r.decoder_name == "BASE64"][0]
        self.assertGreater(a1z26.applicability_score, b64.applicability_score)
        self.assertTrue(a1z26.applicable)

    def test_bytes_literal_applicability(self):
        from src.policy import get_applicability
        text = "b'd3BqdkpBTXtqaGx6aHlfazNqeTl3YTNrXzc4MjUwaG1qfQ=='"
        results = get_applicability(text)
        bytes_lit = [r for r in results if r.decoder_name == "BYTES_LITERAL_EXTRACT"][0]
        rot13 = [r for r in results if r.decoder_name == "ROT13"][0]
        self.assertEqual(bytes_lit.applicability_score, 95)
        self.assertGreater(bytes_lit.applicability_score, rot13.applicability_score)

    def test_hex_applicability(self):
        from src.policy import get_applicability
        results = get_applicability("7069636f4354467b746573747d")
        hex_result = [r for r in results if r.decoder_name == "HEX"][0]
        self.assertTrue(hex_result.applicable)
        self.assertGreater(hex_result.applicability_score, 50)

    def test_binary_applicability(self):
        from src.policy import get_applicability
        results = get_applicability("01110000 01101001 01100011")
        binary_result = [r for r in results if r.decoder_name == "BINARY"][0]
        self.assertTrue(binary_result.applicable)


class TestTransitionPolicy(unittest.TestCase):
    INTERENDEC_INPUT = "YidkM0JxZGtwQlRYdHFhR3g2YUhsZmF6TnFlVGwzWVROclh6YzRNalV3YUcxcWZRPT0nCg=="

    def test_interencdec_policy_order(self):
        from src.decoders import decode_base64, decode_bytes_literal
        from src.policy import get_transition_policy

        policy1 = get_transition_policy(self.INTERENDEC_INPUT)
        top1_names = [p[0] for p in policy1[:3]]
        self.assertIn("BASE64", top1_names)

        l1_out = decode_base64(self.INTERENDEC_INPUT).output
        policy2 = get_transition_policy(l1_out)
        top2_names = [p[0] for p in policy2[:3]]
        self.assertIn("BYTES_LITERAL_EXTRACT", top2_names)

        l2_out = decode_bytes_literal(l1_out).output
        policy3 = get_transition_policy(l2_out)
        top3_names = [p[0] for p in policy3[:3]]
        self.assertIn("BASE64", top3_names)


class TestMaxBranch(unittest.TestCase):
    INTERENDEC_INPUT = "YidkM0JxZGtwQlRYdHFhR3g2YUhsZmF6TnFlVGwzWVROclh6YzRNalV3YUcxcWZRPT0nCg=="

    def _run_cli(self, *args):
        main_dir = os.path.join(os.path.dirname(__file__), "..")
        cmd = [sys.executable, os.path.join(main_dir, "main.py")] + list(args)
        result = subprocess.run(cmd, capture_output=True, text=True, cwd=main_dir)
        return result

    def test_max_branch_finds_flag(self):
        result = self._run_cli(
            self.INTERENDEC_INPUT,
            "--recursive",
            "--depth", "4",
            "--max-branch", "4",
        )
        self.assertEqual(result.returncode, 0)
        self.assertIn("picoCTF{caesar_d3cr9pt3d_78250afc}", result.stdout)

    def test_show_applicability_cli(self):
        result = self._run_cli(
            self.INTERENDEC_INPUT,
            "--recursive",
            "--depth", "4",
            "--max-branch", "4",
            "--show-applicability",
            "--top", "1",
        )
        self.assertEqual(result.returncode, 0)
        self.assertIn("[APPLICABILITY LOG]", result.stdout)
        self.assertIn("Expanded decoders:", result.stdout)
        self.assertIn("picoCTF{caesar_d3cr9pt3d_78250afc}", result.stdout)


class TestV052InterencdecRegression(unittest.TestCase):
    INTERENDEC_INPUT = "YidkM0JxZGtwQlRYdHFhR3g2YUhsZmF6TnFlVGwzWVROclh6YzRNalV3YUcxcWZRPT0nCg=="

    def test_best_candidate_chain(self):
        from src.decoder_engine import run_recursive_decoders
        results = run_recursive_decoders(self.INTERENDEC_INPUT, max_depth=4, max_branch=5)
        self.assertGreater(len(results), 0)
        best = results[0]
        self.assertEqual(best.output, "picoCTF{caesar_d3cr9pt3d_78250afc}")
        self.assertIn("BASE64", best.chain)
        self.assertIn("BYTES_LITERAL_EXTRACT", best.chain)
        self.assertIn("CAESAR_SHIFT_19", best.chain)
        self.assertIn("picoCTF", best.flags[0] if best.flags else "")

    def test_chain_order_correct(self):
        from src.decoder_engine import run_recursive_decoders
        results = run_recursive_decoders(self.INTERENDEC_INPUT, max_depth=4, max_branch=5)
        best = results[0]
        expected_chain = ["BASE64", "BYTES_LITERAL_EXTRACT", "BASE64", "CAESAR_SHIFT_19"]
        self.assertEqual(best.chain, expected_chain)


class TestV052ReversePenalty(unittest.TestCase):
    def test_reverse_chain_penalized(self):
        from src.decoder_engine import run_recursive_decoders
        from src.policy import _is_base64_like
        input_text = "cvpbPGS{grfg}"
        results = run_recursive_decoders(input_text, max_depth=3, max_branch=5)
        reverse_results = [r for r in results if r.chain and "REVERSE" in r.chain]
        non_reverse_results = [r for r in results if r.chain and "REVERSE" not in r.chain]
        if reverse_results and non_reverse_results:
            best_reverse = max(reverse_results, key=lambda r: r.score)
            best_non_reverse = max(non_reverse_results, key=lambda r: r.score)
            self.assertLessEqual(best_reverse.score, best_non_reverse.score + 50)

    def test_reverse_base64_noise_penalized(self):
        from src.decoder_engine import run_recursive_decoders
        base64_input = "cGljb0NURnt0ZXN0fQ=="
        results = run_recursive_decoders(base64_input, max_depth=3, max_branch=5)
        reverse_results = [r for r in results if r.chain and "REVERSE" in r.chain and not r.flags]
        for r in reverse_results:
            self.assertLess(r.score, 100)


class TestV052NoiseFamilySuppression(unittest.TestCase):
    INTERENDEC_INPUT = "YidkM0JxZGtwQlRYdHFhR3g2YUhsZmF6TnFlVGwzWVROclh6YzRNalV3YUcxcWZRPT0nCg=="

    def test_caesar_noise_reduced_in_top_results(self):
        from src.decoder_engine import run_recursive_decoders
        results = run_recursive_decoders(self.INTERENDEC_INPUT, max_depth=4, max_branch=5)
        top_10 = results[:10]
        caesar_noise_count = sum(
            1 for r in top_10
            if r.chain and len(r.chain) >= 2
            and r.chain[-1].startswith("CAESAR_SHIFT_")
            and not r.flags
        )
        self.assertLessEqual(caesar_noise_count, 3)

    def test_noise_family_not_dominating_top_5(self):
        from src.decoder_engine import run_recursive_decoders
        results = run_recursive_decoders(self.INTERENDEC_INPUT, max_depth=4, max_branch=5)
        top_5 = results[:5]
        caesar_noise = [r for r in top_5 if r.chain and r.chain[-1].startswith("CAESAR_SHIFT_") and not r.flags]
        self.assertLessEqual(len(caesar_noise), 2)


class TestV052ApplicabilityTransition(unittest.TestCase):
    def test_base64_like_no_rot13_expansion(self):
        from src.policy import get_transition_policy, _is_strong_base64_like
        base64_text = "cGljb0NURnt0ZXN0fQ=="
        self.assertTrue(_is_strong_base64_like(base64_text))
        policy = get_transition_policy(base64_text)
        rot13_entry = [p for p in policy if p[0] == "ROT13"][0]
        caesar_entry = [p for p in policy if p[0] == "CAESAR"][0]
        self.assertLessEqual(rot13_entry[1], 5)
        self.assertLessEqual(caesar_entry[1], 5)

    def test_base64_like_prefers_base64_decoder(self):
        from src.policy import get_transition_policy
        base64_text = "cGljb0NURnt0ZXN0fQ=="
        policy = get_transition_policy(base64_text)
        top_decoder = policy[0]
        self.assertEqual(top_decoder[0], "BASE64")
        self.assertGreaterEqual(top_decoder[1], 90)

    def test_strong_base64_no_caesar_shifts_in_recursive(self):
        from src.decoder_engine import run_recursive_decoders
        from src.policy import _is_strong_base64_like
        base64_text = "cGljb0NURnt0ZXN0fQ=="
        self.assertTrue(_is_strong_base64_like(base64_text))
        results = run_recursive_decoders(base64_text, max_depth=2, max_branch=5)
        caesar_results = [r for r in results if r.chain and r.chain[-1].startswith("CAESAR_SHIFT_")]
        for r in caesar_results:
            self.assertLess(r.score, 20)


class TestDisplayOptimization(unittest.TestCase):
    def _run_cli(self, *args):
        main_dir = os.path.join(os.path.dirname(__file__), "..")
        cmd = [sys.executable, os.path.join(main_dir, "main.py")] + list(args)
        result = subprocess.run(cmd, capture_output=True, text=True, cwd=main_dir)
        return result

    def test_output_preview_truncation(self):
        from src.utils import _preview
        short_text = "picoCTF{test}"
        self.assertEqual(_preview(short_text), short_text)
        long_text = "a" * 100
        preview = _preview(long_text)
        self.assertEqual(len(preview), 63)
        self.assertTrue(preview.endswith("..."))

    def test_output_preview_length(self):
        from src.utils import _preview
        text_70 = "b" * 70
        result = _preview(text_70)
        self.assertLessEqual(len(result), 63)

    def test_top_results_summary_format(self):
        from src.decoder_engine import run_all_decoders
        from src.utils import print_results
        import io
        import sys
        results = run_all_decoders("cGljb0NURnt0ZXN0fQ==")
        captured = io.StringIO()
        sys.stdout = captured
        print_results(results[:5])
        sys.stdout = sys.__stdout__
        output = captured.getvalue()
        self.assertIn("Output Preview:", output)
        self.assertNotIn("b'd3BqdkpBTXtqaGx6aHlfazNqeTl3YTNrXzc4MjUwaG1qfQ=='", output)

    def test_best_candidate_full_output(self):
        from src.decoder_engine import run_recursive_decoders
        from src.utils import print_best_candidate
        import io
        import sys
        results = run_recursive_decoders(
            "YidkM0JxZGtwQlRYdHFhR3g2YUhsZmF6TnFlVGwzWVROclh6YzRNalV3YUcxcWZRPT0nCg==",
            max_depth=4, max_branch=5
        )
        best = results[0]
        captured = io.StringIO()
        sys.stdout = captured
        print_best_candidate(best)
        sys.stdout = sys.__stdout__
        output = captured.getvalue()
        self.assertIn("Flag: picoCTF{caesar_d3cr9pt3d_78250afc}", output)
        self.assertIn("[OUTPUT]", output)
        self.assertIn("picoCTF{caesar_d3cr9pt3d_78250afc}", output)

    def test_applicability_log_summary(self):
        from src.decoder_engine import run_recursive_decoders
        from src.utils import print_applicability
        import io
        import sys
        applicability_log = []
        results = run_recursive_decoders(
            "YidkM0JxZGtwQlRYdHFhR3g2YUhsZmF6TnFlVGwzWVROclh6YzRNalV3YUcxcWZRPT0nCg==",
            max_depth=2, max_branch=5,
            show_applicability=True, applicability_log=applicability_log
        )
        captured = io.StringIO()
        sys.stdout = captured
        print_applicability(applicability_log)
        sys.stdout = sys.__stdout__
        output = captured.getvalue()
        self.assertIn("Expanded decoders:", output)
        lines = output.split("\n")
        decoder_lines = [l for l in lines if l.strip().startswith("- ")]
        self.assertLessEqual(len(decoder_lines), 10)

    def test_compact_mode_cli(self):
        sample_path = os.path.join(os.path.dirname(__file__), "..", "samples", "interencdec-enc_flag.txt")
        result = self._run_cli(
            "--file", sample_path,
            "--recursive", "--depth", "4",
            "--compact",
        )
        self.assertEqual(result.returncode, 0)
        self.assertIn("picoCTF{caesar_d3cr9pt3d_78250afc}", result.stdout)
        self.assertIn("[1]", result.stdout)
        self.assertNotIn("[4]", result.stdout)

    def test_compact_mode_with_report(self):
        report_path = os.path.join(os.path.dirname(__file__), "test_compact_report.md")
        sample_path = os.path.join(os.path.dirname(__file__), "..", "samples", "interencdec-enc_flag.txt")
        result = self._run_cli(
            "--file", sample_path,
            "--recursive", "--depth", "4",
            "--compact",
            "--report", report_path,
        )
        self.assertEqual(result.returncode, 0)
        self.assertTrue(os.path.exists(report_path))
        with open(report_path, "r") as f:
            content = f.read()
        self.assertIn("picoCTF{caesar_d3cr9pt3d_78250afc}", content)
        self.assertIn("Output Preview:", content)
        os.remove(report_path)
