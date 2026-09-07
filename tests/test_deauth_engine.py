#!/usr/bin/env python3
"""Byte-exact unit tests for w1-deauth-eng."""

import os
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from firmware import deauth_engine as eng
from firmware import frame_core as fc


class FrameControlTest(unittest.TestCase):
    def test_deauth_frame_control(self):
        fc_bytes = fc.encode_frame_control(fc.FC_SUBTYPE_DEAUTH)
        parsed = fc.decode_frame_control(fc_bytes)
        self.assertEqual(parsed["type"], fc.FC_TYPE_MGMT)
        self.assertEqual(parsed["subtype"], fc.FC_SUBTYPE_DEAUTH)
        # byte-exact: FC for mgmt deauth non-protected == c0 00
        self.assertEqual(fc_bytes, b"\xc0\x00")

    def test_disassoc_frame_control(self):
        self.assertEqual(
            fc.encode_frame_control(fc.FC_SUBTYPE_DISASSOC), b"\xa0\x00")

    def test_frame_control_roundtrip_flags(self):
        raw = fc.encode_frame_control(fc.FC_SUBTYPE_DEAUTH, flags=fc.FC_FLAG_RETRY)
        parsed = fc.decode_frame_control(raw)
        self.assertTrue(parsed["retry"])
        self.assertFalse(parsed["protected"])


class MacTest(unittest.TestCase):
    def test_mac_roundtrip(self):
        m = "00:11:22:33:44:55"
        self.assertEqual(fc.mac_str(fc.mac_bytes(m)), m)

    def test_mac_bytes_len(self):
        self.assertEqual(len(fc.mac_bytes("00:11:22:33:44:55")), 6)

    def test_broadcast(self):
        self.assertTrue(fc.is_broadcast(fc.BROADCAST))
        self.assertFalse(fc.is_broadcast(fc.mac_bytes("00:11:22:33:44:55")))

    def test_lab_oui(self):
        self.assertTrue(fc.is_lab_mac(fc.mac_bytes("00:11:22:33:44:55")))
        self.assertFalse(fc.is_lab_mac(fc.mac_bytes("aa:bb:cc:dd:ee:ff")))


class DeauthBuildParseTest(unittest.TestCase):
    def test_build_deauth_byte_exact(self):
        seq = 8
        frame = fc.build_deauth("00:11:22:33:44:66", "00:11:22:33:44:55",
                                "00:11:22:33:44:55", reason=7, seq_num=seq)
        # header 24 bytes + reason 2 bytes = 26
        self.assertEqual(len(frame), 26)
        parsed = fc.parse_deauth(frame)
        self.assertEqual(parsed["subtype_val"], fc.FC_SUBTYPE_DEAUTH)
        self.assertEqual(parsed["reason_code"], 7)
        self.assertEqual(parsed["seq_num"], seq)
        self.assertEqual(parsed["da"], "00:11:22:33:44:66")
        self.assertEqual(parsed["sa"], "00:11:22:33:44:55")
        self.assertEqual(parsed["bssid"], "00:11:22:33:44:55")

    def test_deauth_reason_code_mapping(self):
        frame = fc.build_deauth(fc.BROADCAST_STR, "00:11:22:33:44:55",
                                "00:11:22:33:44:55", reason=14)
        parsed = fc.parse_deauth(frame)
        self.assertEqual(parsed["reason_text"], "MIC failure")

    def test_disassoc_roundtrip(self):
        frame = fc.build_disassoc("ff:ff:ff:ff:ff:ff", "00:11:22:33:44:55",
                                  "00:11:22:33:44:55", reason=8)
        parsed = fc.parse_disassoc(frame)
        self.assertEqual(parsed["subtype_val"], fc.FC_SUBTYPE_DISASSOC)
        self.assertEqual(parsed["reason_code"], 8)
        self.assertTrue(parsed["is_broadcast"])


class SeqControlTest(unittest.TestCase):
    def test_seq_roundtrip(self):
        for seq in (0, 1, 4095):
            raw = fc.encode_seq_control(seq)
            out = fc.decode_seq_control(raw)
            self.assertEqual(out["seq_num"], seq)

    def test_frag_preserved(self):
        raw = fc.encode_seq_control(100, frag_num=3)
        out = fc.decode_seq_control(raw)
        self.assertEqual(out["frag_num"], 3)
        self.assertEqual(out["seq_num"], 100)


class FcsTest(unittest.TestCase):
    def test_fcs_roundtrip(self):
        frame = fc.build_deauth("00:11:22:33:44:66", "00:11:22:33:44:55",
                                "00:11:22:33:44:55", reason=7)
        with_fcs = frame + fc.fcs(frame)
        self.assertTrue(fc.verify_fcs(with_fcs))

    def test_fcs_detects_corruption(self):
        frame = fc.build_deauth("00:11:22:33:44:66", "00:11:22:33:44:55",
                                "00:11:22:33:44:55", reason=7)
        frame += fc.fcs(frame)
        corrupted = bytearray(frame)
        corrupted[10] ^= 0x01
        self.assertFalse(fc.verify_fcs(bytes(corrupted)))


class EngineAnalysisTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.frames = eng.build_showcase_frames()
        cls.result = eng.run_analysis(cls.frames, eng.build_pmf_matrix())

    def test_parses_all_frames(self):
        self.assertEqual(len(self.result["parsed"]), len(self.frames))

    def test_flood_detected(self):
        types = [a["type"] for a in self.result["analysis"]["alerts"]]
        self.assertIn("flood_rate", types)

    def test_randomized_mac_detected(self):
        types = [a["type"] for a in self.result["analysis"]["alerts"]]
        self.assertIn("randomized_mac", types)

    def test_broadcast_heavy_not_falsed(self):
        # 2 broadcast of 13 total → ratio < 0.5, should NOT trigger
        types = [a["type"] for a in self.result["analysis"]["alerts"]]
        self.assertNotIn("broadcast_heavy", types)

    def test_pmf_matrix_resp_req(self):
        cats = eng.categorize_resp_req(eng.build_pmf_matrix())
        self.assertIn("WPA3-SAE (PMF req)", cats["required"])

    def test_fcs_stripped_on_parse(self):
        frame = eng.build_showcase_frames()[0]["data"]
        parsed = eng.parse_deauth_frame(frame)
        self.assertEqual(parsed["subtype_val"], fc.FC_SUBTYPE_DEAUTH)


class ReportJsonTest(unittest.TestCase):
    def test_json_serializable(self):
        result = eng.run_analysis(eng.build_showcase_frames(), eng.build_pmf_matrix())
        import json
        json.dumps(result, default=str)   # must not raise

    def test_report_file_written(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, "nested", "out.json")
            rc = eng.main(["--json", out])
            self.assertEqual(rc, 0)
            self.assertTrue(os.path.exists(out))


class SafetyGateTest(unittest.TestCase):
    def test_wifi_flag_is_gate(self):
        # main() returns exit code 2 when the real-air gate flag is passed
        self.assertEqual(eng.main(["--wifi"]), 2)


if __name__ == "__main__":
    unittest.main()
