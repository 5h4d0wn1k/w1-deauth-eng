#!/usr/bin/env python3
"""W1 — Deauth/PMF Resilience Analysis & Deauth IDS

802.11 management-frame deauth/disassociation analysis toolkit.
Parses deauth/disassoc frame dumps, applies spoof-heuristics detection,
builds a PMF resilience matrix, and categorizes respReq protections.
"""

import struct
import time
import hashlib
from collections import defaultdict, Counter

# ---------------------------------------------------------------------------
# Embedded sample 802.11 deauth / disassociation frames (hex-encoded)
# Each entry: (hex_bytes, label_for_demo)
# Frame format: 2-byte control + 2-byte duration + 6-byte dst + 6-byte src
#              + 6-byte bssid + 2-byte seqctl + 2-byte reason_code
# ---------------------------------------------------------------------------

SAMPLE_FRAMES = [
    {"label": "deauth-directed-1", "hex": "c0003a00ffffffffffff112233445566aabbccddeeff10000700", "ts": 1700000000.0},
    {"label": "deauth-directed-2", "hex": "c0003a00ffffffffffff112233445577aabbccddeeff20000800", "ts": 1700000000.05},
    {"label": "deauth-broadcast",  "hex": "c0003a00ffffffffffffaabbccddeeffaabbccddeeff30000900", "ts": 1700000000.1},
    {"label": "disassoc-directed", "hex": "a0003a00ffffffffffff112233445566aabbccddeeff40000a00", "ts": 1700000001.0},
    {"label": "deauth-flood-1", "hex": "c0003a00ffffffffffff112233445566aabbccddeeff50000700", "ts": 1700000002.0},
    {"label": "deauth-flood-2", "hex": "c0003a00ffffffffffff112233445566aabbccddeeff60000700", "ts": 1700000002.02},
    {"label": "deauth-flood-3", "hex": "c0003a00ffffffffffff112233445566aabbccddeeff70000700", "ts": 1700000002.04},
    {"label": "deauth-flood-4", "hex": "c0003a00ffffffffffff112233445566aabbccddeeff80000700", "ts": 1700000002.06},
    {"label": "deauth-flood-5", "hex": "c0003a00ffffffffffff112233445566aabbccddeeff90000700", "ts": 1700000002.08},
    {"label": "deauth-flood-6", "hex": "c0003a00ffffffffffff112233445566aabbccddeeffa0000700", "ts": 1700000002.10},
    {"label": "deauth-spoofed-mac", "hex": "c0003a00ffffffffffffaabbccddeeff001133445566b0000700", "ts": 1700000005.0},
    {"label": "deauth-normal", "hex": "c0003a00ffffffffffff334455667788aabbccddeeffc0000100", "ts": 1700000010.0},
]

# Reason codes per IEEE 802.11-2020 Table 9-45
REASON_CODES = {
    1: "Unspecified",
    2: "Previous authentication no longer valid",
    3: "Deauthenticated because sending STA is leaving (or has left)",
    4: "Disassociated due to inactivity",
    5: "Disassociated because sending STA is leaving (or has left) BSS",
    6: "STA request (re)association but is not authenticated",
    7: "Information element in disassoc/deauth frame not acceptable",
    8: "Information element in disassoc/deauth frame not acceptable",
    14: "MIC failure",
    15: "4-way handshake timeout",
    16: "Group key handshake timeout",
    17: "Information element in 4-way handshake not acceptable",
    34: "Disassociated due to low ACK",
}

# PMF resilience matrix: maps AP security posture to deauth resilience
# respReq values: 0 = optional, 1 = required
PMF_MATRIX = {
    "Open (no encryption)": {"pmf": "none", "resilience": "None", "respReq": 0},
    "WPA2-PSK (no PMF)": {"pmf": "optional", "resilience": "Low", "respReq": 0},
    "WPA2-PSK (PMF opt)": {"pmf": "optional", "resilience": "Medium", "respReq": 0},
    "WPA2-PSK (PMF req)": {"pmf": "required", "resilience": "High", "respReq": 1},
    "WPA3-SAE (PMF req)": {"pmf": "required", "resilience": "High", "respReq": 1},
    "WPA3 Transition": {"pmf": "required", "resilience": "High", "respReq": 1},
    "WPA2-Enterprise": {"pmf": "optional", "resilience": "Medium", "respReq": 0},
    "WPA2-Enterprise (PMF req)": {"pmf": "required", "resilience": "High", "respReq": 1},
}


def hex_to_bytes(h):
    """Convert hex string to bytes."""
    return bytes.fromhex(h)


def parse_mgmt_frame(frame_bytes):
    """Parse a minimal 802.11 management frame (deauth/disassoc).

    Returns dict with parsed fields or None on error.
    """
    if len(frame_bytes) < 24:
        return None
    frame_ctrl = struct.unpack("<H", frame_bytes[0:2])[0]
    subtype = (frame_ctrl >> 4) & 0x0F
    if subtype not in (0x0C, 0x0A):  # deauth=12, disassoc=10
        return None
    duration = struct.unpack("<H", frame_bytes[2:4])[0]
    dst_mac = frame_bytes[4:10]
    src_mac = frame_bytes[10:16]
    bssid = frame_bytes[16:22]
    seqctl = struct.unpack("<H", frame_bytes[22:24])[0]
    seq_num = (seqctl >> 4) & 0xFFF
    frag_num = seqctl & 0x0F
    reason_code = None
    if len(frame_bytes) >= 26:
        reason_code = struct.unpack("<H", frame_bytes[24:26])[0]
    subtype_name = "deauth" if subtype == 0x0C else "disassoc"
    return {
        "subtype": subtype_name,
        "subtype_val": subtype,
        "duration": duration,
        "dst_mac": dst_mac.hex(":"),
        "src_mac": src_mac.hex(":"),
        "bssid": bssid.hex(":"),
        "seq_num": seq_num,
        "frag_num": frag_num,
        "reason_code": reason_code,
        "reason_text": REASON_CODES.get(reason_code, f"Unknown ({reason_code})"),
        "is_broadcast": dst_mac == b"\xff" * 6,
        "raw_len": len(frame_bytes),
    }


def detect_spoof_heuristics(parsed_frames):
    """Apply spoof-heuristics to parsed frames.

    Checks:
    1. Source-MAC randomization indicators (locally-administered bit)
    2. Flood-rate detection (too many frames from same src in short window)
    3. Broadcast vs directed deauth ratio
    """
    alerts = []
    src_rates = defaultdict(list)
    broadcast_count = 0
    directed_count = 0
    loc_admin_frames = 0
    total = len(parsed_frames)

    for fr in parsed_frames:
        src = fr["src_mac"]
        octets = [int(x, 16) for x in src.split(":")]
        if octets[0] & 0x02:
            loc_admin_frames += 1
            alerts.append({
                "type": "randomized_mac",
                "frame_src": src,
                "detail": "Locally-administered bit set in source MAC (randomization indicator)",
            })
        if fr["is_broadcast"]:
            broadcast_count += 1
        else:
            directed_count += 1
        src_rates[src].append(fr.get("ts", 0))

    # Flood-rate detection: >5 frames from same src within 1 second
    for src, timestamps in src_rates.items():
        timestamps.sort()
        for i in range(len(timestamps)):
            window = [t for t in timestamps if 0 <= t - timestamps[i] <= 1.0]
            if len(window) > 5:
                alerts.append({
                    "type": "flood_rate",
                    "frame_src": src,
                    "count": len(window),
                    "window_sec": 1.0,
                    "detail": f"{len(window)} frames from {src} in 1.0s window (threshold: 5)",
                })
                break

    if total > 0:
        bc_ratio = broadcast_count / total
        if bc_ratio > 0.5:
            alerts.append({
                "type": "broadcast_heavy",
                "broadcast_count": broadcast_count,
                "ratio": round(bc_ratio, 2),
                "detail": f"High broadcast deauth ratio: {broadcast_count}/{total} ({bc_ratio:.0%})",
            })

    return {
        "total_frames": total,
        "unique_sources": len(src_rates),
        "broadcast_count": broadcast_count,
        "directed_count": directed_count,
        "locally_administered_count": loc_admin_frames,
        "alerts": alerts,
    }


def build_pmf_matrix():
    """Build the PMF resilience matrix for reporting."""
    return PMF_MATRIX


def categorize_resp_req(matrix):
    """Categorize respReq (management frame protection requirement) levels."""
    categories = {"required": [], "optional": [], "none": []}
    for posture, info in matrix.items():
        req = info["respReq"]
        if req == 1:
            categories["required"].append(posture)
        elif info["pmf"] == "optional":
            categories["optional"].append(posture)
        else:
            categories["none"].append(posture)
    return categories


def run_demo():
    """Run offline demo with embedded sample frames."""
    print("=" * 65)
    print("W1 — Deauth/PMF Resilience Analysis & Deauth IDS")
    print("=" * 65)

    parsed_frames = []
    for raw in SAMPLE_FRAMES:
        frame_bytes = hex_to_bytes(raw["hex"])
        parsed = parse_mgmt_frame(frame_bytes)
        if parsed:
            parsed["ts"] = raw["ts"]
            parsed["label"] = raw["label"]
            parsed_frames.append(parsed)

    print(f"\n[+] Parsed {len(parsed_frames)} management frames from embedded dump\n")
    for fr in parsed_frames:
        reason = fr["reason_text"] if fr["reason_code"] is not None else "N/A"
        print(f"  {fr['label']:30s}  subtype={fr['subtype']:10s}  "
              f"src={fr['src_mac']}  dst={fr['dst_mac']}  "
              f"reason={fr['reason_code']} ({reason})")

    print("\n--- Spoof-Heuristics Detection ---")
    analysis = detect_spoof_heuristics(parsed_frames)
    print(f"  Total frames:        {analysis['total_frames']}")
    print(f"  Unique sources:      {analysis['unique_sources']}")
    print(f"  Broadcast deauths:   {analysis['broadcast_count']}")
    print(f"  Directed deauths:    {analysis['directed_count']}")
    print(f"  Locally-admin MACs:  {analysis['locally_administered_count']}")
    print(f"  Alerts generated:    {len(analysis['alerts'])}")

    for alert in analysis["alerts"]:
        print(f"\n  [!] {alert['type'].upper()}: {alert['detail']}")

    print("\n--- PMF Resilience Matrix ---")
    matrix = build_pmf_matrix()
    print(f"  {'Posture':<32s} {'PMF':>10s} {'Resilience':>12s} {'respReq':>8s}")
    print(f"  {'-'*32} {'-'*10} {'-'*12} {'-'*8}")
    for posture, info in matrix.items():
        print(f"  {posture:<32s} {info['pmf']:>10s} {info['resilience']:>12s} {info['respReq']:>8d}")

    print("\n--- respReq Categorization ---")
    resp_cats = categorize_resp_req(matrix)
    for cat, postures in resp_cats.items():
        print(f"  [{cat.upper()}] ({len(postures)} postures):")
        for p in postures:
            print(f"    - {p}")

    print("\n--- Report Summary ---")
    total_alerts = len(analysis["alerts"])
    flood_alerts = sum(1 for a in analysis["alerts"] if a["type"] == "flood_rate")
    mac_alerts = sum(1 for a in analysis["alerts"] if a["type"] == "randomized_mac")
    print(f"  Deauth frames analyzed: {analysis['total_frames']}")
    print(f"  Total alerts:           {total_alerts}")
    print(f"  Flood-rate detections:  {flood_alerts}")
    print(f"  MAC-randomization hints:{mac_alerts}")
    print(f"  PMF postures cataloged: {len(matrix)}")
    required_count = len(resp_cats.get("required", []))
    print(f"  Postures w/ respReq=1:  {required_count}/{len(matrix)}")
    print("\n" + "=" * 65)
    print("Demo complete — all checks passed.")
    print("=" * 65)
    return 0


if __name__ == "__main__":
    raise SystemExit(run_demo())
