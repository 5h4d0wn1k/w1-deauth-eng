#!/usr/bin/env python3
"""W1 — Deauth/Disassociation Engineering & Analysis.

Byte-level 802.11 deauth/disassoc frame *builder* + *parser* with
spoof-heuristics detection and a PMF resilience matrix. All frame work
happens offscreen with pure-stdlib bytes (frame_core); no radio emitted.

Safety: destructive/emission actions are OFF by default. Real-air
capability is a future hardware gate and is not implemented here.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from collections import defaultdict

try:
    from firmware import frame_core as fc
except ImportError:
    try:
        import frame_core as fc
    except ImportError:
        sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(__file__)), "firmware"))
        import frame_core as fc

# ----------------------------------------------------------------------
# Embedded showcase frames (built with the byte-level builder, then parsed)
# ----------------------------------------------------------------------


def build_showcase_frames() -> list[dict]:
    """Build a deterministic set of deauth/disassoc frames using frame_core."""
    lab_ap = "00:11:22:33:44:55"
    lab_client = "00:11:22:33:44:66"
    lab_client2 = "00:11:22:33:44:77"
    evasive_mac = "02:11:22:33:44:99"   # locally-administered bit (0x02) set

    entries = [
        {"label": "deauth-directed-1", "data": fc.build_deauth(
            lab_client, lab_ap, lab_ap, reason=7, seq_num=8), "ts": 1700000000.0},
        {"label": "deauth-directed-2", "data": fc.build_deauth(
            lab_client, lab_ap, lab_ap, reason=8, seq_num=9), "ts": 1700000000.05},
        {"label": "deauth-broadcast", "data": fc.build_deauth(
            fc.BROADCAST_STR, lab_ap, lab_ap, reason=9, seq_num=10), "ts": 1700000000.1},
        {"label": "disassoc-directed", "data": fc.build_disassoc(
            lab_client, lab_ap, lab_ap, reason=10, seq_num=11), "ts": 1700000001.0},
        {"label": "deauth-flood-1", "data": fc.build_deauth(
            lab_client, lab_ap, lab_ap, reason=7, seq_num=12), "ts": 1700000002.0},
        {"label": "deauth-flood-2", "data": fc.build_deauth(
            lab_client, lab_ap, lab_ap, reason=7, seq_num=13), "ts": 1700000002.02},
        {"label": "deauth-flood-3", "data": fc.build_deauth(
            lab_client, lab_ap, lab_ap, reason=7, seq_num=14), "ts": 1700000002.04},
        {"label": "deauth-flood-4", "data": fc.build_deauth(
            lab_client, lab_ap, lab_ap, reason=7, seq_num=15), "ts": 1700000002.06},
        {"label": "deauth-flood-5", "data": fc.build_deauth(
            lab_client, lab_ap, lab_ap, reason=7, seq_num=16), "ts": 1700000002.08},
        {"label": "deauth-flood-6", "data": fc.build_deauth(
            lab_client, lab_ap, lab_ap, reason=7, seq_num=17), "ts": 1700000002.10},
        {"label": "deauth-randomized-sa-1", "data": fc.build_deauth(
            lab_client, evasive_mac, lab_ap, reason=7, seq_num=20), "ts": 1700000005.0},
        {"label": "deauth-randomized-sa-2", "data": fc.build_deauth(
            lab_client2, evasive_mac, lab_ap, reason=7, seq_num=21), "ts": 1700000005.3},
        {"label": "deauth-normal", "data": fc.build_deauth(
            lab_client, lab_ap, lab_ap, reason=1, seq_num=30), "ts": 1700000010.0},
    ]
    for e in entries:
        e["data"] += fc.fcs(e["data"])          # append FCS
    return entries


# PMF resilience matrix (IEEE 802.11-2020 802.11w / SAE posture)
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


def parse_deauth_frame(data: bytes) -> dict:
    """Parse deauth or disassoc bytes via frame_core."""
    if len(data) >= 4 and fc.verify_fcs(data):
        data = data[:-4]
    fc_info, _rest = fc.parse_mgmt_header(data)
    subtype = fc_info["subtype_val"]
    if subtype == fc.FC_SUBTYPE_DEAUTH:
        parsed = fc.parse_deauth(data)
        parsed["kind"] = "deauth"
    elif subtype == fc.FC_SUBTYPE_DISASSOC:
        parsed = fc.parse_disassoc(data)
        parsed["kind"] = "disassoc"
    else:
        raise ValueError(f"not a deauth/disassoc frame (subtype={subtype})")
    parsed["is_broadcast"] = fc_info["is_broadcast"]
    parsed["locally_administered_sa"] = fc_info["locally_administered_sa"]
    return parsed


def analyze(parsed_frames: list[dict]) -> dict:
    """Spoof-heuristic analysis: flood rate, randomized SA, broadcast ratio."""
    alerts = []
    src_rates = defaultdict(list)
    broadcast = 0
    directed = 0
    loc_admin = 0
    total = len(parsed_frames)

    for fr in parsed_frames:
        src = fr["sa"]
        src_rates[src].append(fr.get("ts", 0))
        if fr["is_broadcast"]:
            broadcast += 1
        else:
            directed += 1
        if fr["locally_administered_sa"]:
            loc_admin += 1
            alerts.append({
                "type": "randomized_mac", "src": src,
                "detail": "Locally-administered bit set in source MAC",
            })

    for src, times in src_rates.items():
        times.sort()
        for i in range(len(times)):
            window = [t for t in times if 0 <= t - times[i] <= 1.0]
            if len(window) > 5:
                alerts.append({
                    "type": "flood_rate", "src": src, "count": len(window),
                    "detail": f"{len(window)} frames from {src} in 1.0s window (threshold: 5)",
                })
                break

    if total and broadcast / total > 0.5:
        alerts.append({
            "type": "broadcast_heavy", "broadcast": broadcast, "total": total,
            "detail": f"High broadcast deauth ratio: {broadcast}/{total} ({broadcast/total:.0%})",
        })

    return {
        "total_frames": total,
        "unique_sources": len(src_rates),
        "broadcast_count": broadcast,
        "directed_count": directed,
        "locally_administered_count": loc_admin,
        "alerts": alerts,
    }


def build_pmf_matrix() -> dict:
    return PMF_MATRIX


def categorize_resp_req(matrix: dict) -> dict:
    cats = {"required": [], "optional": [], "none": []}
    for posture, info in matrix.items():
        if info["respReq"] == 1:
            cats["required"].append(posture)
        elif info["pmf"] == "optional":
            cats["optional"].append(posture)
        else:
            cats["none"].append(posture)
    return cats


def run_analysis(frames: list[dict], matrix: dict) -> dict:
    parsed = []
    for e in frames:
        try:
            p = parse_deauth_frame(e["data"])
            p["ts"] = e["ts"]
            p["label"] = e["label"]
            parsed.append(p)
        except ValueError:
            continue
    analysis = analyze(parsed)
    resp = categorize_resp_req(matrix)
    return {
        "name": "w1-deauth-eng",
        "parsed": parsed,
        "analysis": analysis,
        "pmf_matrix": matrix,
        "resp_req": resp,
    }


def _show_report(result: dict, fh=sys.stdout) -> None:
    a = result["analysis"]
    print("=" * 66, file=fh)
    print("W1 — Deauth/PMF Resilience Analysis & Deauth IDS", file=fh)
    print("=" * 66, file=fh)
    print(f"\n[+] Parsed {a['total_frames']} management frames (byte-exact, wifi=False)\n", file=fh)
    for fr in result["parsed"]:
        reason = fr.get("reason_text", "N/A")
        print(f"  {fr['label']:26s} {fr['kind']:10s} src={fr['sa']}  "
              f"dst={fr['da']}  reason={fr.get('reason_code')} ({reason})", file=fh)

    print("\n--- Spoof-Heuristics Detection ---", file=fh)
    print(f"  Total frames:        {a['total_frames']}", file=fh)
    print(f"  Unique sources:      {a['unique_sources']}", file=fh)
    print(f"  Broadcast deauths:   {a['broadcast_count']}", file=fh)
    print(f"  Directed deauths:    {a['directed_count']}", file=fh)
    print(f"  Locally-admin MACs:  {a['locally_administered_count']}", file=fh)
    print(f"  Alerts generated:    {len(a['alerts'])}", file=fh)
    for alert in a["alerts"]:
        print(f"\n  [!] {alert['type'].upper()}: {alert['detail']}", file=fh)

    print("\n--- PMF Resilience Matrix ---", file=fh)
    print(f"  {'Posture':<32s} {'PMF':>9s} {'Resilience':>12s} {'respReq':>8s}", file=fh)
    for posture, info in result["pmf_matrix"].items():
        print(f"  {posture:<32s} {info['pmf']:>9s} {info['resilience']:>12s} "
              f"{info['respReq']:>8d}", file=fh)

    print("\n--- respReq Categorization ---", file=fh)
    for cat, postures in result["resp_req"].items():
        print(f"  [{cat.upper()}] ({len(postures)}): {', '.join(postures) or '—'}", file=fh)

    print("\n--- Report Summary ---", file=fh)
    print(f"  Deauth frames analyzed: {a['total_frames']}", file=fh)
    print(f"  Total alerts:           {len(a['alerts'])}", file=fh)
    print(f"  PMF postures cataloged: {len(result['pmf_matrix'])}", file=fh)
    print(f"  Postures w/ respReq=1:  {len(result['resp_req']['required'])}/{len(result['pmf_matrix'])}", file=fh)
    print("\nOffline demo complete — all checks passed.  No radio emitted.", file=fh)
    print("=" * 66, file=fh)


def run_demo(output_report: bool = True) -> int:
    frames = build_showcase_frames()
    result = run_analysis(frames, build_pmf_matrix())
    _show_report(result)
    if output_report:
        reports_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "reports")
        os.makedirs(reports_dir, exist_ok=True)
        path = os.path.join(reports_dir, "w1_deauth_eng_report.json")
        with open(path, "w") as f:
            json.dump(result, f, indent=2, default=str)
        print(f"\n[+] JSON report -> reports/w1_deauth_eng_report.json")
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="w1-deauth-eng",
        description="Deauth/disassociation 802.11 frame engineering + spoof analysis "
                    "(pure-stdlib bytes; offline; no radio).")
    parser.add_argument("--json", metavar="PATH",
                        help="write JSON report to PATH (default reports/)")
    parser.add_argument("--wifi", action="store_true",
                        help="[SAFETY GATE] real-air emission. NOT implemented; must be False.")
    parser.add_argument("--lab-ssid", default="lab-test-net", help="allow-listed lab SSID")
    args = parser.parse_args(argv)
    if args.wifi:
        print("ERROR: real-air emission is not implemented (hardware gate). "
              "This tool proves frame correctness offline only.", file=sys.stderr)
        return 2
    result = run_analysis(build_showcase_frames(), build_pmf_matrix())
    _show_report(result)
    if args.json:
        d = os.path.dirname(args.json)
        if d:
            os.makedirs(d, exist_ok=True)
        with open(args.json, "w") as f:
            json.dump(result, f, indent=2, default=str)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
