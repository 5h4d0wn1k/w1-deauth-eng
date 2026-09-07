# W1 — Deauth/PMF Resilience Analysis & Deauth IDS `w1-deauth-eng`

802.11 management-frame deauth/disassociation analysis toolkit for authorized wireless security assessment.

## Overview

This project implements defensive analysis of 802.11 deauthentication and disassociation attacks:
- **Frame parser**: Parses raw deauth/disassoc management frames from hex-encoded dumps
- **Spoof-heuristics detector**: Identifies MAC randomization, flood-rate anomalies, broadcast vs directed patterns
- **PMF resilience matrix**: Maps AP security postures to Protected Management Frames (PMF) resistance levels
- **respReq categorizer**: Classifies management frame protection requirements per security posture
- **Offline-first**: Runs fully on embedded sample data with no network dependency

## Features

- **802.11 frame parser**: Decodes deauth (subtype 12) and disassoc (subtype 10) frames from raw bytes
- **Flood-rate detection**: Flags sources emitting >5 deauth frames within a 1-second sliding window
- **MAC-randomization heuristic**: Detects locally-administered bit as indicator of address randomization
- **Broadcast vs directed analysis**: Identifies deauth storms targeting specific vs all clients
- **PMF matrix builder**: 8 security postures with resilience and protection-requirement ratings
- **Reason code lookup**: Maps IEEE 802.11-2020 Table 9-45 reason codes to descriptions
- **Offline demo**: 12 embedded sample frames covering normal, flood, and spoofed scenarios

## Installation

```bash
# No external dependencies — Python 3.8+ standard library only
python3 firmware/deauth_engine.py --help
```

## Usage

```bash
# Run the offline demo (prints parsed frame table + analysis, writes JSON report)
python3 firmware/deauth_engine.py --json reports/w1_deauth_eng_report.json

# Run the byte-exact unit tests
python3 -m unittest discover -s tests
```

```python
from firmware.deauth_engine import run_analysis, build_pmf_matrix
from firmware import frame_core as fc

# Build a real deauth frame, byte-exact, offscreen
frame = fc.build_deauth("00:11:22:33:44:66", "00:11:22:33:44:55",
                        "00:11:22:33:44:55", reason=7, seq_num=8) + fc.fcs(frame)

# Parse + analyze a collection of frames
alerts = run_analysis([], build_pmf_matrix())  # see parse_deauth_frame for a single frame
```

## Example Output

```
=================================================================
W1 — Deauth/PMF Resilience Analysis & Deauth IDS
=================================================================

[+] Parsed 12 management frames from embedded dump

  deauth-directed-1              subtype=deauth      src=aa:bb:cc:dd:ee:ff dst=ff:ff:ff:ff:ff:ff reason=7 (Information element in disassoc/deauth frame not acceptable)
  ...

--- Spoof-Heuristics Detection ---
  Total frames:        12
  Unique sources:      4
  Broadcast deauths:   7
  Directed deauths:    5
  Locally-admin MACs:  3
  Alerts generated:    4

  [!] FLOOD_RATE: 6 frames from aa:bb:cc:dd:ee:ff in 1.0s window (threshold: 5)
  [!] RANDOMIZED_MAC: Locally-administered bit set in source MAC
  [!] BROADCAST_HEAVY: High broadcast deauth ratio: 7/12 (58%)

--- PMF Resilience Matrix ---
  Posture                          PMF   Resilience   respReq
  ----------------------------------------------------------------
  Open (no encryption)             none         None        0
  WPA3-SAE (PMF req)           required         High        1
  ...

--- Report Summary ---
  Deauth frames analyzed: 12
  Total alerts:           4
  Postures w/ respReq=1:  5/8

Demo complete — all checks passed.
```

## IMPORTANT: Read before use.

This project is provided for **educational and authorized security testing purposes only**.

### Authorization Requirements
- You MUST have explicit written permission before performing any wireless security analysis
- Capturing or analyzing deauth/disassoc frames on networks you do not own is illegal
- This tool should ONLY be used on networks you own or have written authorization to test
- The offline tooling in this repo performs **no radio emission and no capture** — it builds and
  parses frame bytes on the host CPU only, and is designed to prove frame correctness in a lab.

### Regulatory Framework
- **Federal Communications Act (47 U.S.C. § 333)**: Willful interference with or jamming of
  authorized radio communications is a federal crime. Transmitting deauth frames on a real
  channel **interferes with** a lawful radio service and requires authorization.
- **47 CFR Part 15 / Part 18 (electromagnetic emissions)**: Unauthorized intentional radiators
  and spurious emissions are regulated. Any real-air use must operate on licensed/authorized
  channels within FCC emission limits.
- **Computer Fraud and Abuse Act (CFAA, 18 U.S.C. § 1030)**: Unauthorized access to, or
  interference with, protected computers and networks is a federal crime.
- **State Laws**: Many states have additional wiretapping, computer-crime, and RF-interference statutes.

### Acceptable Use
- Testing deauth resilience of your own wireless infrastructure
- Authorized penetration testing with a written scope
- Academic research in controlled lab environments (shielded/faraday, licensed band)
- Security education and training

### Prohibited Use
- Deauthing access points or clients you do not own
- Interfering with wireless networks without authorization
- Any activity that violates applicable laws or regulations
- Operating an intentional radiator outside FCC/regulatory limits

### No Warranty
This software is provided "AS IS" without warranty of any kind. The author is not responsible
for any misuse, damage, or legal consequences caused by this software.

### Responsible Disclosure
If you discover vulnerabilities using this tool, follow responsible disclosure practices:
1. Report to the vendor/owner privately
2. Allow reasonable time for remediation
3. Do not exploit beyond proof of concept

## Live Lab Test Plan

This repo is a pre-hardware engineering/simulation tool. To take it to a live lab, you must
add real-air capability behind a hardware gate and run in a controlled, authorized environment.

Offline (this repo, no radio):
1. `python3 firmware/deauth_engine.py --json reports/w1.json` — run the frame-analysis demo
   (exit 0) and inspect the JSON in `reports/`.
2. `python3 -m unittest discover -s tests` — confirm all byte-exact unit tests pass (exit 0).
3. `python3 firmware/deauth_engine.py --wifi` — confirm the real-air gate rejects emission
   (exit 2) until a hardware backend is implemented and an explicit `--wifi --lab-ssid` + MAC
   allowlist confirmation is provided.

Authorized lab (only with hardware gate + written scope + allowlist):
4. On an AIR-GAPPED, shield-attenuated test bench on an authorized channel, transmit the
   exact frame bytes this tool prints, and confirm they are received by the lab monitor with
   matching byte sequence.
5. Point a lab monitor (e.g., w7-wids-sensor) at the bench; confirm it detects the deauth
   storm you generated and emits an alert.
6. Confirm `green = permitted`: no frame is ever transmitted without prior lab-owner written
   authorization and the LAB_SSID/MAC allowlist in force.

## Metrics

- Frame header builder/parser: 802.11 management address format 3 (dur + DA/SA/BSSID + SeqCtl)
- Frame types engineered byte-exact: deauth (12), disassociation (10)
- FCS: IEEE CRC-32 append + verify (rejects corrupted frames)
- Spoof heuristics: flood-rate (threshold 5/s), locally-administered-SA, broadcast-ratio
- PMF resilience posture matrix: 8 postures, respReq classification
- Deterministic offline: all frame bytes derived from builders; no wall-clock randomness

- Test suite: `python3 -m unittest discover -s tests`
- Reports: `reports/w1_deauth_eng_report.json` (gitignored)

## License

MIT
