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
# No external dependencies — Python 3.6+ standard library only
python3 firmware/deauth_engine.py
```

## Usage

```bash
# Run offline demo with embedded sample frames
python3 firmware/deauth_engine.py
```

```python
from firmware.deauth_engine import parse_mgmt_frame, detect_spoof_heuristics, build_pmf_matrix

# Parse a raw deauth frame
frame_bytes = bytes.fromhex("c0003a01ffffff112233445566aabbccddeeff00170007")
parsed = parse_mgmt_frame(frame_bytes)

# Analyze a collection of parsed frames
alerts = detect_spoof_heuristics([parsed])

# Get the PMF resilience matrix
matrix = build_pmf_matrix()
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

### Legal Framework
- **Computer Fraud and Abuse Act (CFAA)**: Unauthorized interception of network traffic and interference with wireless communications is a federal crime
- **Federal Communications Act (47 U.S.C. § 333)**: Willful interference with authorized radio communications is prohibited
- **State Laws**: Many states have additional wiretapping and computer crime statutes

### Acceptable Use
- Testing deauth resilience of your own wireless infrastructure
- Authorized penetration testing with written scope
- Academic research in controlled lab environments
- Security education and training

### Prohibited Use
- Deauthing access points or clients you do not own
- Interfering with wireless networks without authorization
- Any activity that violates applicable laws or regulations
- Commercial use without proper licensing

### No Warranty
This software is provided "AS IS" without warranty of any kind. The author is not responsible for any misuse or damage caused by this software.

### Responsible Disclosure
If you discover vulnerabilities using this tool, follow responsible disclosure practices:
1. Report to the vendor/owner privately
2. Allow reasonable time for remediation
3. Do not exploit beyond proof of concept

## License

MIT
