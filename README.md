> **⚠️ EDUCATIONAL USE ONLY — AUTHORIZED TESTING ONLY.**
> This project exists for education, research, and **defense of systems you own
> or hold explicit written authorization to assess**. Unauthorized use is
> prohibited and may be illegal. Read [ETHICS.md](ETHICS.md) and
> [SCOPE.md](SCOPE.md) before use. Use at your own risk; **AS IS**, no warranty.

# W1 — 802.11 Deauthentication Attack & PMF Resilience Analysis

Deauthentication (`deauth`) frame parsing, spoofed-MAC heuristics, and WPA3
Protected Management Frames (PMF) resilience analysis for **Wi-Fi security**
research, **wireless IDS (WIDS)** tuning, and authorized penetration testing.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Stars](https://img.shields.io/github/stars/5h4d0wn1k/w1-deauth-eng)](https://github.com/5h4d0wn1k/w1-deauth-eng)
[![Issues](https://img.shields.io/github/issues/5h4d0wn1k/w1-deauth-eng)](https://github.com/5h4d0wn1k/w1-deauth-eng/issues)
[![Last commit](https://img.shields.io/github/last-commit/5h4d0wn1k/w1-deauth-eng)](https://github.com/5h4d0wn1k/w1-deauth-eng)

## Why

802.11 deauthentication is one of the oldest and most abused wireless attacks:
management frames are sent in clear, so any nearby station can flood a client
off an access point or force an association cycle. Defenders need tooling that
proves exactly how such frames are built *and* what anomaly patterns a WIDS
should raise on — without emitting a single radio packet. W1 is an offline,
byte-exact engineering and detection-research tool: it constructs and parses
802.11 management frames on the host CPU, classifies spoof heuristics (MAC
randomization, flood rates, broadcast storms), and maps an AP's security
posture onto a PMF resilience matrix. Everything runs on embedded sample data
with zero network access, which keeps it firmly inside the scope of authorized
wireless security testing, lab research, and detection engineering.

## Features

- **802.11 frame builder + parser** — byte-exact deauth (subtype 12) and
  disassociation (subtype 10) frames with IEEE CRC-32 FCS append/verify
- **Flood-rate detection** — flags sources emitting >5 deauth frames in a 1s
  sliding window
- **MAC-randomization heuristic** — detects the locally-administered bit as an
  address-randomization indicator
- **Broadcast vs directed analysis** — distinguishes deauth storms aimed at all
  clients from targeted ones
- **PMF resilience matrix** — 8 security postures (open, WPA2, WPA3-SAE, …)
  with resilience and `respReq` protection-requirement ratings
- **Reason-code lookup** — maps IEEE 802.11-2020 Table 9-45 reason codes to
  plain-language descriptions
- **Offline demo** — 12 embedded sample frames covering normal, flood, and
  spoofed scenarios; JSON report output
- **Safety-gated live gate** — `--wifi` requires an explicit `--lab-ssid` +
  allowlist before any real-air backend is considered

## Quickstart

Zero third-party dependencies — Python 3.8+ standard library only.

```bash
# Full offline demo: parses embedded frames, prints analysis, writes JSON report
python3 firmware/deauth_engine.py --json reports/w1_deauth_eng_report.json

# Real-air emission gate (rejects until a hardware backend + allowlist exist)
python3 firmware/deauth_engine.py --wifi --lab-ssid your-lab-ssid

# Byte-exact unit tests (23 cases)
python3 -m unittest discover -s tests
```

Programmatic use:

```python
from firmware.deauth_engine import run_analysis, build_pmf_matrix
from firmware import frame_core as fc

frame = fc.build_deauth("00:11:22:33:44:66", "00:11:22:33:44:55",
                        "00:11:22:33:44:55", reason=7, seq_num=8) + fc.fcs(frame)
alerts = run_analysis([], build_pmf_matrix())
```

## Project structure

- `firmware/deauth_engine.py` — CLI entry point, analysis engine, PMF matrix
- `firmware/frame_core.py` — byte-exact 802.11 management-frame builder/parser
- `tests/` — 23 byte-exact unit tests

## Legal & authorized use

This project is provided for **educational and authorized security testing
purposes only** — no radio emission and no capture. Real-air operation is
explicitly gated. Read the full requirements in [ETHICS.md](ETHICS.md) and
[SCOPE.md](SCOPE.md), report responsibly, and never attach this to a network
you do not own or have written authorization to assess. See
[SECURITY.md](SECURITY.md) and [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Please keep all test payloads synthetic
and all targets within your own authorized lab.

## License

MIT — see [LICENSE](LICENSE).