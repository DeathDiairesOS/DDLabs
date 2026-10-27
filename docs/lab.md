# Ten-concern replay lab

The lab runs invented observations through WiFi Scout's production parsers,
rule engine, and terminal renderer. It produces a report you can inspect and
repeat without a Wi-Fi adapter. The ten cases are representative concerns,
not a ranking of how often attacks occur.

The expected complete run contains **six observable risk indicators, three
demonstrated blind spots, and one input-protection check**. Ten passing scenario
checks would mean the program behaved as expected in those cases. It would
**not** mean ten attacks were detected or that a network is trustworthy.

## Run it and open the results

After installing WiFi Scout using the README instructions:

```sh
wifi-scout lab --output lab-results
```

Open `lab-results/index.html` in a browser. It is a standalone, offline report
with filters and expandable evidence, controls, findings, and scanner output.
For machine-readable output as well:

```sh
wifi-scout lab --output lab-results --json
```

The report files are written in both modes:

| Output | Contents |
| --- | --- |
| `index.html` | Human-readable results, with limitations and controls alongside each case |
| `results.json` | Complete scenario outcomes, expected behavior, checks, findings, and normalized observations |
| `fixtures/*.nmcli.txt` | Synthetic NetworkManager output used by the real parser |
| `fixtures/*.pcap` | Generated management-frame captures used by the real TShark executable |
| `terminal-hostile-ssid.txt` | Production CLI rendering of the hostile-name case |

Reusing the output directory replaces these generated artifacts. All fixture
names, addresses, and frames are invented. Running the lab does not collect
nearby network data, save visit history, connect to an AP, or transmit frames.

The lab has no additional Python runtime dependency. **TShark must be installed
and available on `PATH` for the native deauthentication capture case.** No
capture privileges or monitor interface are needed to decode these files. The
20-second observation window is encoded in packet timestamps; the test reads a
static file rather than waiting for a radio capture.

Exit codes make incomplete runs visible:

| Code | Meaning |
| --- | --- |
| `0` | All ten scenario expectations passed |
| `1` | At least one scenario behaved unexpectedly |
| `2` | A required native check was skipped, such as missing TShark, or the command could not complete |

When TShark is absent, LAB-07 is marked **skipped** and contributes no detection
claim. A broken installed decoder produces a failed check; it is not replaced
with a simulated successful result. Read the generated report's actual status
and tool versions rather than assuming every run is complete.

## What each case establishes

| Case | Concern | Expected observation and its limit |
| --- | --- | --- |
| LAB-01 | A same-name hotspot with conflicting security | `SECURITY_CONFLICT`; candidate withheld for the conflicting name. A configuration upgrade or unrelated operator can also explain the pattern. |
| LAB-02 | An exact-copy evil twin | No observable difference. Identical advertised name, BSSID, and security produce the same analysis; identity stays unconfirmed. |
| LAB-03 | Security downgraded since a saved visit | `BASELINE_SECURITY_CHANGED` for a familiar name changing from WPA2 to open on a new BSSID, when the earlier observation is supplied. Replacement or reconfiguration remains a possible explanation. |
| LAB-04 | Obsolete WEP protection | `SECURITY_LEGACY`; the AP is excluded from suggestions. The test does not crack a key or demonstrate eavesdropping. |
| LAB-05 | Original WPA or TKIP ciphers | Legacy protocol/cipher findings, including a WPA2 advertisement offering TKIP alongside CCMP. This identifies advertised configuration, not the cipher a client actually negotiates. |
| LAB-06 | Open hotspot radio exposure | `SECURITY_OPEN`, distinguished from Enhanced Open/OWE. Correctly validated HTTPS contents remain protected; an authorized open AP can remain a limited candidate with warnings. |
| LAB-07 | Unusual deauthentication activity | Actual TShark decoding of 40 non-retry frames over 20 seconds triggers `DEAUTH_ACTIVITY` for the primary AP. That AP is excluded; an unaffected authorized AP may still be suggested. Activity does not prove intent or identify an attacker. |
| LAB-08 | A phishing captive portal | Outside scan visibility. Identical Wi-Fi advertisements cannot reveal page contents, credential forms, or TLS behavior. No portal is hosted or exercised. |
| LAB-09 | DNS/ARP spoofing or traffic interception | Outside the collected fields. Identical management advertisements cannot reveal post-connection traffic manipulation. No interception is attempted or simulated. |
| LAB-10 | An SSID trying to inject terminal/HTML instructions | The hostile name remains one data record and its terminal control sequence is escaped. This checks tool input handling, not malicious-AP classification. Browser rendering is tested separately. |

LAB-02, LAB-08, and LAB-09 are **observational-equivalence checks**: the same
scanner input is presented under two hypothetical explanations. Matching
results demonstrate that those explanations cannot be distinguished with these
observations. They are not demonstrations of executed attacks or successful
attack detection.

## Benign controls and boundaries

The suite also checks that a normal two-AP network produces no medium/high
findings, a stronger unrelated private AP is not selected without authorization,
an unchanged baseline does not produce a change warning, and unavailable
security/cipher fields do not become legacy-protection findings. Enhanced Open
is kept separate from an explicitly open link.

The deauthentication case includes four negative controls:

| Control | Decoded observation | Expected finding |
| --- | --- | --- |
| Ordinary activity | 2 frames over 20 seconds | No `DEAUTH_ACTIVITY` |
| Insufficient interval | 40 frames over 5 seconds | No `DEAUTH_ACTIVITY`; the rule requires at least 10 seconds |
| Retransmissions | 40 retry-marked frames over 20 seconds; non-retry count is zero | No `DEAUTH_ACTIVITY` |
| Below the rate threshold | 39 frames over 20 seconds, or 1.95 frames/second | No `DEAUTH_ACTIVITY` |

The 39-versus-40 boundary exercises a documented heuristic. A result below that
threshold is not evidence that attackers are absent. Read the [rule
reference](rules.md) for all thresholds and competing explanations.

## What has and has not been validated

The lab was exercised on Linux with **TShark 4.4.19 decoding generated PCAPs**.
NetworkManager cases replay its documented text format through the real parser;
they do not invoke `nmcli`, NetworkManager, a driver, or a radio. No physical
Wi-Fi interface was available during development.

The production CLI renderer is part of LAB-10. The optional browser regression
suite is separate and requires development tools:

```sh
python tests/browser_smoke.py
python tests/lab_browser_smoke.py --results lab-results --screenshots
```

See the README for its Playwright/Chromium setup. Its result is not silently
counted as part of a `wifi-scout lab` run.
The second command checks the generated interactive report and feeds LAB-10's
already-parsed observations to the production dashboard renderer. It also
writes desktop/mobile report screenshots; that browser check exercises output
handling, not wireless collection.

The implementation lives in `src/wifi_scout/lab.py`, the deterministic packet
builder in `src/wifi_scout/lab_fixtures.py`, and the report renderer in
`src/wifi_scout/lab_report.py`. These ship with the installed package. The
generated input files and complete JSON report make the claims inspectable.

## A later hardware check

A physical follow-up can use an owned test AP with documented settings and a
Linux machine with NetworkManager. Record the AP model, firmware, radio,
driver, OS, and tool versions; then compare an ordinary live scan with those
known settings. A saved visit can be compared after a deliberate configuration
change on that test AP. Label those results separately from replay results.

For passive advanced observations, use a separate compatible monitor adapter
so the current connection can stay in place, and follow the README's hardware
and capture-permission requirements. WiFi Scout does not change interface
mode or stop NetworkManager. This document does not claim that hardware checks
have been performed.
