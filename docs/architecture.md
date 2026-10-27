# Architecture

WiFi Scout separates collection, interpretation, and presentation. Runtime code uses the Python standard library; NetworkManager and TShark remain optional system executables selected explicitly by the user.

```text
nmcli discovery ──────┐
TShark observations ─┼─> ScanResult / NetworkObservation ─> evaluate() ─> Report
bundled demo ────────┘                                      ↑             │
                                                optional local baseline  ├─ CLI text / JSON
                                                                        └─ loopback dashboard
```

## Collection boundary

Each adapter returns a `ScanResult` with source, mode, timestamps, limitations, and normalized `NetworkObservation` entries. Adapters do not rank access points, authenticate operators, or connect to networks. `ScanError` represents an actionable collection failure instead of silently substituting demo data.

- **NetworkManager:** Linux discovery through escaped terse `nmcli` output. The adapter handles escaped separators and backslashes. Signal percentage remains a percentage; it is not converted into fabricated dBm. Frequency determines band when available. A scan request may make the OS transmit probes, and cached observations can remain in its results.
- **TShark:** explicit advanced collection or capture-file import. Live mode requires an existing monitor interface, observes its configured channel, and uses selected management-frame fields. It does not configure the adapter, stop services, or write raw captures. Imported captures have their own observation time and must not be presented as current live discovery.
- **Demo:** packaged synthetic observations exercise interpretation and presentation without accessing wireless hardware. Its mode and source remain explicit throughout the report.

Commands use argument arrays without a shell. Names discovered over the air never become command fragments. Missing tools, permission failures, malformed output, unsupported platforms/interfaces, and empty observations are different outcomes.

See [tool-fields.md](tool-fields.md) for official documentation and field semantics. A future adapter for another OS must meet the same contract and include documented field semantics and tests before claiming platform support.

## Shared model

`models.py` contains dataclasses for observations, advertised `Security`, `Finding`, `Assessment`, `Recommendation`, and `Report`. `None` means **unknown**, not false. In particular, absent PMF information does not mean PMF is disabled, and an absent deauthentication count does not mean a capture observed zero deauthentication frames.

SSID and BSSID identify observations, not trusted entities. Multiple observations may share an SSID or advertise different properties. A BSSID can be spoofed, so it must not serve as an authentication credential. Application payloads, passwords, and nearby client identifiers are not part of the normalized model.

## Interpretation boundary

`engine.evaluate(scan, authorized_ssids, venue_ssid, baseline)` is deterministic and independent of subprocesses, the web server, and storage. It produces three independent dimensions, findings, missing information, and a recommendation with reasons and caveats.

Authorization is supplied by the user. A venue-name match does not create authorization. Candidate eligibility and evidence sufficiency are evaluated before comparisons, so a nearby private network is not selected simply because its encryption or signal is stronger. Results never express a universal safety percentage or claim that an operator is verified.

The [rule reference](rules.md) defines stable IDs, severities, evidence, thresholds, ranking, and abstention behavior. Confidence describes support for a finding; it is not a probability that a network is malicious. Baseline changes and conflicting advertisements carry competing explanations.

## Presentation boundary

The CLI prints readable summaries or a JSON representation of `Report`. Terminal rendering escapes control and directional-format characters supplied in network names. JSON remains structured data; consumers must apply their own output-context escaping.

The dashboard serves bundled HTML, CSS, and JavaScript from a server bound to IPv4 loopback. Ordinary discovery or demo mode is fixed when the server starts. The main scan action uses a JSON POST; reading a page does not trigger a scan. A per-process request token and local Host/Origin checks protect mutation endpoints from unrelated web pages. The browser renders untrusted text as text rather than HTML. The dashboard is intended for one local user, not deployment on a public network.

The UI exposes evidence, uncertainty, and limitations alongside recommendations. The source/mode label stays visible so a demonstration cannot be mistaken for a live observation. Advanced capture remains a CLI action with explicit hardware and privilege acknowledgement.

The default dashboard uses short explanations and groups exact, nonempty SSIDs
for readability. Grouping is presentation only: the normalized observations and
recommendation engine still operate on individual access points. A group's
visible warning summaries include concerns from all of its observations.
Addresses, raw measurements, rule IDs, confidence, and evidence remain available
inside initially closed technical sections. Important warnings and the inability
to authenticate an operator are visible without expanding those sections.

## Optional storage

Normal scans do not persist. A user can explicitly save a normalized previous-visit baseline and later request comparison. The dashboard uses one local baseline file; CLI paths may be chosen explicitly. History is distinct from any files the user redirects or exports themselves.

Baseline storage limits access through private file permissions and avoids partial writes. It is not an encrypted location-history database. Names, BSSIDs, and timestamps can be sensitive, and backups or exported copies remain outside the deletion operation. Demo data is excluded from live baselines.

## Validation strategy

- Parser fixtures check escaped `nmcli` fields, unknowns, valid/invalid numeric values, security interpretations, and selected TShark observations.
- Rule tests check benign multi-AP behavior, explicit candidate eligibility, insufficient evidence, conflicting configurations, optional baselines, and supported management-frame findings.
- Hostile-input tests cover terminal control sequences and HTML-looking names, as well as safe subprocess invocation and local web-service boundaries.
- Browser checks exercise real DOM interaction, responsive rendering, and demo labeling. Screenshots are generated from bundled demo observations.
- Packaging checks install the built wheel so missing static assets or fixtures are caught independently of a source checkout.

Fixtures can establish parser and rule behavior. They cannot establish driver compatibility, RF behavior, or accuracy in a real venue. No real wireless hardware was available during initial development; that limitation is stated in the README and must remain visible until actual validation is documented.
