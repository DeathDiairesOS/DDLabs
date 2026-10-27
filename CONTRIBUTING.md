# Contributing to WiFi Scout

Contributions should make Wi-Fi observations easier to understand without promising more than a scan can establish. Small, documented changes with meaningful tests are welcome.

## Local setup

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e .
python -m unittest discover -s tests -v
wifi-scout serve --demo
```

Python 3.10 or newer is required. The application has no Python runtime dependencies. Tests use `unittest`; live wireless hardware is not required for the test suite. Build tooling may need to be installed separately to create a wheel:

```sh
python -m pip install build
python -m build
```

## Before opening a change

- Explain the user-visible problem, the resulting behavior, and how you verified it.
- Keep collection inside adapters and interpretation inside the deterministic rule engine. Avoid mixing subprocess calls with recommendations.
- Preserve unknown values. Do not turn missing telemetry into a security failure or assume that a name/BSSID authenticates an operator.
- Keep findings stable and explainable: ID, severity, confidence, evidence, plain language, and competing explanations. Update [docs/rules.md](docs/rules.md) when rules or thresholds change.
- Use structured subprocess arguments. Treat SSIDs, BSSIDs, tool output, and imported files as untrusted data. Add meaningful tests for new parsing and output contexts.
- Keep runtime operation offline, dependencies modest, and all browser assets local. Do not add telemetry or automatic connections.
- Do not add injection, password attacks, client probing, traffic manipulation, automatic monitor-mode changes, or service shutdown.
- Keep source/mode labeling and the explicit authorization boundary for recommendations.

For UI changes, check a narrow mobile viewport and desktop viewport, keyboard navigation, loading/error/empty states, and names containing punctuation, Unicode, HTML-looking text, or control characters. Update screenshots when the interface changes substantially; screenshots must stay labeled as demo observations.

## Adapter and hardware contributions

Read [architecture.md](docs/architecture.md) and [tool-fields.md](docs/tool-fields.md). A new adapter must document its official field meanings, supported OS/tool versions, permission requirements, observation limits, and subprocess failure behavior. Platform support must be implemented and tested before it is advertised.

For real-hardware testing, record the OS, NetworkManager/TShark version, adapter and driver, capture mode/channel, command used, and what was verified. Obtain permission and minimize data. Prefer synthetic or sanitized selected-field fixtures; do not upload packet captures containing application payloads, client identifiers, credentials, or unrelated personal data. Document any normalization applied to fixtures.

Separate claims verified with fixtures from claims verified with hardware. A passing fixture test is not evidence that a driver can enter monitor mode or that a venue’s network is trustworthy.

## Reporting problems

For an ordinary bug, include the command, expected/actual behavior, OS and tool versions, and a minimal sanitized example. Do not include secrets or a full scan of your surroundings unless you have deliberately reviewed and anonymized it. For a potential vulnerability, follow [SECURITY.md](SECURITY.md).

Contributions are provided under the project’s [MIT License](LICENSE).
