# What WiFi Scout uses

The native Android phone app uses Android's Java APIs, OpenJDK, Gradle and the
Android Gradle plugin, with JUnit for development tests. Its interface, Wi-Fi
adapter, capability parser and comparison rules are custom code; it has no
third-party runtime library dependency. The generated Gradle wrapper retains
Gradle's own license notices. See [the Android guide](../android/README.md).

The [iPhone companion](../iphone/README.md) is custom HTML, CSS and JavaScript
using standard browser file, clipboard and service-worker APIs. It runs in
Safari and can be added to the Home Screen after its assets are served from
HTTPS. It views explicitly imported Android or desktop reports; it does not
perform native nearby-Wi-Fi scanning or add radio access to the browser. It
labels any original suggestion as historical, keeps details expandable, and
leaves joining to the user in iPhone Settings. No frontend library, account or
report-upload service is required.

Android's **Share report** workflow uses a custom JSON exporter and private
read-only content provider, then the operating system's share chooser. After a
disclosure and explicit confirmation, the app retains at most five exported JSON
files in its private cache. This is an exception to the default memory-only
handling of scan observations. Only the selected destination receives a
temporary read grant; a recipient may save its own copy. Reports can reveal
network names, access-point addresses, timing and joining selections, but contain
no passwords. The iPhone companion processes imported data in page memory and
caches only its app-shell assets, not report files or results.

The table below describes the separate desktop tool and project media tooling.

WiFi Scout has no Python runtime package dependencies and no hosted backend,
LLM, telemetry, account system, or external API. System executables are used
only for the explicitly selected collection/decoding backend.

| Open-source component | Its role | What was exercised here |
| --- | --- | --- |
| Python and its standard library | CLI, data models, process execution, local HTTP server, JSON, storage, and tests | Running application, automated tests, and isolated package installs |
| NetworkManager / `nmcli` | Ordinary Linux Wi-Fi discovery | Documented output replay and process/error tests; no live Wi-Fi hardware was available |
| Wireshark / TShark | Optional management-frame decoding and passive capture | Actual TShark 4.4.19 decoded generated PCAP files; no live capture |
| Playwright, Chromium and WebKit | Development-only browser checks, screenshots and demo recording | Dashboard rendering, keyboard access, hostile SSIDs, disclosure controls, offline-request checks and the real dashboard walkthrough; iPhone-companion layout and report-import checks in desktop browser engines |
| FFmpeg and FFprobe | Development-only video editing, encoding and validation | Captioned GitHub demo, animated preview, scene timing and full-video decoding |
| Python `unittest` | Automated regression tests | Parser, rule, privacy, HTTP, diagnostics, and simulation checks |
| setuptools and `build` | Package creation | Wheel/source builds and wheel installation outside the checkout |
| Git | Source version-control format | Local checkout; publication is a separate action |

The HTML, CSS, and JavaScript use browser standards directly; there is no React,
Vue, charting library, remote font, or CDN requirement. GitHub Actions workflow
files are included for CI. GitHub's hosting service is not itself part of the
offline application, and locally passing checks do not claim a hosted CI run.

## Custom code

- Collection adapters and robust parsers that normalize tool-specific fields.
- The data model and deterministic rules, including finding IDs and evidence.
- Recommendation eligibility, explicit joining permission, and separate
  configuration, reception, and identity assessments.
- Local-only dashboard/API, readable summaries, grouped network cards, and
  expandable technical evidence.
- Opt-in saved-visit comparisons, deletion, and hostile-input handling.
- Synthetic packet builders, the ten-concern lab, and the stress simulations.
- Read-only tool/radio readiness diagnostics and standalone evidence reports.
- Native Android scanning and permission handling, report serialization and
  explicit sharing through a private read-only provider.
- Safari/Home Screen report importing, historical suggestion display, and
  offline app-shell caching for the iPhone companion.

The rules are heuristics written for this project. They are not a pretrained
security model or a validated intrusion-detection product. Passing a synthetic
test establishes behavior for that input, not real-world detection accuracy.

## Tools that were not used as scanners

We did not use Aircrack-ng/airodump-ng, Scapy, Kismet, or an external reputation
service. `mac80211_hwsim`, `wmediumd`, and `hostapd` are relevant to a separately
prepared kernel virtual-radio lab, but that lab is not available or executed in
this environment. Merely listing them in diagnostics does not claim support or
validation. See [hardware validation](hardware-validation.md).

Official field references for the two implemented backends are in
[tool-fields.md](tool-fields.md).
