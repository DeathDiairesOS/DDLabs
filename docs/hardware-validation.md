# Readiness and hardware validation

WiFi Scout can test its parsers and rules without a radio. Establishing that it
works with a particular adapter, driver, and real venue requires a separate
hardware run. Keep those evidence levels distinct when reporting results.

| Test level | What it exercises | What it does not establish |
| --- | --- | --- |
| Synthetic scan text and generated PCAPs | Production parsing, TShark decoding, rule behavior, output handling, and controlled loss/duplication cases | Real radio reception, firmware, drivers, or live capture permissions |
| Kernel virtual radios | A Linux wireless software stack and virtual network configuration | Physical antennas, RF interference, chipset firmware, or a real venue's behavior |
| Physical test equipment | The specific adapter, driver, AP, configuration, and conditions recorded in that run | Compatibility with every device or reliable attack attribution |

The development environment used for the initial lab had no wireless network
interface or loaded `mac80211_hwsim` module. Its inspected effective capability
set was empty, and virtual-radio setup tools were unavailable. No kernel-radio
or physical-radio run is claimed by the synthetic lab results.

## Check this machine first

```sh
wifi-scout doctor
wifi-scout doctor --json > hardware-readiness.json
```

`doctor` is read-only. It inspects the platform, tool availability, interface
type/driver information, and available capability indicators. It does not scan
for networks, connect, change interface modes, load kernel modules, start
services, or alter privileges. Its report excludes Wi-Fi names, MAC addresses,
IP addresses, and hostnames. Version commands do not prove that a subsequent
scan or capture will be permitted.

Read each check's status. Missing tools or unavailable interface information are
different from a confirmed working scanner. A loaded virtual-radio module is
not physical hardware validation, and an installed TShark executable is not
proof of live capture permission. Save a fresh readiness report on the machine
where a hardware test will actually run.

## Ordinary discovery with a test AP

Use a test access point you own or have permission to configure. Keep unrelated
users off the test setup, and use a separate adapter for experiments that could
affect the current connection. Record the AP's settings before collecting data.

For an example test network named `Scout Lab`:

```sh
wifi-scout scan --interface wlan0 --venue 'Scout Lab' --allow-ssid 'Scout Lab' --json > live-normal-01.json
wifi-scout scan --interface wlan0 --venue 'Scout Lab' --allow-ssid 'Scout Lab' --json > live-normal-02.json
```

Replace `wlan0` with the interface identified on your machine. `--allow-ssid`
confirms permission and any required credentials; it neither supplies a
password nor causes a connection. NetworkManager discovery may transmit normal
Wi-Fi probe requests. WiFi Scout never joins the network itself.

Compare the AP's documented name, security mode, band, and channel with the
observations. Run again at a different known location or distance, recording
that change. A changing signal is expected; it is not a measurement of internet
speed. NetworkManager may retain cached access-point entries, so record the
timing and any AP changes rather than treating every entry as a fresh frame.

Useful controls include a stable configuration, multiple APs sharing the same
test name, different signal conditions, and unavailable fields. Unknown
telemetry should stay unknown. An empty scan or parser error should be reported
as that outcome rather than replaced with demo data.

## Compare a deliberate configuration change

Save a baseline only when you intend to retain those observations:

```sh
wifi-scout scan --interface wlan0 --save-baseline ./test-visit.json --json > live-before-change.json
```

Change a setting on the dedicated test AP using its normal administration
controls, record exactly what changed, and collect a comparison:

```sh
wifi-scout scan --interface wlan0 --baseline ./test-visit.json --json > live-after-change.json
wifi-scout history delete --path ./test-visit.json
```

Use the same collection backend for the baseline and comparison. A supported
configuration change should be described as a change, with reconfiguration as
a possible explanation. It should not establish that an attacker is present.
If the changed field was not observable, record that limitation instead of
expecting a finding from missing evidence.

## Passive management-frame observations

Use a separate, compatible adapter whose monitor interface already exists.
Prepare its channel and capture permissions through the operating system's
normal controls before running WiFi Scout. Changing an active adapter's mode
can disconnect it; WiFi Scout does not perform that setup or stop
NetworkManager.

```sh
wifi-scout scan --advanced --interface wlan1mon --duration 15 --acknowledge-monitor --json > live-management-01.json
```

This observes the interface's current channel. Compare available RSN, protected
management-frame, radio, and timing fields with the known AP configuration.
Missing driver or decoder fields remain unknown. Record tool errors and
permission failures as test results; running a dashboard as root is not the
remedy.

Observe ordinary operation over multiple consented runs before judging whether
activity warnings are useful. Maintenance and normal disconnections can produce
management traffic too. Record those known events alongside the observations.
The software lab's generated disconnect bursts are decoded from files; they are
not transmitted over the air. WiFi Scout has no attack-injection mode.

## What a kernel virtual-radio lab would require

Linux `mac80211_hwsim` creates virtual wireless radios. Tools such as `hostapd`
and `wpa_supplicant` can exercise AP/client software behavior; `wmediumd` can
model aspects of the wireless medium. This is a separate environment setup,
requiring a suitable kernel, the relevant tools, and appropriate administrative
permissions. It should run in a dedicated disposable machine or VM, isolated
from a user's real networking setup.

WiFi Scout does not provision this environment, load its modules, or claim that
its replay lab runs these tools. `doctor` reports relevant readiness indicators
so missing prerequisites remain visible. Virtual radios could help test Linux
discovery and controlled software conditions, but would still leave physical
driver, firmware, and RF behavior unvalidated.

## Record enough evidence to reproduce a result

For each run, keep a small local record alongside the JSON output:

| Field | Record |
| --- | --- |
| Evidence level | Synthetic replay, kernel virtual radio, or physical hardware |
| Software | WiFi Scout version, OS, kernel, NetworkManager/nmcli version, TShark version if used |
| Client hardware | Adapter model, hardware revision if known, driver, firmware version if available |
| Access point | Model, firmware, security settings, channel/band, and any deliberate change |
| Collection | Command, backend, mode, duration, interface type, and timestamps |
| Conditions | Approximate distance/location, known obstructions, number of observed APs, and known maintenance events |
| Expected versus observed | Field-by-field comparison, findings, missing data, errors, and repetitions |
| Limits | Uncontrolled conditions, suspected loss, unsupported fields, and anything not tested |

Do not label a run as a successful attack detector merely because a warning
appeared. Record whether the known behavior was visible, whether the warning
had a benign explanation, and whether an expected observation was missed.
Identical visible properties cannot establish whether an operator is genuine.

Exports can contain nearby AP names, addresses, and timestamps that reveal
locations. Keep them local by default. Before sharing a bug report, prefer a
synthetic reproduction or minimize and anonymize the necessary AP evidence
while retaining the relationships needed to reproduce the issue. Source packet
captures may contain additional information even though WiFi Scout exports only
selected fields. Deleting a baseline does not delete separately exported files
or backups.
