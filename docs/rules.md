# Deterministic rules

WiFi Scout describes observations in three separate dimensions. It does not
calculate a universal safety score, authenticate an access point, or establish
operator trust. A finding's confidence describes the interpretation of the
recorded evidence, **not** the trustworthiness of an advertised identity.

`None`/JSON `null` means unavailable. Unknown fields never become an open network,
a disabled feature, or an attack finding. Values are compared only when both
observations provide that field. Strings used as network identifiers are exact
and case-sensitive; Unicode is not silently normalized.

## Dimensions

1. **Wireless security configuration:** recognized advertised protocols, from
   legacy WEP/original WPA to open, OWE, WPA2, WPA2/WPA3 transition, and WPA3.
   OWE is Enhanced Open: encrypted radio communication without operator
   authentication. Explicitly advertised obsolete TKIP or WEP pairwise ciphers
   are classified as legacy even with WPA2/WPA3 or modern ciphers also present.
   Advertisements do not prove what a client will negotiate. Missing cipher
   telemetry stays unknown and does not create a legacy finding.
2. **Expected connection quality:** a broad signal tier. NetworkManager signal
   percentages use `70–100` strong, `40–69` moderate, and `0–39` weak. Physical
   dBm readings use at least `-60` strong, `-75` through less than `-60` moderate,
   and below `-75` weak. If neither supported reading is present, quality is
   unknown. Percentages and dBm are never converted into one another. These are
   documented heuristic reception tiers, not a throughput prediction. If both
   are available, the percentage is used consistently.
   TShark uses the median of available signal samples for the same advertised
   configuration, with sample count and observed range retained. It does not
   manufacture signal measurements when radio metadata is missing.
3. **Confidence in network identity:** always unconfirmed. Exact venue-name
   matching and continuity with a saved visit are weak identity clues only.
   Names, BSSIDs, and advertised capabilities can be spoofed. Signal strength,
   hidden names, vendor differences, and missing vendor fields cannot establish
   identity or maliciousness.

## Findings

Every finding contains stable `id`, `severity`, `confidence`, `title`,
`explanation`, and structured `evidence` fields. Severity is `info`, `medium`,
or `high`; confidence is `low`, `medium`, or `high`. Neither is a probability.

| ID | Severity / confidence | Trigger and interpretation |
| --- | --- | --- |
| `SECURITY_UNKNOWN` | info / low | Protocol list is missing, empty, or contains unrecognized protocols. No security failure is inferred. |
| `SECURITY_LEGACY` | high / high | WEP or original WPA is advertised, including alongside modern protocols. Original WPA's `WPA1` spelling is normalized to `WPA`. |
| `SECURITY_LEGACY_CIPHER` | high / high | An explicitly observed pairwise cipher is TKIP, WEP, WEP-40, or WEP-104 (including spellings WEP40/WEP104). Applies even to WPA2/WPA3 advertisements and mixed legacy/modern cipher sets: actual client negotiation is unknown. Missing cipher telemetry is not a failure. |
| `SECURITY_OPEN` | medium / high | `OPEN` is explicitly observed. No radio-link encryption is advertised; correctly validated HTTPS contents remain protected. A captive portal does not add wireless-link encryption. |
| `SECURITY_OWE` | info / high | OWE is explicitly advertised. Radio-link encryption is distinct from operator authentication. |
| `SECURITY_MODERN` | info / high | WPA2 or WPA3 is advertised without an explicitly observed obsolete pairwise cipher. This does not establish operator trust or imply missing cipher details were checked. |
| `PMF_REQUIRED` | info / high | The observed RSN protected-management-frame required bit is true. It does not protect every management frame or authenticate the operator. Missing PMF data creates no negative finding. |
| `SECURITY_CONFLICT` | medium / medium | Two observations with the same nonempty SSID disagree on jointly known protocol sets, authentication sets, pairwise cipher sets, PMF capability, or PMF requirement. Configuration drift, staged upgrades, unrelated operators, or impersonation can explain this. Unknown fields do not disagree with known fields. |
| `MULTIPLE_ACCESS_POINTS` | info / high | The same nonempty SSID has multiple BSSIDs and this observation has no known security conflict with its peers. Multiple APs are normal in enterprise and mesh deployments. Unknown fields remain unknown. |
| `VENUE_NAME_MATCH` | info / low | An SSID exactly matches the venue name the user entered. A name match neither grants permission to connect nor authenticates the AP. |
| `BASELINE_SECURITY_CHANGED` | medium / medium | The same BSSID differs from the saved visit on jointly known security fields, or a new BSSID of a familiar SSID conflicts with **every** saved same-name AP on jointly known security fields. A compatible or unknown prior configuration prevents the latter finding. Updates, replacement equipment, reconfiguration, or an incomplete prior scan are competing explanations. |
| `BASELINE_NAME_CHANGED` | medium / medium | The same BSSID has a different nonempty advertised SSID than before. Renaming is a competing explanation. |
| `BASELINE_MATCH` | info / low | BSSID and name match the baseline, both observations have recognized security protocols, and no jointly known security fields conflict. Only observable continuity is established. |
| `BASELINE_NEW_AP` | info / low | The SSID appeared in the saved scan but this BSSID did not. Mesh expansion or incomplete prior coverage commonly explains it. It does not block a recommendation by itself. |
| `DEAUTH_ACTIVITY` | medium / medium | A TShark-backed observation records at least **20 frames**, at least **2 deauthentication frames/second**, and a known capture interval of at least **10 seconds**. All three conditions must hold. This is a documented heuristic, not an attack detector. Roaming, troubleshooting, radio faults, retransmissions, or malicious activity may explain the count. Frame addresses can be spoofed. |
| `DEAUTH_BURST` | medium / medium | When the whole-capture rule does not fire, a capture lasting at least **30 seconds** has at least **20 distinct non-retry observations in a ten-second window**. Three window lengths must be available before applying this supplementary long-capture check; shorter captures retain the original whole-capture boundary. Timestamp/sequence/fragment evidence and at least ten seconds of same-BSSID observations are required by the adapter. This is an uncalibrated heuristic, not proof of an attack. |
| `SIGNAL_VARIABLE` | info / medium | At least **five** valid signal samples span at least **20 dB**. Signal strength is summarized by its median. Movement, interference, and antenna differences are competing explanations. This finding does not establish maliciousness and does not itself exclude an otherwise eligible candidate. |

Deauthentication counts concern only frames the adapter could observe during its
capture. A low count, a short capture, a fixed monitored channel, or missing
capture data does not establish the absence of attackers. Counts do not identify
the sender's real-world identity or establish intent.

Repeated capture records are removed when the timestamp, sequence, fragment,
and advertised BSSID identify the same event. Advertisement deduplication also
requires matching selected content so contradictions are preserved. Retry-marked
deauthentication frames remain excluded. Without the needed metadata, reliable
deduplication is unavailable and that limitation is reported. A ten-second peak
uses a half-open interval `(end - 10 seconds, end]`. Missing event timestamps
make imported per-AP duration and peak evidence unknown; a known live capture
timer may still support the aggregate count.

These thresholds have **not** been calibrated against field traffic. The stress
lab demonstrates that modeled packet loss can suppress warnings and that benign
maintenance can be observationally identical to hostile disconnect activity.
No detection-accuracy or real-world false-positive rate is claimed.

## Recommendation algorithm

The caller passes `authorized_ssids`, meaning network names the user says they
have both permission and any required credentials to join. A matching venue name
alone does not set authorization. If a venue name is entered, it additionally
filters this allowlist by exact equality.

1. Start with observed APs matching the user's explicit joining permissions and
   the venue-name filter, if present. Nearby private networks outside this set
   are never candidates, even if their advertisements look better.
2. Require a known name and BSSID, recognized usable security configuration, and
   at least a moderate signal tier. Exclude observations with legacy protection
   (including explicitly advertised obsolete pairwise ciphers),
   a same-name security conflict, a changed baseline name/security configuration,
   or elevated deauthentication observations.
3. Order eligible candidates lexicographically by advertised configuration:
   WPA3-only, then WPA2 (including WPA2/WPA3 transition), then OWE-only, then
   explicitly open. This is a conservative configuration preference, not a claim
   about operator trust or actual protocol negotiation. Within a configuration
   tier, prefer stronger broad signal tiers. Equivalent candidates use the
   name and lowercase BSSID for stable ordering; these tie-breakers confer no
   trust. Raw signal differences within a tier do not decide a winner.
4. Emit **Best observed candidate** with the selected SSID/BSSID, reasons,
   competing explanations, warnings, and unavailable information. An open-only
   authorized option may be selected, with its encryption and HTTPS caveats
   clearly stated. A single suitable AP is labeled a limited comparison.
5. Otherwise emit **Cannot confidently recommend**, explain what is missing or
   unresolved, and suggest confirming expected venue settings or using a
   trusted alternative such as a personal hotspot.

Radio observations cannot establish internet speed, a working login/captive
portal, client isolation, device compatibility, trustworthy DNS, or the absence
of attackers. The recommendation never attempts to connect. Merely displaying
an AP does not mean the user has permission to join it.

## Baselines and demonstration data

Baselines are provided explicitly by the application. The engine ignores a
baseline from a different backend or live/demo mode to avoid comparing
incompatible observations, and explains that limitation. Only jointly known
fields are compared. Unknown earlier details are not an observed change. For a
new BSSID using a familiar name, the engine checks all saved same-name APs: a
security-change finding requires a known conflict with every one. One compatible
or insufficiently observed prior configuration makes that conclusion unavailable.

The bundled demo has a fixed historical observation time and `mode: demo`.
Individual examples identify the backend they illustrate. Elevated
deauthentication examples illustrate a TShark capture, while NetworkManager
examples leave unsupported RSN/PMF details unknown. The demo includes ordinary
multi-AP venue Wi-Fi, inconsistent advertisements, missing fields, legacy and
Enhanced Open configurations, a private network outside the venue, a hidden
name, and a deliberately hostile HTML/control-character name.

Changes to rules must update this document and add a test asserting the
observable behavior and an alternative or insufficient-evidence case. No
fixture establishes real hardware support.
