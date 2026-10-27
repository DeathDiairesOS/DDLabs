# Tool fields and collection boundaries

These mappings were checked against the official NetworkManager and Wireshark
documentation and the NetworkManager source listed below. NetworkManager
discovery has been tested with synthetic output and mocked process failures.
TShark **4.4.19** has also been run against the generated, bundled management-frame
PCAP; that is a real decoder test using invented frames, **not wireless hardware
validation**. No Wi-Fi interface was available in the development environment.

## NetworkManager / nmcli

WiFi Scout invokes a structured argument list equivalent to:

```sh
nmcli --terse --escape yes --colors no --wait 20 \
  --fields SSID-HEX,BSSID,SIGNAL,CHAN,FREQ,SECURITY,WPA-FLAGS,RSN-FLAGS \
  device wifi list --rescan yes
```

An optional interface adds `ifname INTERFACE`. SSIDs are never command arguments.
The subprocess receives `LC_ALL=C` and `LANG=C`. `--rescan yes` requests fresh OS
discovery, but NetworkManager can retain older access-point entries. The recorded
time is retrieval time, **not an exact per-AP receive timestamp**. WiFi Scout does
not mistake `nmcli --offline` for offline discovery: that flag concerns offline
connection-profile operations. Runtime scanning needs no internet access.

| Field | Interpretation |
| --- | --- |
| `SSID-HEX` | Bytes of the advertised SSID, decoded strictly as UTF-8. Hex avoids embedded newline, colon, or backslash corrupting row framing. Empty/all-NUL or non-UTF-8 names become unknown and cannot match an authorized name. |
| `BSSID` | Access point's advertised hardware address, normalized to lowercase; can be spoofed. |
| `SIGNAL` | NetworkManager's relative signal quality, 0–100 percent. It is not RSSI in dBm, throughput, or a security percentage. |
| `CHAN`, `FREQ` | Radio channel and frequency in MHz. Band derives from frequency; it is not inferred from a potentially ambiguous channel number. |
| `SECURITY` | NetworkManager's interpreted security advertisement. `WPA1` maps to WPA, `WPA2`/`WPA3`/`WEP` remain distinct. Empty or `--` is nmcli's explicit open-network representation. Unrecognized output is unknown. |
| `WPA-FLAGS`, `RSN-FLAGS` | Explicit `psk`, `802.1X`, `sae`, `owe` authentication and `pair_*` cipher flags; missing flags do not imply an insecure configuration. |

OWE is Enhanced Open. `OWE-TM` indicates OWE transition mode and is conservatively
represented with both OPEN and OWE, because an advertisement does not establish
that a client will use the encrypted association. WPA-EAP-SUITE-B-192 is mapped to
WPA3 enterprise authentication. PMF and deauthentication counts remain unknown in
ordinary discovery; nmcli does not provide those fields through this interface.

The terse parser implements nmcli's documented backslash escaping of `:` and
`\`, validates the complete eight-field layout, and rejects malformed output
instead of quietly making recommendations from shifted columns. It does not
evaluate shell escapes or interpolate any collected value into a command.

Official references:

- [nmcli manual: terse output, escaping, fields, Wi-Fi listing and rescanning](https://networkmanager.dev/docs/api/latest/nmcli.html)
- [NetworkManager AccessPoint properties: Strength, Frequency, Ssid, HwAddress, WPA/RSN flags, LastSeen](https://networkmanager.dev/docs/api/latest/gdbus-org.freedesktop.NetworkManager.AccessPoint.html)
- [NetworkManager security flag enum](https://networkmanager.dev/docs/api/latest/nm-dbus-types.html)
- [Official nmcli source: `nmc_fields_dev_wifi_list`, `show_access_point_info`, and `ap_wpa_rsn_flags_to_string`](https://github.com/NetworkManager/NetworkManager/blob/main/src/nmcli/devices.c)

## TShark

Live collection requires Linux and an **existing radiotap monitor interface**
(`/sys/class/net/INTERFACE/type` equals 803). WiFi Scout never enables monitor mode,
changes channels, stops a service, or changes capture permissions. Use a dedicated
adapter so configuring monitor mode outside WiFi Scout does not disrupt your
connection. The CLI requires an explicit acknowledgment of these requirements.

TShark checks its local field registry with `-G fields`. Required 802.11 fields
must exist. Unsupported optional fields are omitted and listed as unknown in the
scan limitations. This handles version differences without treating decoder
absence as an observed security problem.

Live collection uses `-a duration:N` (5–60 seconds), no `-I` and no `-w`, with this
libpcap capture filter:

```text
type mgt subtype beacon or type mgt subtype probe-resp or type mgt subtype deauth
```

Both live and file modes apply a display filter for subtypes 0x0008 (beacon),
0x0005 (probe response), and 0x000c (deauthentication). `-n` disables address-name
resolution. Output uses `-T fields`, `header=y`, tab separators, double quotes,
and all repeated field occurrences; Python's CSV reader handles quoting.

| Fields | Interpretation |
| --- | --- |
| `frame.time_epoch`, `frame.len`, `frame.cap_len` | Receive timestamp and original/captured lengths. Missing or invalid receive timestamps remain unknown; file imports never substitute the current time. Truncation prevents deriving an open configuration from absent information elements. |
| `wlan.fc.type_subtype`, `wlan.bssid`, `wlan.ssid` | Management subtype, AP address, and hex SSID bytes. No client source/destination/transmitter addresses are exported. |
| `radiotap.dbm_antsignal`, `radiotap.channel.freq`, `wlan.ds.current_channel` | Driver-provided radio measurements. Missing radiotap data stays unknown. The first antenna reading per record is used, then the median across available records for the same advertised configuration; sample count and range are retained. No cross-adapter normalization is attempted. |
| `wlan.rsn.version`, `wlan.rsn.akms.type`, `wlan.rsn.akms.oui` | RSN version and advertised authentication suites. Only standard 00:0f:ac selectors are interpreted; unknown selectors or missing OUIs stay unknown. PSK/EAP modes imply WPA2, SAE/FT-SAE and Suite-B-192 modes imply WPA3, selector 18 implies OWE. These are advertisement summaries, not proof of negotiated compliance. |
| `wlan.rsn.pcs.type`, `wlan.rsn.pcs.oui` | Advertised pairwise cipher suites, qualified by their OUI. |
| `wlan.rsn.capabilities.mfpc`, `wlan.rsn.capabilities.mfpr` | Explicit management frame protection capable/required bits. Omitted bits are unknown, not false. |
| `wlan.wfa.ie.wpa.*` | Legacy WPA version, AKM and unicast cipher suites; suite values are qualified by Microsoft's 00:50:f2 OUI. |
| `wlan.fixed.capabilities.privacy`, `wlan.tag.number` | Supplementary privacy/IE evidence. OPEN requires a complete frame, available decoders, explicit clear privacy bit, and no RSN/WPA indication. A set privacy bit alone is insufficient to label WEP. |
| `wlan.fc.retry` | Retry bit used to exclude retransmitted deauthentication observations. Missing retry metadata keeps the count unknown. |
| `wlan.seq`, `wlan.frag` | Sequence and fragment values, qualified by BSSID and timestamp, help remove repeated capture records without exporting client addresses. They are also required for the distinct-event ten-second peak. These field names were checked against the native TShark 4.4.19 registry. |

Rows are aggregated by BSSID, SSID, and advertised security properties, including
ciphers and both PMF flags, so changing advertisements are not overwritten.
Duplicate advertisement headers alone do not erase different security evidence.
When records arrive out of order, the latest valid observation timestamp is
preserved. Signal sample statistics describe only frames that were captured.
Deauthentication counts are associated with the advertised BSSID, not attributed
to an authenticated sender. No client identifiers or reason-to-client mappings
are retained. Even counted frames can be spoofed, and benign disconnects are
possible. The documented rule engine determines when volume merits a finding.

Live durations are the requested capture interval. File-import durations are the
span between selected management-frame timestamps. File completeness, packet
loss, gaps, channel history, and provenance are unknown, and may distort rates.
Imports are limited to 32 MiB and have a subprocess timeout. Input PCAPs already
exist; WiFi Scout does not create or delete their potentially sensitive contents.

TShark and the OS necessarily process received frames in memory. WiFi Scout's
capture filter excludes application-data frames, the selected output omits nearby
client addresses, and WiFi Scout does not request a saved PCAP. Its optional
baseline retains only the normalized AP observations.

Official references:

- [TShark manual: `-G fields`, `-n`, `-f`, `-Y`, `-a`, `-T fields`, and `-E`](https://www.wireshark.org/docs/man-pages/tshark.html)
- [Wireshark IEEE 802.11 display-filter reference](https://www.wireshark.org/docs/dfref/w/wlan.html)
- [Wireshark radiotap display-filter reference](https://www.wireshark.org/docs/dfref/r/radiotap.html)
- [Linux interface-type constants: ARPHRD_IEEE80211_RADIOTAP](https://github.com/torvalds/linux/blob/master/include/uapi/linux/if_arp.h)

## Reproduce the decoder check

The synthetic PCAP contains one invented locally administered AP address,
broadcast recipients, an SSID with terminal/HTML control text, WPA2/WPA3 and PMF
variants, an open advertisement, and 30 deauthentication frames. No real network
or nearby client data was collected. Rebuild it deterministically:

```sh
python tests/fixtures/generate_capture.py
python -m unittest discover -s tests -p test_adapters.py -v
```

When `tshark` is on PATH, the suite runs the actual binary against that PCAP and
checks normalized output. Without it, that one integration test is explicitly
skipped; all parser/process tests still run. Tested here with TShark 4.4.19 on
Linux; this does not establish support for all releases or any live hardware.
