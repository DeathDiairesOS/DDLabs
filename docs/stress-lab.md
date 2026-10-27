# Difficult-observation simulation lab

Run `wifi-scout stress-lab --output stress-results --seed 7` with TShark installed.
This generates 13 PCAP files, decodes them using the actual executable, and runs
the production rules. `index.html` is a standalone report; `results.json` holds
the checks, input hashes, seed, and full observations. No frames are transmitted.

For optional browser verification, install Playwright and Chromium, then run
`python tests/stress_browser_smoke.py stress-results --screenshots` from the
checkout. This checks filters against the recorded totals, keyboard expansion,
mobile layout, and the absence of external requests.

Use `wifi-scout doctor --json` to inspect prerequisites without scanning or
changing interfaces. Missing native TShark leaves stress scenarios explicitly
skipped; there is no fabricated fallback. Exit codes are 0 for all checks
passing, 1 for an unexpected result, and 2 for an incomplete/skipped run.

## What the simulation covers

| Input condition | What is exercised | What is not established |
| --- | --- | --- |
| Steady observations | Native decoding and ordinary configuration interpretation | Operator trust |
| 80 APs across shared names and channels | Parser/rule handling of many advertised networks | Physical congestion, channel contention, speed, or scanning coverage |
| Changing signal readings | Median, observed range, sample count, and informational variation finding | Actual propagation, device calibration, or future connection quality |
| A strong final outlier | The last beacon no longer overrides a mostly weak signal history | Whether weak reception will persist |
| Sustained disconnect observations | Existing whole-capture volume rule | Attack intent |
| A short burst in 120 seconds | Supplementary ten-second window rule | Field-calibrated thresholds |
| Duplicate capture records | Identifiable repeats are counted once | Perfect uniqueness when metadata is missing |
| Seeded loss of events | Explicitly demonstrates loss-induced missing evidence | Actual packet-loss probability or RF interference |
| Missing radio metadata | Unknown signal stays unknown; no reception-based suggestion | Driver compatibility |
| Truncated security fields | Missing security is not invented as OPEN | Capture completeness |
| Five-second capture | Documented minimum interval prevents unsupported conclusions | Absence of activity or attackers |
| Benign maintenance / hypothetical hostile burst | Byte-identical observations produce identical activity warnings | Attribution of the cause |

The final two cases are deliberately identical. Calling both warnings attacks
would falsely accuse the benign case. WiFi Scout labels observed activity and
states the alternative explanations. These scenarios do not provide a measured
attack-detection rate or real-world false-positive rate.

With seed 7, modeled loss retains 15 of 40 events. Those remaining observations
do not trigger the activity rule. The passing test records that limitation; it
does not count it as a successful detection. Other seeds preserve their actual
generated counts in the result metadata.

## Improvements checked against the prior implementation

The development run replayed the exact same capture files through saved copies
of the earlier parser/rules and the updated ones:

| Case | Before | After |
| --- | --- | --- |
| Five events stored twelve times each | 60 counted events; activity warning | 5 distinct events; duplicate-driven warning removed |
| 40-event burst within a 120-second capture | Whole-capture average hid the burst | Ten-second peak produces a burst finding; candidate withheld |
| Mostly −80 dBm with a final −35 dBm sample | Final strong sample caused a suggestion | Median remains −80 dBm; weak candidate withheld and variation explained |

The delivered development evidence includes `before-after.json` and the saved
source copies/hashes. A normal fresh stress-lab run tests the current code only;
it does not silently reconstruct or claim to execute an old implementation.

See [rules.md](rules.md) for exact thresholds and [tool-fields.md](tool-fields.md)
for optional metadata requirements. Signal variability is informational, not an
attack warning. The new burst finding only applies to captures lasting at least
30 seconds; shorter captures retain the existing aggregate rule.

## Remaining validation work

Software-generated records cannot validate live radios, driver behavior,
channel-hopping losses, real crowded venues, or useful warning thresholds in
practice. The current environment has neither a visible wireless device nor a
prepared kernel virtual-radio lab. `mac80211_hwsim` and `wmediumd` were not used
for these results. See [hardware-validation.md](hardware-validation.md) for a
separate, owned-equipment validation workflow.
