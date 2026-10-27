# Airport Wi-Fi product demo

> Not sure which Wi-Fi to use at the airport? Run WiFi Scout, compare the warnings,
> and open the details before you decide. Confirm the network with staff before joining.

[Watch the full MP4](wifi-scout-demo.mp4) or open [the local player](index.html).
The video is silent and has on-screen explanations. The optional
[WebVTT captions](captions.vtt) contain the same walkthrough in text.

## What it shows

1. Open the local WiFi Scout dashboard.
2. Enter **Airport Guest**, confirm permission and any needed credentials, and scan.
3. See **Cannot confidently recommend** because two access points with that name
   advertise different protection settings.
4. Expand the technical evidence and compare the WPA2 and OPEN observations.
5. In the illustrative airport café scenario, ask staff for another option.
   Enter **Juniper Café**, confirm access, and scan again.
6. Read the **Best observed candidate** recommendation, its reasons and its limits.
7. Decide whether to connect using the device's own Wi-Fi controls.

These are the project's unchanged bundled fictional observations, rendered by
the actual dashboard and evaluated through its real local API. The café location
and conversation with staff are narrative context. No real airport, staff,
network, radio scan, or successful connection is claimed. A recommendation does
not authenticate the network operator.

## Files

| File | Purpose |
| --- | --- |
| `wifi-scout-demo.mp4` | Full 1080p H.264 walkthrough, silent with visible explanations |
| `wifi-scout-preview.gif` | Lightweight six-frame animated preview for the GitHub README |
| `poster.png` | Static preview showing the actual dashboard |
| `index.html` | Local video player with keyboard controls and optional captions |
| `captions.vtt` | Text captions for the walkthrough |
| `timeline.json` | Exact scene timing and export metadata |
| `capture/dashboard-demo.webm` | Unedited browser recording |
| `capture/capture.json` | Capture timings and assertions about the actual outcomes |
| `capture/*-report.json` | Actual API outputs shown in the video |

The edit adds title/end cards, explanatory panels, a persistent fictional-demo
label, and reading pauses. The airport evidence is enlarged for readability.
It does not replace dashboard warnings or change recommendation outcomes.
Media composition uses Chromium and FFmpeg. The Python application gains no
new runtime dependency. No stock footage, music, or generated voice is included.

## Reproduce the capture and edit

From the repository, with the project installed, install the optional development
tools Playwright, Chromium, FFmpeg and FFprobe. On Debian/Ubuntu the system
packages are `chromium` and `ffmpeg`. Then run:

```sh
python -m pip install playwright
python -m playwright install ffmpeg
python tools/capture_demo.py
python tools/render_demo.py
```

Both scripts accept `--chromium /path/to/chromium`. The capture script accepts
`--output`, and the renderer accepts `--capture` and `--output`. Generated
render intermediates and the recorder's temporary duplicate files are ignored
by Git. No Wi-Fi hardware is needed; no live scan runs.

The capture checks both recommendation outcomes, the permission reset when a
name changes, expandable evidence, browser errors, and loopback-only requests.
`timeline.json` records the final duration; encoder timing can vary by a frame.

To view the player with caption-track loading supported consistently:

```sh
python -m http.server 8000 --bind 127.0.0.1 --directory docs/demo
```

Then open `http://127.0.0.1:8000`. GitHub renders the animated README preview;
its link opens the MP4. The player HTML is a local artifact and is not a
published website. All media and source are included under the repository's
MIT license.
