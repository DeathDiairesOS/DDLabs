"""Make the captioned GitHub video from a real Playwright dashboard recording.

Run tools/capture_demo.py first, then python tools/render_demo.py.
Development tools: Playwright, Chromium, FFmpeg (libx264), and FFprobe.
The application itself does not depend on these tools.
"""

from __future__ import annotations

import argparse
import html
import json
from pathlib import Path
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[1]
WIDTH, HEIGHT, FPS = 1920, 1080, 25
INTRO_SECONDS, OUTRO_SECONDS = 5, 6

COPY = {
    "open": ("Start here", "Run WiFi Scout.", "Open the local dashboard."),
    "airport_setup": ("01 / Compare", "Start with the venue’s name.", "Confirm you’re allowed to use it and have any needed credentials. Then scan."),
    "airport_warning": ("02 / Notice", "A familiar name. Conflicting settings.", "WiFi Scout withholds its recommendation."),
    "airport_card": ("02 / Notice", "Understand the concern.", "Same name. Different protection. See the warning straight away."),
    "airport_details": ("03 / Understand", "Open the evidence.", "Compare the advertised settings behind the warning."),
    "cafe_setup": ("04 / Check", "Ask staff for another option.", "Confirm the café’s Wi-Fi name and access details."),
    "cafe_result": ("05 / Decide", "A clearer next step.", "A best observed candidate, with reasons and limits."),
    "cafe_details": ("05 / Decide", "Know why it was suggested.", "Read the reasons. You decide whether to connect."),
    "cafe_technical": ("Go deeper", "Curious about the details?", "Inspect the individual access-point observations."),
}

WIFI = '<svg width="46" height="46" viewBox="0 0 32 32" fill="none"><path d="M5 12.3a17.7 17.7 0 0 1 22 0M9 17.3a11.4 11.4 0 0 1 14 0M13 22.1a5 5 0 0 1 6 0" stroke="currentColor" stroke-width="2.5" stroke-linecap="round"/><circle cx="16" cy="26" r="1.4" fill="currentColor"/></svg>'

CSS = """
*{box-sizing:border-box}html,body{margin:0;width:1920px;height:1080px;overflow:hidden}
body{font-family:Arial,Helvetica,sans-serif;background:#16372e;color:#f7f8ef}
.canvas{position:relative;width:1920px;height:1080px;background:radial-gradient(ellipse at 89% 23%,#355747 0%,#193b30 37%,#16372e 70%)}
.brand{position:absolute;left:64px;top:36px;display:flex;gap:13px;align-items:center;font-size:33px;letter-spacing:-1px}.brand strong{font-weight:700}
.tag{position:absolute;right:64px;top:45px;color:#dce8b4;border:1px solid #71866b;border-radius:30px;padding:12px 21px;font-size:17px;font-weight:bold;letter-spacing:1.1px}
.chrome{position:absolute;left:64px;top:110px;width:1280px;height:40px;border-radius:13px 13px 0 0;background:#e1e7db;color:#697564;text-align:center;font-size:14px;line-height:40px}
.dots{position:absolute;left:17px;top:15px;display:flex;gap:7px}.dots i{width:9px;height:9px;background:#a2ae9b;border-radius:50%}
.screen{position:absolute;left:64px;top:150px;width:1280px;height:800px;background:#f7f8f2;box-shadow:0 24px 65px #071e2755}
.side{position:absolute;left:1400px;right:62px;top:223px}.eyebrow{font-size:19px;letter-spacing:2px;text-transform:uppercase;font-weight:bold;color:#d7e8a9;margin:0 0 28px}
.side h1{font-size:48px;line-height:1.13;letter-spacing:-1.6px;font-weight:600;margin:0 0 30px}
.side p{font-size:26px;line-height:1.47;color:#cfdbd0;margin:0}.side .rule{width:58px;height:4px;background:#cfdf9b;margin:39px 0 25px}
.small{font-size:19px!important;line-height:1.45!important;color:#aebfad!important}
.footer{position:absolute;left:64px;right:64px;bottom:46px;border-top:1px solid #5a725b;padding-top:20px;display:flex;justify-content:space-between;font-size:20px;color:#c4d2c3}
.hero{position:absolute;left:100px;top:220px;max-width:1140px}.hero h1{font-size:110px;font-weight:600;letter-spacing:-5px;line-height:1.03;margin:0 0 35px}.hero .sub{font-size:35px;line-height:1.45;color:#cfdbd0;max-width:1000px}
.hero code{display:inline-block;font-family:monospace;font-size:31px;letter-spacing:-.5px;color:#d7e8a9;background:#0d281f;border:1px solid #60795c;border-radius:12px;padding:24px 31px;margin:7px 0 30px}
.orbit{position:absolute;right:116px;top:265px;width:445px;height:445px;border:1px solid #657d5b;border-radius:50%}.orbit:before{content:'';position:absolute;inset:55px;border:1px solid #657d5b;border-radius:50%}.orbit:after{content:'';position:absolute;inset:110px;border:1px solid #657d5b;border-radius:50%}.plane{position:absolute;left:147px;top:150px;color:#d6e7aa;z-index:2}.airport{position:absolute;right:110px;top:780px;font-size:19px;letter-spacing:3px;color:#adc29d}
.hero.outro{top:205px}.hero.outro h1{font-size:92px}.hero.outro .sub{font-size:28px;max-width:1100px}
.endmark{position:absolute;right:160px;top:355px;color:#d6e7aa;transform:scale(4)}
"""


def document(body: str) -> str:
    return f'<!doctype html><html><meta charset="utf-8"><style>{CSS}</style><body><div class="canvas"><div class="brand">{WIFI}<span>WiFi <strong>Scout</strong></span></div><div class="tag">REAL APP · FICTIONAL DEMO DATA</div>{body}</div></body></html>'


def panel(scene_id: str) -> str:
    label, title, description = COPY[scene_id]
    return document(
        '<div class="chrome"><span class="dots"><i></i><i></i><i></i></span>WiFi Scout / local dashboard</div><div class="screen"></div>'
        f'<div class="side"><div class="eyebrow">{html.escape(label)}</div><h1>{html.escape(title)}</h1><p>{html.escape(description)}</p><div class="rule"></div><p class="small">A useful clue.<br>Not proof of who runs the network.</p></div>'
        '<div class="footer"><span>Understand nearby Wi-Fi before you connect.</span><span>Local · Open source · You stay in control</span></div>'
    )


def card(kind: str) -> str:
    if kind == "intro":
        return document('<div class="hero"><div class="eyebrow">Before you connect</div><h1>Airport Wi-Fi.<br>Which one?</h1><p class="sub">Don’t know which network to use?<br>Start with a little more context.</p></div><div class="orbit"><svg class="plane" width="150" height="150" viewBox="0 0 64 64" fill="currentColor"><path d="M29 7c0-4 6-4 6 0v18l22 14v6L35 38v13l8 6v4l-11-3-11 3v-4l8-6V38L7 45v-6l22-14z"/></svg></div><div class="airport">A MOMENT BEFORE YOU JOIN</div><div class="footer"><span>A real dashboard walkthrough using invented Wi-Fi observations.</span><span>WiFi Scout / Product demo</span></div>')
    return document('<div class="hero outro"><div class="eyebrow">Less guessing. More context.</div><h1>Compare the clues.<br>Then choose.</h1><code>wifi-scout serve --demo</code><p class="sub">Confirm the network with staff.<br>A scan cannot verify its operator.<br>Connect using your device’s Wi-Fi settings.</p></div><div class="endmark">' + WIFI + '</div><div class="footer"><span>Try the demo from the GitHub README.</span><span>Local · Open source · No automatic connections</span></div>')


def run(*args: str) -> None:
    subprocess.run(args, check=True, stdout=subprocess.DEVNULL)


def seconds(path: Path) -> float:
    return float(subprocess.check_output([
        "ffprobe", "-v", "error", "-show_entries", "format=duration", "-of", "default=nw=1:nk=1", str(path)
    ]))


def clock(value: float) -> str:
    millis = round(value * 1000)
    return f"{millis // 3600000:02}:{millis // 60000 % 60:02}:{millis // 1000 % 60:02}.{millis % 1000:03}"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--capture", type=Path, default=ROOT / "docs/demo/capture")
    parser.add_argument("--output", type=Path, default=ROOT / "docs/demo")
    parser.add_argument("--chromium", default=shutil.which("chromium"))
    args = parser.parse_args()
    from playwright.sync_api import sync_playwright

    capture, output = args.capture.resolve(), args.output.resolve()
    work = output / "render"
    work.mkdir(parents=True, exist_ok=True)
    manifest = json.loads((capture / "capture.json").read_text())
    recording = capture / manifest["recording"]
    duration = seconds(recording)
    scenes = manifest["scenes"]
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(executable_path=args.chromium, headless=True, args=["--no-sandbox"])
        page = browser.new_page(viewport={"width": WIDTH, "height": HEIGHT}, device_scale_factor=1)
        for name, markup in [("intro", card("intro")), ("outro", card("outro"))] + [(s["id"], panel(s["id"])) for s in scenes]:
            page.set_content(markup)
            page.screenshot(path=str(work / f"{name}.png"))
        browser.close()

    encoded = []
    timeline = []
    elapsed = 0.0
    encoding = ["-c:v", "libx264", "-preset", "fast", "-crf", "20", "-pix_fmt", "yuv420p", "-r", str(FPS), "-an"]
    for kind, length in (("intro", INTRO_SECONDS),):
        path = work / f"{kind}.mp4"
        run("ffmpeg", "-hide_banner", "-loglevel", "error", "-y", "-loop", "1", "-framerate", str(FPS), "-i", str(work / f"{kind}.png"), "-vf", "setsar=1", "-t", str(length), *encoding, str(path))
        encoded.append(path)
        timeline.append({"id": kind, "start": elapsed, "end": elapsed + length, "caption": "At the airport, and not sure which Wi-Fi to use? Start with WiFi Scout."})
        elapsed += length
    for index, scene in enumerate(scenes):
        start = max(0, scene["start"])
        end = min(scene["end"], duration)
        source_length = max(.04, round((end - start) * FPS) / FPS)
        minimum = 5 if scene["id"] in {"airport_setup", "cafe_setup", "cafe_result"} else 4
        length = max(minimum, source_length)
        hold = max(0, length - source_length)
        path = work / f"scene-{index:02}.mp4"
        focus = "crop=640:600:640:0,scale=-2:800,pad=1280:800:(ow-iw)/2:0:color=0xf7f8f2," if scene["id"] == "airport_details" else ""
        filters = f"[1:v]trim=duration={source_length},setpts=PTS-STARTPTS,fps={FPS},{focus}tpad=stop_mode=clone:stop_duration={hold}[screen];[0:v][screen]overlay=64:150:shortest=1,setsar=1[v]"
        run("ffmpeg", "-hide_banner", "-loglevel", "error", "-y", "-loop", "1", "-framerate", str(FPS), "-i", str(work / f"{scene['id']}.png"), "-ss", str(start), "-i", str(recording), "-filter_complex", filters, "-map", "[v]", "-t", str(length), *encoding, str(path))
        encoded.append(path)
        actual_length = seconds(path)
        assert abs(actual_length - length) <= 1 / FPS + .001, (scene["id"], actual_length, length)
        timeline.append({"id": scene["id"], "start": elapsed, "end": elapsed + actual_length, "caption": COPY[scene["id"]][1] + " " + COPY[scene["id"]][2]})
        elapsed += actual_length
        print(f"Rendered {scene['id']}: {length:.2f}s", flush=True)
    path = work / "outro.mp4"
    run("ffmpeg", "-hide_banner", "-loglevel", "error", "-y", "-loop", "1", "-framerate", str(FPS), "-i", str(work / "outro.png"), "-vf", "setsar=1", "-t", str(OUTRO_SECONDS), *encoding, str(path))
    encoded.append(path)
    timeline.append({"id": "outro", "start": elapsed, "end": elapsed + OUTRO_SECONDS, "caption": "Compare the clues. Confirm the network with staff. A scan cannot verify its operator. You decide whether to connect."})
    concat = work / "concat.txt"
    concat.write_text("\n".join("file '" + str(path).replace("'", "'\\''") + "'" for path in encoded) + "\n")
    final = output / "wifi-scout-demo.mp4"
    run("ffmpeg", "-hide_banner", "-loglevel", "error", "-y", "-f", "concat", "-safe", "0", "-i", str(concat), "-c", "copy", "-movflags", "+faststart", str(final))
    vtt = "WEBVTT\n\n" + "\n\n".join(f"{clock(s['start'])} --> {clock(s['end'])}\n{s['caption']}" for s in timeline) + "\n"
    (output / "captions.vtt").write_text(vtt)
    (output / "timeline.json").write_text(json.dumps({"duration": seconds(final), "width": WIDTH, "height": HEIGHT, "fps": FPS, "audio": False, "scenes": timeline, "source_capture": "capture/capture.json"}, indent=2) + "\n")
    # A lightweight six-frame teaser works in GitHub README rendering. The MP4
    # carries the complete real interactions; this GIF is explicitly a preview.
    teaser_ids = {"intro", "airport_card", "airport_details", "cafe_setup", "cafe_result", "outro"}
    teaser = [s for s in timeline if s["id"] in teaser_ids]
    for index, scene in enumerate(teaser):
        at = scene["start"] + (scene["end"] - scene["start"]) * .7
        run("ffmpeg", "-hide_banner", "-loglevel", "error", "-y", "-ss", str(at), "-i", str(final), "-vf", "scale=960:-1:flags=lanczos,setsar=1", "-frames:v", "1", str(work / f"teaser-{index:02}.png"))
    gif_filter = "split[a][b];[a]palettegen=max_colors=96[p];[b][p]paletteuse=dither=bayer:bayer_scale=3"
    run("ffmpeg", "-hide_banner", "-loglevel", "error", "-y", "-framerate", "5/12", "-i", str(work / "teaser-%02d.png"), "-vf", gif_filter, "-frames:v", str(len(teaser)), "-fps_mode", "vfr", "-final_delay", "240", "-loop", "0", str(output / "wifi-scout-preview.gif"))
    # A useful poster shows the real app with the plain-language warning.
    poster_at = next(s["start"] for s in timeline if s["id"] == "airport_card") + 1
    run("ffmpeg", "-hide_banner", "-loglevel", "error", "-y", "-ss", str(poster_at), "-i", str(final), "-frames:v", "1", str(output / "poster.png"))
    print(f"Created {final} ({seconds(final):.2f}s)", flush=True)


if __name__ == "__main__":
    main()
