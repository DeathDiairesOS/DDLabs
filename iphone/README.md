# WiFi Scout iPhone companion

This is a phone-first, offline-capable **report viewer**, not a native iOS Wi-Fi
scanner. It opens JSON reports shared from the Android app or the desktop tool,
shows plain-language concerns, and keeps technical observations expandable.

The file's original suggestion is labeled **Suggested in this report**. Imported
observations never become a current iPhone scan or proof of operator identity.
The reported source, export time, observation age and demo status remain visible. No network is
selected or joined automatically.

## Use it

1. Open the companion in Safari.
2. Choose **Open a report**, paste JSON, or try the clearly labeled fictional example.
3. Read the concerns and expand technical details if useful.
4. Confirm the network's name and sign-in details with the venue.
5. Open iPhone **Settings → Wi-Fi** and choose the confirmed name yourself.

Android can share a report explicitly; desktop JSON is produced with commands
such as `wifi-scout scan --json`. A report can include nearby network names,
addresses and times. Only share it with someone you intend to receive that data.

Files are limited to 1 MiB and 1,000 access-point observations. Supported inputs
are `wifi-scout-phone-report` version 1 from Android, and the current WiFi Scout
desktop `{scan, assessments, recommendation, limitations}` format. Unsupported
or malformed reports show an error and remove any previous displayed suggestion.

## Local preview and Home Screen use

From the repository:

```sh
python -m http.server 8000 --bind 127.0.0.1 --directory iphone
```

Open `http://127.0.0.1:8000` on the development machine. To use this as an offline
Home Screen companion on a physical iPhone, serve this directory from an HTTPS
origin, visit it in Safari once online, then choose **Share → Add to Home Screen**.
The repository does not publish or host that origin automatically. A phone cannot
reach another machine's localhost address. Opening downloaded HTML files does
not install the service worker or an offline Home Screen app.

No build step or third-party JavaScript library is required. The companion itself
has no account system; a hosting provider may require sign-in to open its link. All fonts,
scripts, styles and icons are local. The service worker caches only the explicit
app-shell asset list. Imported reports, pasted text, file names and results are
never uploaded, written to browser storage or added to the cache. They remain in
page memory until cleared or the page closes. **Clear report** removes the shown
observations and pasted input. Hosting access logs, if the directory is served,
are the hosting provider's responsibility; no report data is sent to that host.

Copying a Wi-Fi name uses the browser clipboard only after an explicit tap and
may require HTTPS and browser permission. Joining instructions remain available
when clipboard access is unavailable. The companion has no iOS private-API link
or automatic Wi-Fi settings handoff.

## Platform limit and validation

Apple does not expose a general-purpose nearby Wi-Fi scanning API to ordinary
iOS apps. The companion does not bypass that restriction or suggest that a
responsive webpage has radio access. See [Apple's Wi-Fi API overview](https://developer.apple.com/documentation/technotes/tn3111-ios-wifi-api-overview).

Browser checks can verify report parsing, input safety, layout, disclosure controls
and offline shell behavior. They do not establish physical iPhone, Safari,
Home Screen installation, radio reception, or network-operator trust. Record any
device-specific validation separately.

The Android app is the first native scanning application. This directory is the
complementary iPhone-compatible web workflow; it is not an App Store build.
