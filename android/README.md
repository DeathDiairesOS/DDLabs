# WiFi Scout for Android

A native, local Android app for comparing nearby Wi-Fi before choosing whether
to join. Android 10 or newer is required. No desktop server, Python installation,
account, cloud backend, or Wi-Fi password storage is needed on the phone.

## Phone workflow

1. Tap **Scan nearby Wi-Fi**. Android requests location permission when needed;
   Wi-Fi and the system Location setting must be enabled.
2. Read grouped network cards with plain-language protection, signal and identity
   information. Important concerns remain visible.
3. Mark the network names you have permission and any required credentials to use.
4. Read the **Best observed candidate**, if there is enough fresh evidence.
   Expand technical details when you want the underlying observations.
5. Use **Open Wi-Fi settings** to choose the network through Android. WiFi Scout
   does not connect automatically or request your password.

**Try demo** uses invented observations without requesting scan permissions.
Demo networks cannot initiate a connection. A rejected or empty live scan never
silently becomes demo data.

## Share a report with the iPhone companion

After a live scan or an explicit demo, tap **Share report**. Read the disclosure,
then choose **Choose where to share** to open Android's share chooser. Select a
destination yourself; WiFi Scout does not send the report automatically. A
shared file is JSON in the `wifi-scout-phone-report` version 1 format.

Reports contain Wi-Fi names, access-point addresses, observed settings, timing
information and the network names you said you could use. They contain no
passwords, but real observations can reveal places you have visited. Demo
exports are labeled as fictional. Consider this information before choosing a
recipient or another app to handle the file.

On an iPhone, open the [companion](../iphone/README.md) in Safari and choose
**Open a report** to select the saved JSON file. It shows the original suggestion
as **Suggested in this report**, along with concerns and expandable evidence.
This is a view of earlier observations; it does not turn into a current iPhone
scan or verify the operator. Confirm the expected network with the venue, then
choose it yourself in **Settings → Wi-Fi**.

An explicit export creates a file in WiFi Scout's private Android cache. At most
five exported JSON files are retained; a new export removes older copies as
needed. Android may evict these cache files. The selected share destination gets
a temporary read-only content URI grant, not general access to the app's files.
The provider rejects writes and paths outside its private report directory.
Clear the app's cache through Android Settings to remove its local export copies.
That does not delete copies already saved by a recipient or share destination.

## What the Android app can observe

The app uses Android's `WifiManager` scan APIs. It reads advertised names,
access-point identifiers, security capability strings, signal readings, frequency,
and observation age. It can identify known obsolete protection, explicit open
links, inconsistent known protection under one name, and missing evidence.
Multiple access points with matching settings are normal and are not an attack.
The capability parser supports documented common personal and enterprise forms;
newer or unfamiliar authentication flags remain unknown and ineligible instead
of being guessed as open or modern protection.

The comparison requires explicit joining permission, recognized security,
usable signal and observations no older than 30 seconds. That age is a freshness
policy, not an attack threshold. Unknown timestamps, rejected scans, cached-only
results and stale observations cannot support a fresh recommendation.

Normal Android scan APIs do not expose the desktop TShark management-frame
capture. This first Android version does not claim deauthentication detection,
protected-management-frame inspection, real-world attack attribution, internet
speed measurement, or verification of an operator. Advertised protection is not
a universal trust score. Open Wi-Fi does not defeat correctly validated HTTPS.

## Android permissions and limits

Android's `startScan()` and `getScanResults()` still require precise location
permission, including on Android 13 and later. Nearby-device permission alone
does not replace that requirement. Location services must also be enabled.
WiFi Scout does not request GPS coordinates, background location or the INTERNET
permission. Observations and joining selections stay in process memory by
default; there is no automatic visit history or telemetry. The exception is an
explicit **Share report** action, which writes up to five exported JSON files in
the private cache as described above. Android's own system services and the
share destination you choose operate under their own permissions.

Foreground scan requests can be throttled to four per two minutes. A successful
scan broadcast can still contain older per-access-point observations, so the app
checks their monotonic timestamps too. OEM behavior, radio reception and scan
coverage vary. Closing or backgrounding the app stops its pending scan listener.

Official references:

- [Android Wi-Fi scanning](https://developer.android.com/develop/connectivity/wifi/wifi-scan)
- [Android Wi-Fi permission requirements](https://developer.android.com/develop/connectivity/wifi/wifi-permissions)
- [Android ScanResult fields](https://developer.android.com/reference/android/net/wifi/ScanResult)

## Build and test

Open this `android/` directory in Android Studio, or use JDK 17 or newer,
Android SDK platform 35, build tools 35.0.0 and the checked-in Gradle wrapper:

```sh
./gradlew testDebugUnitTest lintDebug assembleDebug
```

The installable development build is
`app/build/outputs/apk/debug/app-debug.apk`. It uses a local debug signing key;
it is not a Play Store release. Keep signing keys out of source control.

For a connected Android test device with USB debugging enabled:

```sh
adb install -r app/build/outputs/apk/debug/app-debug.apk
```

Pure Java tests cover rule, parsing and report-export boundaries. Compiling an APK and passing
these tests does not establish radio or driver behavior. Test permission denial,
approximate-only permission, disabled Location/Wi-Fi, rejected and delayed scans,
stale results, rotation, backgrounding, font scaling and settings handoff on a
physical device before relying on live results.

## iPhone

This directory builds the native Android scanner. The separate
[iPhone companion](../iphone/README.md) is a Safari-compatible imported-report
viewer, with optional Home Screen use. Serve its assets from HTTPS, open it once
in Safari, and use **Share → Add to Home Screen** for its offline app shell.
The repository does not publish that site automatically. Imported report data
stays in page memory; it is not uploaded or included in the offline cache.

Apple does not expose a general-purpose nearby Wi-Fi scanning API to ordinary
iPhone apps. The companion therefore does not perform native nearby-network
scanning, capture management frames, or join a network. It is not an App Store
build. A phone-sized webpage cannot add access to the missing scan API. See
[Apple's Wi-Fi API overview](https://developer.apple.com/documentation/technotes/tn3111-ios-wifi-api-overview).

## Open source and custom code

Android/OpenJDK, Gradle and the Android Gradle plugin build the native Java app.
JUnit is used for development tests. The UI, platform adapter, capability parser
and conservative comparison rules, JSON report exporter, and private read-only
sharing provider are custom project code. The app has no
third-party runtime library dependency. The Python desktop tool remains useful
for capture-file analysis and its broader offline laboratories.
