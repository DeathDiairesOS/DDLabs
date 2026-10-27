package org.wifiscout.app;

import android.Manifest;
import android.app.Activity;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.pm.PackageManager;
import android.location.LocationManager;
import android.net.wifi.ScanResult;
import android.net.wifi.WifiManager;
import android.net.wifi.WifiSsid;
import android.os.Build;
import android.os.Handler;
import android.os.Looper;
import android.os.SystemClock;

import org.wifiscout.app.core.ScoutEngine;

import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;

/** One explicitly requested foreground Android scan; no joining or background polling. */
public final class AndroidWifiScanner implements AutoCloseable {
    public interface Listener {
        void onStatus(String message, boolean scanning);
        void onResults(List<ScoutEngine.Observation> observations, boolean fresh, String message);
    }

    public static final int LOCATION_PERMISSION_REQUEST = 4107;
    public static final long SCAN_TIMEOUT_MILLIS = 20_000L;

    private final Activity activity;
    private final Listener listener;
    private final WifiManager wifi;
    private final Handler main = new Handler(Looper.getMainLooper());
    private BroadcastReceiver receiver;
    private Runnable timeout;
    private boolean awaitingPermission;
    private boolean scanning;
    private boolean foreground = true;
    private boolean closed;
    private int generation;

    public AndroidWifiScanner(Activity activity, Listener listener) {
        this.activity = activity;
        this.listener = listener;
        this.wifi = activity.getApplicationContext().getSystemService(WifiManager.class);
    }

    /** Called only from an explicit Scan action, on the activity's main thread. */
    public void requestScan() {
        if (closed || activity.isFinishing() || activity.isDestroyed()) return;
        foreground = true;
        if (scanning || awaitingPermission) {
            listener.onStatus("A scan request is already in progress.", true);
            return;
        }
        if (wifi == null) {
            fail("This device does not expose Android Wi-Fi scanning.", false);
            return;
        }
        if (!hasPreciseLocationPermission()) {
            awaitingPermission = true;
            listener.onStatus("Android requires precise Location permission to list nearby Wi-Fi. WiFi Scout does not request your GPS location.", true);
            // Android 12+ requires requesting coarse and fine together to offer
            // the precise/approximate choice. Approximate alone cannot scan Wi-Fi.
            activity.requestPermissions(new String[] {
                    Manifest.permission.ACCESS_FINE_LOCATION,
                    Manifest.permission.ACCESS_COARSE_LOCATION
            }, LOCATION_PERMISSION_REQUEST);
            return;
        }
        beginScan();
    }

    /** Forward Activity.onRequestPermissionsResult here; unrelated requests are ignored. */
    public void onRequestPermissionsResult(int requestCode, String[] permissions, int[] grantResults) {
        if (requestCode != LOCATION_PERMISSION_REQUEST || !awaitingPermission
                || closed || !foreground) return;
        awaitingPermission = false;
        // Re-read the actual grant instead of relying on result-array ordering.
        if (!hasPreciseLocationPermission()) {
            fail("Nearby Wi-Fi needs precise Location permission. Allow it in app permissions, or use the clearly labeled demo without permission.", false);
            return;
        }
        beginScan();
    }

    public boolean hasPreciseLocationPermission() {
        return activity.checkSelfPermission(Manifest.permission.ACCESS_FINE_LOCATION)
                == PackageManager.PERMISSION_GRANTED;
    }

    public boolean isLocationEnabled() {
        try {
            LocationManager location = activity.getSystemService(LocationManager.class);
            return location != null && location.isLocationEnabled();
        } catch (RuntimeException unavailable) {
            return false;
        }
    }

    public boolean isWifiEnabled() {
        try {
            return wifi != null && wifi.isWifiEnabled();
        } catch (SecurityException unavailable) {
            return false;
        }
    }

    @SuppressWarnings("deprecation") // Foreground discovery still uses Android's rate-limited API.
    private void beginScan() {
        if (closed || !foreground) return;
        if (!hasPreciseLocationPermission()) {
            fail("Location permission changed. Allow precise Location permission before scanning.", false);
            return;
        }
        if (!isLocationEnabled()) {
            fail("Turn on the phone’s Location setting to scan nearby Wi-Fi. Android requires it even though WiFi Scout does not request GPS coordinates.", false);
            return;
        }
        if (!isWifiEnabled()) {
            fail("Turn on Wi-Fi in the phone’s settings, then tap Scan again.", false);
            return;
        }

        final int token = ++generation;
        scanning = true;
        listener.onStatus("Scanning nearby Wi-Fi… Android may send normal discovery requests. This does not join a network.", true);
        receiver = new BroadcastReceiver() {
            @Override public void onReceive(Context context, Intent intent) {
                if (closed || !foreground || !scanning || generation != token
                        || !WifiManager.SCAN_RESULTS_AVAILABLE_ACTION.equals(intent.getAction())) return;
                boolean updated = intent.getBooleanExtra(WifiManager.EXTRA_RESULTS_UPDATED, false);
                complete(updated);
            }
        };
        try {
            IntentFilter filter = new IntentFilter(WifiManager.SCAN_RESULTS_AVAILABLE_ACTION);
            if (Build.VERSION.SDK_INT >= 33) {
                // Android's Wi-Fi service can run outside the system UID. This
                // exact action is a platform-protected broadcast; other ordinary
                // apps cannot spoof it. Never add unprotected actions here.
                activity.registerReceiver(receiver, filter, Context.RECEIVER_EXPORTED);
            } else {
                activity.registerReceiver(receiver, filter);
            }
            timeout = () -> {
                if (!closed && foreground && scanning && generation == token) {
                    fail("The phone did not finish a new scan in time. Wait a little, then tap Scan again.", true);
                }
            };
            main.postDelayed(timeout, SCAN_TIMEOUT_MILLIS);
            if (!wifi.startScan()) {
                fail("Android did not accept a new scan. It may be limiting repeated scans or the Wi-Fi service may be busy. Wait before trying again.", true);
            }
        } catch (SecurityException denied) {
            fail("Android blocked Wi-Fi scanning. Check precise Location permission and the phone’s Location setting.", false);
        } catch (RuntimeException unavailable) {
            fail("The phone’s Wi-Fi service could not start a scan. Check Wi-Fi settings and try again.", false);
        }
    }

    private void complete(boolean updated) {
        List<ScoutEngine.Observation> observations;
        try {
            observations = readObservations();
        } catch (SecurityException denied) {
            fail("Android no longer permits access to these observations. Check precise Location permission and Location settings.", false);
            return;
        } catch (RuntimeException unavailable) {
            fail("The phone’s Wi-Fi service could not return scan results. Please try again.", false);
            return;
        }
        stopPendingRequest();
        if (closed || !foreground) return;

        int recent = 0;
        for (ScoutEngine.Observation item : observations) {
            if (item.ageMillis >= 0 && item.ageMillis <= ScoutEngine.MAX_OBSERVATION_AGE_MS) recent++;
        }
        // An updated broadcast alone is insufficient: ScanResult can retain
        // older APs. The engine also checks each AP's own monotonic age.
        boolean fresh = updated && recent > 0;
        String message;
        if (!updated) {
            message = "Android reported that the scan did not update. These are cached observations; no recommendation will be made.";
        } else if (observations.isEmpty()) {
            message = "The scan finished without visible access points. Move or wait, then try again. This does not establish that no networks are nearby.";
        } else if (recent == 0) {
            message = "Android returned observations, but none has a known age within 30 seconds. No recommendation will be made from this cache.";
        } else if (recent < observations.size()) {
            message = "Scan complete. " + recent + " recent access-point observations; older or untimed observations are shown for context and excluded from recommendations.";
        } else {
            message = "Scan complete. " + recent + " recent access-point observations. Signal and advertised protection are clues; operator identity is not verified.";
        }
        listener.onResults(observations, fresh, message);
        listener.onStatus(message, false);
    }

    private List<ScoutEngine.Observation> readObservations() {
        if (wifi == null) throw new SecurityException();
        // Keep the direct check beside the guarded call so Android lint can
        // verify it as well as the runtime path. Callers also catch revocation.
        if (activity.checkSelfPermission(Manifest.permission.ACCESS_FINE_LOCATION)
                != PackageManager.PERMISSION_GRANTED) throw new SecurityException();
        List<ScanResult> results = wifi.getScanResults();
        if (results == null) return Collections.emptyList();
        long nowMicros = SystemClock.elapsedRealtimeNanos() / 1_000L;
        List<ScoutEngine.Observation> observations = new ArrayList<>();
        for (ScanResult result : results) {
            if (result == null) continue;
            String address = result.BSSID;
            if (address == null || !address.matches("(?i)[0-9a-f]{2}(?::[0-9a-f]{2}){5}")) address = null;
            else address = address.toLowerCase(Locale.ROOT);
            Integer signal = result.level >= -127 && result.level <= 0 ? result.level : null;
            Integer frequency = result.frequency > 0 && result.frequency <= 100_000 ? result.frequency : null;
            observations.add(new ScoutEngine.Observation(
                    readName(result), address, signal, frequency, result.capabilities,
                    observationAgeMillis(result.timestamp, nowMicros)));
        }
        return Collections.unmodifiableList(observations);
    }

    /** Android timestamps are microseconds since boot, not Unix timestamps. */
    static long observationAgeMillis(long timestampMicros, long nowMicros) {
        if (timestampMicros <= 0 || nowMicros < 0 || timestampMicros > nowMicros) return -1;
        long difference = nowMicros - timestampMicros;
        // Round up: an AP just beyond the freshness boundary must not sneak in.
        return difference / 1_000L + (difference % 1_000L == 0 ? 0 : 1);
    }

    @SuppressWarnings("deprecation")
    private static String readName(ScanResult result) {
        if (Build.VERSION.SDK_INT >= 33) {
            WifiSsid wifiSsid = result.getWifiSsid();
            if (wifiSsid == null) return null;
            byte[] bytes = wifiSsid.getBytes();
            if (bytes.length == 0) return null;
            boolean hidden = true;
            for (byte value : bytes) if (value != 0) { hidden = false; break; }
            if (hidden) return null;
            try {
                return StandardCharsets.UTF_8.newDecoder()
                        .onMalformedInput(CodingErrorAction.REPORT)
                        .onUnmappableCharacter(CodingErrorAction.REPORT)
                        .decode(ByteBuffer.wrap(bytes)).toString();
            } catch (CharacterCodingException unsupportedName) {
                return null;
            }
        }
        // Older Android versions expose only the platform-decoded name.
        String name = result.SSID;
        return name == null || name.isEmpty() || WifiManager.UNKNOWN_SSID.equals(name) ? null : name;
    }

    private void fail(String message, boolean allowCachedObservations) {
        stopPendingRequest();
        if (closed || !foreground) return;
        List<ScoutEngine.Observation> cached = Collections.emptyList();
        if (allowCachedObservations) {
            try { cached = readObservations(); }
            catch (RuntimeException ignored) { /* Unavailable evidence stays unavailable. */ }
            if (!cached.isEmpty()) message += " Showing cached observations only; no recommendation will be made.";
        }
        // A failed live request must not leave an earlier candidate eligible.
        listener.onResults(cached, false, message);
        listener.onStatus(message, false);
    }

    private void stopPendingRequest() {
        scanning = false;
        awaitingPermission = false;
        generation++;
        if (timeout != null) {
            main.removeCallbacks(timeout);
            timeout = null;
        }
        if (receiver != null) {
            try { activity.unregisterReceiver(receiver); }
            catch (IllegalArgumentException ignored) { /* Registration may have failed. */ }
            receiver = null;
        }
    }

    /** Cancel when leaving the foreground. No result/permission callback survives this. */
    public void onStop() {
        boolean pending = scanning || awaitingPermission;
        foreground = false;
        stopPendingRequest();
        if (!closed && pending) listener.onStatus("Scan canceled while the app was away. Tap Scan again when you’re ready.", false);
    }

    /** Permanently release the scanner, for Activity destruction or switching to demo. */
    @Override public void close() {
        closed = true;
        foreground = false;
        stopPendingRequest();
    }
}
