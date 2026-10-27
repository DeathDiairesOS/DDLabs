package org.wifiscout.app;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.ActivityNotFoundException;
import android.content.ClipData;
import android.content.Intent;
import android.content.res.ColorStateList;
import android.graphics.Color;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.net.Uri;
import android.os.Bundle;
import android.os.Build;
import android.os.Handler;
import android.os.Looper;
import android.os.SystemClock;
import android.provider.Settings;
import android.view.Gravity;
import android.view.View;
import android.view.WindowInsets;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

import org.wifiscout.app.core.ScoutEngine;

import java.io.IOException;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/** Native, local-only phone flow. Opening the app never starts a radio scan. */
public final class MainActivity extends Activity {
    private static final int CREAM = Color.rgb(247, 248, 241);
    private static final int FOREST = Color.rgb(39, 73, 48);
    private static final int INK = Color.rgb(38, 60, 43);
    private static final int MUTED = Color.rgb(99, 113, 94);
    private static final int LINE = Color.rgb(219, 226, 212);
    private static final int AMBER = Color.rgb(119, 87, 35);
    private static final int PALE_AMBER = Color.rgb(249, 241, 224);
    private static final int PALE_GREEN = Color.rgb(236, 242, 226);
    private static final long FRESH_MILLIS = 30_000L;

    private final Handler handler = new Handler(Looper.getMainLooper());
    private final Set<String> allowedSsids = new HashSet<>();
    private final Set<String> expandedGroups = new HashSet<>();
    private final List<ScoutEngine.Observation> observations = new ArrayList<>();
    private AndroidWifiScanner scanner;
    private LinearLayout content, results, recommendation, networkList, statusPanel;
    private TextView statusText, modeText;
    private Button scanButton;
    private boolean demo, fresh, busy;
    private long receivedAt;
    private String status = "";
    private final Runnable markOld = () -> {
        if (!demo && !observations.isEmpty()) {
            fresh = false;
            setStatus("These observations are getting old. Scan again before choosing a network.", false);
            renderResults();
        }
    };

    private static final class Snapshot {
        final List<ScoutEngine.Observation> observations;
        final Set<String> allowed, expanded;
        final boolean demo, fresh;
        final long receivedAt;
        final String status;
        Snapshot(MainActivity activity) {
            observations = new ArrayList<>(activity.observations);
            allowed = new HashSet<>(activity.allowedSsids);
            expanded = new HashSet<>(activity.expandedGroups);
            demo = activity.demo;
            fresh = activity.fresh;
            receivedAt = activity.receivedAt;
            status = activity.status;
        }
    }

    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        getWindow().setStatusBarColor(CREAM);
        getWindow().setNavigationBarColor(CREAM);
        getWindow().getDecorView().setSystemUiVisibility(
                View.SYSTEM_UI_FLAG_LIGHT_STATUS_BAR | View.SYSTEM_UI_FLAG_LIGHT_NAVIGATION_BAR);
        Object retained = getLastNonConfigurationInstance();
        if (retained instanceof Snapshot) {
            Snapshot saved = (Snapshot) retained;
            observations.addAll(saved.observations);
            allowedSsids.addAll(saved.allowed);
            expandedGroups.addAll(saved.expanded);
            demo = saved.demo;
            fresh = saved.fresh;
            receivedAt = saved.receivedAt;
            status = saved.status;
        }
        buildScreen();
        createScanner();
        setStatus(status, false);
        renderResults();
    }

    private void createScanner() {
        scanner = new AndroidWifiScanner(this, new AndroidWifiScanner.Listener() {
            @Override public void onStatus(String message, boolean scanning) {
                if (!demo) setStatus(message, scanning);
            }

            @Override public void onResults(List<ScoutEngine.Observation> found,
                                            boolean updated, String message) {
                if (demo) return;
                observations.clear();
                observations.addAll(found);
                receivedAt = SystemClock.elapsedRealtime();
                fresh = updated;
                expandedGroups.clear();
                setStatus(message, false);
                renderResults();
            }
        });
    }

    private void buildScreen() {
        ScrollView scroll = new ScrollView(this);
        scroll.setFillViewport(true);
        scroll.setBackgroundColor(CREAM);
        content = vertical();
        content.setPadding(dp(22), dp(23), dp(22), dp(28));
        scroll.addView(content, new ScrollView.LayoutParams(-1, -2));
        scroll.setOnApplyWindowInsetsListener((view, insets) -> {
            if (Build.VERSION.SDK_INT >= 30) {
                android.graphics.Insets system = insets.getInsets(
                        WindowInsets.Type.systemBars() | WindowInsets.Type.displayCutout());
                view.setPadding(system.left, system.top, system.right, system.bottom);
            } else {
                view.setPadding(insets.getSystemWindowInsetLeft(), insets.getSystemWindowInsetTop(),
                        insets.getSystemWindowInsetRight(), insets.getSystemWindowInsetBottom());
            }
            return insets;
        });
        setContentView(scroll);

        TextView brand = text("WiFi Scout", 26, INK, true);
        add(content, brand, 0, 0);
        modeText = text(getString(R.string.mode_on_phone), 10, MUTED, true);
        modeText.setLetterSpacing(.09f);
        add(content, modeText, 7, 27);
        add(content, text("Make sense of\nnearby Wi-Fi.", 33, INK, true), 0, 13);
        add(content, text("Compare your options before you connect. Clear concerns first, details when you want them.", 16, MUTED, false), 0, 23);

        scanButton = button(getString(R.string.scan_button), true);
        scanButton.setOnClickListener(v -> beginLiveScan());
        add(content, scanButton, 0, 9);
        Button demoButton = button("Try the demo", false);
        demoButton.setOnClickListener(v -> showDemo());
        add(content, demoButton, 0, 9);
        add(content, text("You choose when to scan. WiFi Scout never connects for you.", 12, MUTED, false), 0, 16);

        statusPanel = card(PALE_AMBER);
        statusText = text("", 14, AMBER, false);
        statusText.setAccessibilityLiveRegion(View.ACCESSIBILITY_LIVE_REGION_POLITE);
        statusPanel.addView(statusText);
        add(content, statusPanel, 0, 17);

        addScanHelp();
        results = vertical();
        add(content, results, 24, 24);
        add(content, divider(), 0, 17);
        add(content, text("No account. No cloud. No automatic connections.", 12, MUTED, false), 0, 0);
    }

    private void addScanHelp() {
        LinearLayout help = vertical();
        help.setVisibility(View.GONE);
        TextView explanation = text("Android requires precise location permission and Location to be on for Wi-Fi scans. WiFi Scout does not request your GPS position or send observations anywhere. Android can also limit repeated scans.", 14, MUTED, false);
        add(help, explanation, 8, 12);
        Button wifi = button("Open Wi-Fi settings", false);
        wifi.setOnClickListener(v -> openSettings(Settings.ACTION_WIFI_SETTINGS));
        add(help, wifi, 0, 8);
        Button location = button("Open Location settings", false);
        location.setOnClickListener(v -> openSettings(Settings.ACTION_LOCATION_SOURCE_SETTINGS));
        add(help, location, 0, 8);
        Button permissions = button("Open app permissions", false);
        permissions.setOnClickListener(v -> {
            Intent intent = new Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS,
                    Uri.parse("package:" + getPackageName()));
            launchSettings(intent);
        });
        add(help, permissions, 0, 8);
        Button toggle = disclosureButton(getString(R.string.scan_help_permissions), help, false);
        add(content, toggle, 0, 0);
        add(content, help, 0, 0);
    }

    private void beginLiveScan() {
        if (busy) return;
        boolean leavingDemo = demo;
        demo = false;
        fresh = false;
        handler.removeCallbacks(markOld);
        if (leavingDemo) {
            observations.clear();
            allowedSsids.clear();
            expandedGroups.clear();
        }
        modeText.setText(R.string.mode_on_phone);
        renderResults();
        if (scanner == null) createScanner();
        scanner.requestScan();
    }

    private void showDemo() {
        demo = true;
        if (scanner != null) {
            scanner.close();
            scanner = null;
        }
        handler.removeCallbacks(markOld);
        observations.clear();
        observations.addAll(ScoutEngine.demo());
        allowedSsids.clear();
        expandedGroups.clear();
        fresh = true;
        receivedAt = SystemClock.elapsedRealtime();
        setStatus("Demo only: these invented networks are not your surroundings. No scan or connection takes place.", false);
        modeText.setText(R.string.mode_demo);
        renderResults();
    }

    private void setStatus(String message, boolean scanning) {
        status = message == null ? "" : message;
        busy = scanning;
        scanButton.setText(scanning ? R.string.scanning : R.string.scan_button);
        scanButton.setEnabled(!scanning);
        statusText.setText(status);
        statusPanel.setVisibility(status.isEmpty() ? View.GONE : View.VISIBLE);
    }

    private List<ScoutEngine.Observation> currentObservations() {
        if (demo) return new ArrayList<>(observations);
        long elapsed = Math.max(0, SystemClock.elapsedRealtime() - receivedAt);
        List<ScoutEngine.Observation> aged = new ArrayList<>();
        for (ScoutEngine.Observation n : observations) {
            long age = n.ageMillis < 0 ? -1 : n.ageMillis + elapsed;
            aged.add(new ScoutEngine.Observation(n.ssid, n.bssid, n.signalDbm,
                    n.frequencyMhz, n.capabilities, age));
        }
        return aged;
    }

    private void renderResults() {
        handler.removeCallbacks(markOld);
        results.removeAllViews();
        modeText.setText(demo ? R.string.mode_demo : R.string.mode_on_phone);
        if (observations.isEmpty()) {
            LinearLayout empty = card(Color.WHITE);
            add(empty, text("Your options will appear here.", 21, INK, true), 0, 8);
            add(empty, text("Start a scan, or try the demo without giving location permission.", 15, MUTED, false), 0, 0);
            results.addView(empty);
            return;
        }
        long elapsed = Math.max(0, SystemClock.elapsedRealtime() - receivedAt);
        if (!demo && elapsed > FRESH_MILLIS) fresh = false;
        ScoutEngine.Result report = ScoutEngine.evaluate(currentObservations(), allowedSsids, fresh);
        add(results, text(demo ? "Explore the example results" : "Here’s what we found", 25, INK, true), 0, 8);
        add(results, text(demo ? "Fictional networks · no live scan" : "Nearby Wi-Fi · advertisements, not verified identities", 12, MUTED, false), 0, 18);

        recommendation = card(report.candidate == null ? Color.WHITE : PALE_GREEN);
        renderRecommendation(report);
        add(results, recommendation, 0, 24);
        Button share = button(getString(R.string.share_report), false);
        share.setOnClickListener(v -> confirmReportExport());
        add(results, share, 0, 7);
        add(results, text(getString(R.string.share_report_hint), 12, MUTED, false), 0, 24);
        add(results, text("Nearby Wi-Fi  ·  " + report.groups.size(), 21, INK, true), 0, 5);
        add(results, text("Tap the networks you’re allowed to use to include them in the comparison.", 14, MUTED, false), 0, 16);
        networkList = vertical();
        for (ScoutEngine.Group group : report.groups) add(networkList, networkCard(group), 0, 14);
        results.addView(networkList);
        LinearLayout limitations = card(CREAM);
        add(limitations, text("A useful clue, not a guarantee.", 18, INK, true), 0, 8);
        add(limitations, text("A phone scan cannot confirm who runs a network, inspect its sign-in page, or predict internet speed. Ask the venue for the expected name and sign-in instructions.", 14, MUTED, false), 0, 10);
        LinearLayout details = vertical();
        details.setVisibility(View.GONE);
        for (String limitation : report.limitations) add(details, text("• " + limitation, 13, MUTED, false), 0, 9);
        add(limitations, disclosureButton(getString(R.string.phone_check_limitations), details, false), 0, 0);
        limitations.addView(details);
        add(results, limitations, 4, 0);
        if (!demo && fresh) {
            long delay = Math.max(1, FRESH_MILLIS - elapsed + 1);
            if (report.candidate != null && report.candidate.ageMillis >= 0) {
                delay = Math.min(delay, Math.max(1, FRESH_MILLIS - report.candidate.ageMillis + 1));
            }
            handler.postDelayed(markOld, delay);
        }
    }

    private void renderRecommendation(ScoutEngine.Result report) {
        add(recommendation, text(report.candidate == null ? "YOUR NEXT STEP" : "BEST OBSERVED CANDIDATE", 10, MUTED, true), 0, 9);
        String title = report.candidate == null ? report.recommendationTitle : display(report.candidate.ssid);
        add(recommendation, text(title, 25, INK, true), 0, 10);
        add(recommendation, text(report.recommendationExplanation, 15, INK, false), 0, 13);
        for (String reason : report.reasons) add(recommendation, text("• " + reason, 14, MUTED, false), 0, 8);
        add(recommendation, divider(), 7, 11);
        add(recommendation, text("Who runs it? Not confirmed.", 14, INK, true), 0, 5);
        add(recommendation, text("Names and advertised settings can be copied. Confirm the Wi-Fi with the venue before joining.", 13, MUTED, false), 0, 0);
        if (report.candidate != null) {
            Button join = button(demo ? "Demo only · no connection" : "Open Wi-Fi settings to join", true);
            join.setEnabled(!demo);
            join.setOnClickListener(v -> {
                ScoutEngine.Result latest = ScoutEngine.evaluate(currentObservations(), allowedSsids, fresh);
                if (latest.candidate == null || !latest.candidate.ssid.equals(report.candidate.ssid)) {
                    setStatus("Refresh this scan before choosing. The earlier observations are no longer current.", false);
                    renderResults();
                    return;
                }
                openSettings(Settings.ACTION_WIFI_SETTINGS);
            });
            add(recommendation, join, 18, 7);
            add(recommendation, text(demo ? "Real networks can be selected in your phone’s Wi-Fi settings." : "Choose “" + display(report.candidate.ssid) + "” in Android. WiFi Scout does not select it or enter a password.", 12, MUTED, false), 0, 0);
        }
    }

    private LinearLayout networkCard(ScoutEngine.Group group) {
        LinearLayout card = card(Color.WHITE);
        add(card, text(display(group.ssid), 21, INK, true), 0, 11);
        for (ScoutEngine.Finding finding : group.findings) {
            if (!"info".equalsIgnoreCase(finding.severity)) {
                LinearLayout concern = card(PALE_AMBER);
                concern.setPadding(dp(12), dp(11), dp(12), dp(11));
                add(concern, text(finding.title, 14, AMBER, true), 0, 5);
                add(concern, text(finding.explanation, 13, AMBER, false), 0, 0);
                add(card, concern, 0, 10);
            }
        }
        add(card, text("Protection  ·  " + group.securityLabel, 14, INK, true), 0, 6);
        add(card, text("Signal  ·  " + group.signalLabel, 14, MUTED, false), 0, 6);
        add(card, text(group.identityLabel, 14, MUTED, false), 0, 10);
        if (group.ssid != null && !group.ssid.isEmpty()) {
            CheckBox allow = new CheckBox(this);
            allow.setText(R.string.allow_network);
            allow.setTextColor(INK);
            allow.setTextSize(14);
            allow.setMinHeight(dp(48));
            allow.setButtonTintList(ColorStateList.valueOf(FOREST));
            allow.setChecked(allowedSsids.contains(group.ssid));
            allow.setContentDescription("I am allowed to use " + display(group.ssid) + " and have any required password or sign-in details");
            allow.setOnCheckedChangeListener((view, checked) -> {
                if (checked) allowedSsids.add(group.ssid); else allowedSsids.remove(group.ssid);
                int scrollY = ((ScrollView) content.getParent()).getScrollY();
                renderResults();
                content.post(() -> {
                    ScrollView scroll = (ScrollView) content.getParent();
                    if (checked) {
                        scroll.smoothScrollTo(0, results.getTop() + recommendation.getTop() - dp(16));
                        recommendation.announceForAccessibility("Comparison updated. Read your next step.");
                    } else scroll.scrollTo(0, scrollY);
                });
            });
            add(card, allow, 0, 0);
            add(card, text("I have permission and any needed password or sign-in details.", 12, MUTED, false), 0, 13);
        } else {
            add(card, text("The name is unavailable, so this cannot be suggested.", 13, MUTED, false), 0, 13);
        }
        add(card, divider(), 0, 5);
        LinearLayout technical = vertical();
        boolean expanded = expandedGroups.contains(group.id);
        technical.setVisibility(expanded ? View.VISIBLE : View.GONE);
        for (ScoutEngine.Observation n : group.observations) add(technical, observationDetails(n), 8, 14);
        for (ScoutEngine.Finding finding : group.findings) {
            add(technical, text(finding.title, 14, INK, true), 7, 4);
            add(technical, text(finding.id + " · " + finding.severity, 11, MUTED, false), 0, 5);
            add(technical, text(finding.explanation, 13, MUTED, false), 0, 8);
        }
        String technicalLabel = getString(R.string.technical_details);
        Button expand = disclosureButton(technicalLabel, technical, expanded);
        expand.setOnClickListener(v -> {
            boolean show = technical.getVisibility() != View.VISIBLE;
            technical.setVisibility(show ? View.VISIBLE : View.GONE);
            expand.setText(disclosureText(technicalLabel, show));
            expand.setContentDescription(getString(show ? R.string.network_details_expanded
                    : R.string.network_details_collapsed, display(group.ssid)));
            if (show) expandedGroups.add(group.id); else expandedGroups.remove(group.id);
        });
        expand.setContentDescription(getString(expanded ? R.string.network_details_expanded
                : R.string.network_details_collapsed, display(group.ssid)));
        add(card, expand, 0, 0);
        card.addView(technical);
        return card;
    }

    private LinearLayout observationDetails(ScoutEngine.Observation n) {
        LinearLayout details = vertical();
        add(details, text("Access-point observation", 14, INK, true), 0, 6);
        detail(details, "Name", display(n.ssid));
        detail(details, "Address", n.bssid == null ? "Unknown" : safeText(n.bssid));
        detail(details, "Signal", n.signalDbm == null ? "Unknown" : n.signalDbm + " dBm");
        detail(details, "Frequency", n.frequencyMhz == null ? "Unknown" : n.frequencyMhz + " MHz");
        detail(details, "Band", ScoutEngine.bandLabel(n.frequencyMhz));
        detail(details, "Channel", String.valueOf(ScoutEngine.channel(n.frequencyMhz)));
        detail(details, "Observed age", demo ? "Fictional example" : n.ageMillis < 0 ? "Unknown" : Math.max(0, n.ageMillis / 1000) + " seconds");
        detail(details, "Android capabilities", n.capabilities == null || n.capabilities.isEmpty() ? "Unknown" : safeText(n.capabilities));
        add(details, text("Phone discovery does not capture disconnect frames or establish operator identity.", 12, MUTED, false), 7, 0);
        return details;
    }

    private void detail(LinearLayout parent, String label, String value) {
        add(parent, text(label + ": " + (value == null || "null".equals(value) ? "Unknown" : value), 12, MUTED, false), 0, 5);
    }

    private Button disclosureButton(String label, LinearLayout target, boolean open) {
        Button button = button(disclosureText(label, open), false);
        button.setBackgroundColor(Color.TRANSPARENT);
        button.setGravity(Gravity.START | Gravity.CENTER_VERTICAL);
        button.setPadding(0, dp(7), 0, dp(7));
        button.setTextSize(14);
        button.setOnClickListener(v -> {
            boolean show = target.getVisibility() != View.VISIBLE;
            target.setVisibility(show ? View.VISIBLE : View.GONE);
            button.setText(disclosureText(label, show));
            button.setContentDescription(getString(show ? R.string.disclosure_accessibility_expanded
                    : R.string.disclosure_accessibility_collapsed, label));
        });
        button.setContentDescription(getString(open ? R.string.disclosure_accessibility_expanded
                : R.string.disclosure_accessibility_collapsed, label));
        return button;
    }

    private String disclosureText(String label, boolean expanded) {
        return getString(expanded ? R.string.disclosure_expanded : R.string.disclosure_collapsed, label);
    }

    private void openSettings(String action) { launchSettings(new Intent(action)); }

    private void confirmReportExport() {
        new AlertDialog.Builder(this)
                .setTitle(R.string.share_report_title)
                .setMessage(demo ? R.string.share_demo_disclosure : R.string.share_live_disclosure)
                .setNegativeButton(android.R.string.cancel, null)
                .setPositiveButton(R.string.share_report_confirm, (dialog, which) -> shareReport())
                .show();
    }

    private void shareReport() {
        try {
            long elapsed = Math.max(0, SystemClock.elapsedRealtime() - receivedAt);
            boolean currentFresh = fresh && (demo || elapsed <= FRESH_MILLIS);
            String json = ReportExporter.toJson(currentObservations(), new HashSet<>(allowedSsids),
                    currentFresh, demo, System.currentTimeMillis());
            Uri uri = ReportProvider.writeReport(this, json);
            Intent send = new Intent(Intent.ACTION_SEND)
                    .setType("application/json")
                    .putExtra(Intent.EXTRA_STREAM, uri)
                    .putExtra(Intent.EXTRA_TITLE, getString(R.string.shared_report_name))
                    .addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);
            send.setClipData(ClipData.newRawUri(getString(R.string.shared_report_name), uri));
            startActivity(Intent.createChooser(send, getString(R.string.share_report_chooser)));
        } catch (IOException | IllegalStateException | IllegalArgumentException error) {
            setStatus(getString(R.string.share_report_failed), false);
        } catch (ActivityNotFoundException | SecurityException error) {
            setStatus(getString(R.string.share_chooser_unavailable), false);
        }
    }

    private void launchSettings(Intent intent) {
        try { startActivity(intent); }
        catch (ActivityNotFoundException | SecurityException error) {
            setStatus("Open your phone’s Settings app manually. WiFi Scout could not open that screen.", false);
        }
    }

    private LinearLayout vertical() {
        LinearLayout layout = new LinearLayout(this);
        layout.setOrientation(LinearLayout.VERTICAL);
        return layout;
    }

    private LinearLayout card(int fill) {
        LinearLayout layout = vertical();
        layout.setPadding(dp(18), dp(19), dp(18), dp(18));
        layout.setBackground(background(fill, LINE, 16));
        return layout;
    }

    private GradientDrawable background(int fill, int stroke, int radius) {
        GradientDrawable drawable = new GradientDrawable();
        drawable.setColor(fill);
        drawable.setCornerRadius(dp(radius));
        drawable.setStroke(dp(1), stroke);
        return drawable;
    }

    private TextView text(String value, int size, int color, boolean bold) {
        TextView view = new TextView(this);
        view.setText(value == null ? "Unknown" : value);
        view.setTextSize(size);
        view.setTextColor(color);
        view.setIncludeFontPadding(false);
        view.setLineSpacing(dp(3), 1.08f);
        if (bold) view.setTypeface(Typeface.DEFAULT, Typeface.BOLD);
        if (bold && size >= 18) view.setAccessibilityHeading(true);
        return view;
    }

    private Button button(String label, boolean primary) {
        Button button = new Button(this);
        button.setText(label);
        button.setTextSize(15);
        button.setAllCaps(false);
        button.setTypeface(Typeface.DEFAULT, Typeface.BOLD);
        button.setTextColor(primary ? Color.WHITE : FOREST);
        button.setBackground(background(primary ? FOREST : Color.WHITE, primary ? FOREST : LINE, 12));
        button.setPadding(dp(16), dp(13), dp(16), dp(13));
        button.setMinHeight(dp(52));
        button.setStateListAnimator(null);
        return button;
    }

    private View divider() {
        View line = new View(this);
        line.setBackgroundColor(LINE);
        line.setMinimumHeight(dp(1));
        return line;
    }

    private void add(LinearLayout parent, View child, int above, int below) {
        LinearLayout.LayoutParams params = new LinearLayout.LayoutParams(-1, -2);
        params.topMargin = dp(above);
        params.bottomMargin = dp(below);
        parent.addView(child, params);
    }

    private int dp(float value) { return Math.round(value * getResources().getDisplayMetrics().density); }

    private static String display(String ssid) {
        return ssid == null || ssid.isEmpty() ? "Hidden or unavailable name" : safeText(ssid);
    }

    private static String safeText(String value) {
        StringBuilder safe = new StringBuilder();
        value.codePoints().forEach(cp -> {
            if (Character.isISOControl(cp) || Character.getType(cp) == Character.FORMAT) {
                safe.append(String.format(Locale.ROOT, "\\u%04x", cp));
            } else safe.appendCodePoint(cp);
        });
        return safe.toString();
    }

    @Override public Object onRetainNonConfigurationInstance() { return new Snapshot(this); }

    @Override public void onRequestPermissionsResult(int requestCode, String[] permissions, int[] grants) {
        super.onRequestPermissionsResult(requestCode, permissions, grants);
        if (scanner != null && !demo) scanner.onRequestPermissionsResult(requestCode, permissions, grants);
    }

    @Override protected void onStop() {
        super.onStop();
        if (scanner != null) scanner.onStop();
        if (!demo && !observations.isEmpty()) fresh = false;
        handler.removeCallbacks(markOld);
    }

    @Override protected void onResume() {
        super.onResume();
        if (results != null && !observations.isEmpty()) renderResults();
    }

    @Override protected void onDestroy() {
        if (scanner != null) scanner.close();
        handler.removeCallbacksAndMessages(null);
        super.onDestroy();
    }
}
