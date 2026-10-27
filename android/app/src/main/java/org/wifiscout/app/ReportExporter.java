package org.wifiscout.app;

import java.time.Instant;
import java.util.List;
import java.util.Set;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.wifiscout.app.core.ScoutEngine;

/** Serializes an explicitly shared snapshot. Does not write files or access a network. */
public final class ReportExporter {
    private ReportExporter() {}

    /**
     * Observation ages must already be updated to the export time by the caller.
     * Unknown ages are represented as null, never converted to an invented time.
     */
    public static String toJson(List<ScoutEngine.Observation> observations, Set<String> allowedSsids,
                                boolean fresh, boolean demo, long exportedAtMillis) {
        if (exportedAtMillis < 0) throw new IllegalArgumentException("Export time must be a valid nonnegative epoch timestamp.");
        ScoutEngine.Result result = ScoutEngine.evaluate(observations, allowedSsids, fresh);
        try {
            JSONObject report = new JSONObject();
            report.put("schema", "wifi-scout-phone-report");
            report.put("schema_version", 1);
            report.put("source", "android");
            report.put("mode", demo ? "demo" : "live");
            report.put("exported_at", Instant.ofEpochMilli(exportedAtMillis).toString());
            report.put("fresh_at_export", result.fresh);
            JSONArray groups = new JSONArray();
            for (ScoutEngine.Group group : result.groups) {
                JSONObject item = new JSONObject();
                item.put("id", group.id);
                item.put("ssid", nullable(group.ssid));
                item.put("security_label", group.securityLabel);
                item.put("signal_label", group.signalLabel);
                item.put("identity_label", group.identityLabel);
                item.put("authorized", group.authorized);
                item.put("conflicted", group.conflicted);
                JSONArray points = new JSONArray();
                for (ScoutEngine.Observation observation : group.observations) {
                    points.put(observation(observation, exportedAtMillis, demo));
                }
                item.put("observations", points);
                JSONArray findings = new JSONArray();
                for (ScoutEngine.Finding finding : group.findings) {
                    JSONObject detail = new JSONObject();
                    detail.put("id", finding.id);
                    detail.put("severity", finding.severity);
                    detail.put("title", finding.title);
                    detail.put("explanation", finding.explanation);
                    findings.put(detail);
                }
                item.put("findings", findings);
                groups.put(item);
            }
            report.put("groups", groups);
            JSONObject recommendation = new JSONObject();
            recommendation.put("status", result.recommendationTitle);
            recommendation.put("candidate_ssid", result.candidate == null ? JSONObject.NULL : nullable(result.candidate.ssid));
            recommendation.put("candidate_bssid", result.candidate == null ? JSONObject.NULL : nullable(result.candidate.bssid));
            recommendation.put("reasons", new JSONArray(result.reasons));
            recommendation.put("explanation", result.recommendationExplanation);
            report.put("recommendation", recommendation);
            JSONArray limitations = new JSONArray();
            if (demo) limitations.put("Fictional demonstration observations only. This report does not describe nearby Wi-Fi or a live scan.");
            limitations.put("This shared report is a snapshot. Conditions and access permissions may have changed since export.");
            for (String limitation : result.limitations) limitations.put(limitation);
            report.put("limitations", limitations);
            return report.toString(2);
        } catch (JSONException error) {
            throw new IllegalStateException("WiFi Scout could not serialize this phone report.", error);
        }
    }

    private static JSONObject observation(ScoutEngine.Observation observation, long exportedAtMillis,
                                          boolean demo) throws JSONException {
        JSONObject item = new JSONObject();
        item.put("ssid", nullable(observation.ssid));
        item.put("bssid", nullable(observation.bssid));
        item.put("signal_dbm", nullable(observation.signalDbm));
        item.put("frequency_mhz", nullable(observation.frequencyMhz));
        item.put("capabilities", nullable(observation.capabilities));
        item.put("age_millis_at_export", observation.ageMillis < 0 ? JSONObject.NULL : observation.ageMillis);
        String observedAt = !demo && observation.ageMillis >= 0 && observation.ageMillis <= exportedAtMillis
                ? Instant.ofEpochMilli(exportedAtMillis - observation.ageMillis).toString() : null;
        item.put("observed_at", nullable(observedAt));
        return item;
    }

    private static Object nullable(Object value) {
        return value == null ? JSONObject.NULL : value;
    }
}
