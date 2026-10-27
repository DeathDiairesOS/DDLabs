package org.wifiscout.app;

import static org.junit.Assert.*;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import org.json.JSONArray;
import org.json.JSONObject;
import org.junit.Test;
import org.wifiscout.app.core.ScoutEngine;

public class ReportExporterTest {
    private static final long EXPORTED_AT = Instant.parse("2026-10-27T12:00:00Z").toEpochMilli();
    private static final String WPA2 = "[WPA2-PSK-CCMP][ESS]";

    private static ScoutEngine.Observation point(String ssid, long age) {
        return new ScoutEngine.Observation(ssid, "02:00:00:00:00:01", -55, 5180, WPA2, age);
    }
    private static JSONObject export(List<ScoutEngine.Observation> observations, Set<String> allowed,
                                     boolean fresh, boolean demo) throws Exception {
        return new JSONObject(ReportExporter.toJson(observations, allowed, fresh, demo, EXPORTED_AT));
    }
    private static JSONObject firstPoint(JSONObject report) throws Exception {
        return report.getJSONArray("groups").getJSONObject(0).getJSONArray("observations").getJSONObject(0);
    }

    @Test public void liveExportIncludesVersionedSchemaAndCalculatedObservationTime() throws Exception {
        JSONObject report = export(Collections.singletonList(point("Venue", 1250)), Collections.singleton("Venue"), true, false);
        assertEquals("wifi-scout-phone-report", report.getString("schema"));
        assertEquals(1, report.getInt("schema_version"));
        assertEquals("android", report.getString("source"));
        assertEquals("live", report.getString("mode"));
        assertEquals("2026-10-27T12:00:00Z", report.getString("exported_at"));
        assertTrue(report.getBoolean("fresh_at_export"));
        assertEquals(1250, firstPoint(report).getLong("age_millis_at_export"));
        assertEquals("2026-10-27T11:59:58.750Z", firstPoint(report).getString("observed_at"));
        assertEquals("Venue", report.getJSONObject("recommendation").getString("candidate_ssid"));
        assertEquals("02:00:00:00:00:01", report.getJSONObject("recommendation").getString("candidate_bssid"));
    }

    @Test public void demoNeverInventsRealObservationTimestamps() throws Exception {
        JSONObject report = export(ScoutEngine.demo(), Collections.singleton("Juniper Café"), true, true);
        assertEquals("demo", report.getString("mode"));
        assertTrue(report.getJSONArray("limitations").getString(0).contains("Fictional"));
        JSONArray groups = report.getJSONArray("groups");
        for (int i = 0; i < groups.length(); i++) {
            JSONArray points = groups.getJSONObject(i).getJSONArray("observations");
            for (int j = 0; j < points.length(); j++) {
                assertTrue(points.getJSONObject(j).isNull("observed_at"));
            }
        }
        assertEquals("Juniper Café", report.getJSONObject("recommendation").getString("candidate_ssid"));
    }

    @Test public void missingFieldsStayPresentAsJsonNull() throws Exception {
        ScoutEngine.Observation missing = new ScoutEngine.Observation(null, null, null, null, null, -1);
        JSONObject report = export(Collections.singletonList(missing), Collections.emptySet(), true, false);
        JSONObject point = firstPoint(report);
        for (String key : Arrays.asList("ssid", "bssid", "signal_dbm", "frequency_mhz", "capabilities", "age_millis_at_export", "observed_at")) {
            assertTrue(key, point.has(key));
            assertTrue(key, point.isNull(key));
        }
        assertTrue(report.getJSONArray("groups").getJSONObject(0).isNull("ssid"));
        assertTrue(report.getJSONObject("recommendation").isNull("candidate_ssid"));
        assertTrue(report.getJSONObject("recommendation").isNull("candidate_bssid"));
    }

    @Test public void staleBatchWithholdsCandidateAndPreservesSnapshotEvidence() throws Exception {
        JSONObject report = export(Collections.singletonList(point("Venue", 0)), Collections.singleton("Venue"), false, false);
        assertFalse(report.getBoolean("fresh_at_export"));
        assertEquals("Cannot confidently recommend", report.getJSONObject("recommendation").getString("status"));
        assertTrue(report.getJSONObject("recommendation").isNull("candidate_ssid"));
        assertEquals(1, report.getJSONArray("groups").length());
    }

    @Test public void exportUsesAlreadyAgedObservationsWhenReevaluating() throws Exception {
        JSONObject report = export(Collections.singletonList(point("Venue", 30_001)), Collections.singleton("Venue"), true, false);
        assertTrue(report.getJSONObject("recommendation").isNull("candidate_ssid"));
        assertEquals(30_001, firstPoint(report).getLong("age_millis_at_export"));
    }

    @Test public void hostileUnicodeNamesRoundTripAsDataWithoutNormalization() throws Exception {
        String name = "<script>alert(1)</script>\"\\\n\u202eWi-Fi Café";
        JSONObject report = export(Collections.singletonList(point(name, 0)), Collections.singleton(name), true, false);
        assertEquals(name, report.getJSONArray("groups").getJSONObject(0).getString("ssid"));
        assertEquals(name, firstPoint(report).getString("ssid"));
        assertEquals(name, report.getJSONObject("recommendation").getString("candidate_ssid"));
    }

    @Test public void impossibleOldAgeCannotOverflowIntoAnInventedTimestamp() throws Exception {
        JSONObject report = export(Collections.singletonList(point("Venue", Long.MAX_VALUE)), Collections.singleton("Venue"), true, false);
        assertEquals(Long.MAX_VALUE, firstPoint(report).getLong("age_millis_at_export"));
        assertTrue(firstPoint(report).isNull("observed_at"));
        assertTrue(report.getJSONObject("recommendation").isNull("candidate_ssid"));
    }

    @Test public void conflictsAndPermissionStateAreExportedWithExplanations() throws Exception {
        JSONObject report = export(ScoutEngine.demo(), Collections.singleton("Airport Guest"), true, true);
        JSONObject airport = report.getJSONArray("groups").getJSONObject(0);
        assertTrue(airport.getBoolean("authorized"));
        assertTrue(airport.getBoolean("conflicted"));
        assertEquals("Who runs it: not confirmed", airport.getString("identity_label"));
        JSONArray findings = airport.getJSONArray("findings");
        boolean found = false;
        for (int i = 0; i < findings.length(); i++) {
            JSONObject finding = findings.getJSONObject(i);
            if (finding.getString("id").equals("SECURITY_CONFLICT")) {
                found = true;
                assertEquals("medium", finding.getString("severity"));
                assertTrue(finding.getString("explanation").contains("Reconfiguration"));
            }
        }
        assertTrue(found);
        assertTrue(report.getJSONObject("recommendation").isNull("candidate_ssid"));
    }

    @Test public void callerCollectionsAndObservationsAreUnchanged() throws Exception {
        List<ScoutEngine.Observation> observations = new ArrayList<>(Collections.singletonList(point("Venue", 700)));
        Set<String> allowed = new HashSet<>(Collections.singleton("Venue"));
        ScoutEngine.Observation original = observations.get(0);
        export(observations, allowed, true, false);
        assertSame(original, observations.get(0));
        assertEquals(1, observations.size());
        assertEquals(700, original.ageMillis);
        assertEquals(Collections.singleton("Venue"), allowed);
    }

    @Test public void invalidExportTimeIsRejectedClearly() throws Exception {
        try {
            ReportExporter.toJson(Collections.emptyList(), Collections.emptySet(), true, false, -1);
            fail("Expected an invalid export timestamp to be rejected");
        } catch (IllegalArgumentException expected) {
            assertTrue(expected.getMessage().contains("Export time"));
        }
    }
}
