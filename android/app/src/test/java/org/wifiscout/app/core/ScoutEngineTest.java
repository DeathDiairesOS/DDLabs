package org.wifiscout.app.core;

import static org.junit.Assert.*;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import org.junit.Test;

public class ScoutEngineTest {
    private static final String WPA2 = "[WPA2-PSK-CCMP][ESS]";
    private static ScoutEngine.Observation observation(String ssid, String address, String security, int signal, long age) {
        return new ScoutEngine.Observation(ssid, address, signal, 5180, security, age);
    }
    private static ScoutEngine.Observation observation(String security) {
        return observation("Venue", "02:00:00:00:00:01", security, -55, 0);
    }
    private static Set<String> allow(String... names) { return new HashSet<>(Arrays.asList(names)); }
    private static boolean has(ScoutEngine.Group group, String id) {
        for (ScoutEngine.Finding finding : group.findings) if (finding.id.equals(id)) return true;
        return false;
    }

    @Test public void missingAndUnknownSecurityNeverBecomeOpen() {
        for (String raw : Arrays.asList(null, "", " ", "[ESS][WAPI-PSK-SMS4]", "[RSN-DPP-CCMP][ESS]", "[ESS][UNRECOGNIZED]", "[RSN][ESS]")) {
            ScoutEngine.Security security = ScoutEngine.parseSecurity(raw);
            assertFalse(String.valueOf(raw), security.known);
            assertFalse(String.valueOf(raw), security.protocols.contains("OPEN"));
            assertNull(ScoutEngine.evaluate(Collections.singletonList(observation(raw)), allow("Venue"), true).candidate);
        }
    }

    @Test public void explicitInfrastructureWithoutSecurityIsOpen() {
        ScoutEngine.Security security = ScoutEngine.parseSecurity("[ESS][WPS]");
        assertTrue(security.known);
        assertEquals(Collections.singletonList("OPEN"), security.protocols);
        ScoutEngine.Result result = ScoutEngine.evaluate(Collections.singletonList(observation("[ESS]")), allow("Venue"), true);
        assertNotNull(result.candidate);
        assertTrue(has(result.groups.get(0), "SECURITY_OPEN"));
        assertTrue(result.reasons.toString().contains("HTTPS"));
    }

    @Test public void malformedProtectedMetadataDoesNotBecomeUsable() {
        for (String raw : Arrays.asList("[WPA2-PSK-CCMP][ESS]garbage", "[WPA2-PSK-CCMP][ESS", "[WPA2-PSK-CCMP][]", "WPA2", "[WPA2-PSK-NONE][ESS]", "[WPA3-PSK-CCMP][ESS]")) {
            assertFalse(raw, ScoutEngine.parseSecurity(raw).known);
            assertNull(raw, ScoutEngine.evaluate(Collections.singletonList(observation(raw)), allow("Venue"), true).candidate);
        }
    }

    @Test public void saeAndPskTransitionAreNotMistakenForWpa3Only() {
        ScoutEngine.Security pure = ScoutEngine.parseSecurity("[RSN-SAE-CCMP][ESS]");
        ScoutEngine.Security transition = ScoutEngine.parseSecurity("[RSN-PSK+SAE-CCMP][ESS]");
        assertTrue(pure.known);
        assertEquals(4, pure.rank);
        assertEquals(allow("WPA2", "WPA3"), new HashSet<>(transition.protocols));
        assertEquals(3, transition.rank);
        assertEquals(allow("PSK", "SAE"), new HashSet<>(transition.authentication));
    }

    @Test public void enterpriseAndSuiteBRemainDistinct() {
        ScoutEngine.Security ordinary = ScoutEngine.parseSecurity("[RSN-EAP/SHA1+EAP/SHA256-CCMP][ESS]");
        ScoutEngine.Security suite = ScoutEngine.parseSecurity("[RSN-EAP_SUITE_B_192-GCMP-256][ESS]");
        assertTrue(ordinary.known);
        assertEquals(Collections.singletonList("WPA2"), ordinary.protocols);
        assertTrue(suite.known);
        assertEquals(Collections.singletonList("WPA3"), suite.protocols);
        assertEquals(Collections.singletonList("EAP"), suite.authentication);
    }

    @Test public void fastTransitionUsesItsBaseAuthentication() {
        ScoutEngine.Security security = ScoutEngine.parseSecurity("[RSN-FT/PSK+PSK-CCMP][ESS]");
        assertTrue(security.known);
        assertEquals(Collections.singletonList("PSK"), security.authentication);
        assertEquals(Collections.singletonList("WPA2"), security.protocols);
    }

    @Test public void androidPskSha256SpellingRemainsRecognized() {
        ScoutEngine.Security security = ScoutEngine.parseSecurity("[WPA2-PSK-SHA256-CCMP][RSN-PSK-SHA256-CCMP][ESS]");
        assertTrue(security.known);
        assertEquals(Collections.singletonList("WPA2"), security.protocols);
        assertEquals(Collections.singletonList("PSK"), security.authentication);
    }

    @Test public void oweTransitionDoesNotHideOpenPossibility() {
        assertEquals(2, ScoutEngine.parseSecurity("[RSN-OWE-CCMP][ESS]").rank);
        for (String caps : Arrays.asList("[OWE_TRANSITION][ESS]", "[RSN-OWE_TRANSITION-CCMP][ESS]")) {
            ScoutEngine.Security security = ScoutEngine.parseSecurity(caps);
            assertTrue(caps, security.known);
            assertEquals(1, security.rank);
            assertEquals(allow("OPEN", "OWE"), new HashSet<>(security.protocols));
        }
    }

    @Test public void legacyIncludingMixedCipherAdvertisementsIsExcluded() {
        for (String caps : Arrays.asList("[WEP][ESS]", "[WPA-PSK-TKIP][ESS]", "[WPA2-PSK-CCMP+TKIP][ESS]", "[WPA2-PSK-TKIP][RSN-SAE-CCMP][ESS]")) {
            ScoutEngine.Result result = ScoutEngine.evaluate(Collections.singletonList(observation(caps)), allow("Venue"), true);
            assertEquals(caps, 0, ScoutEngine.parseSecurity(caps).rank);
            assertNull(caps, result.candidate);
        }
    }

    @Test public void sameNameDifferentProtectionBlocksBothCandidates() {
        List<ScoutEngine.Observation> observations = Arrays.asList(observation(WPA2), observation("Venue", "02:00:00:00:00:02", "[ESS]", -35, 0));
        ScoutEngine.Result result = ScoutEngine.evaluate(observations, allow("Venue"), true);
        assertNull(result.candidate);
        assertEquals(1, result.groups.size());
        assertTrue(result.groups.get(0).conflicted);
        assertTrue(has(result.groups.get(0), "SECURITY_CONFLICT"));
        assertTrue(result.groups.get(0).findings.stream().anyMatch(f -> f.id.equals("SECURITY_CONFLICT") && f.explanation.contains("Reconfiguration")));
    }

    @Test public void knownAuthenticationConflictAlsoBlocks() {
        List<ScoutEngine.Observation> observations = Arrays.asList(observation(WPA2), observation("Venue", "02:00:00:00:00:02", "[WPA2-EAP-CCMP][ESS]", -55, 0));
        assertTrue(ScoutEngine.evaluate(observations, allow("Venue"), true).groups.get(0).conflicted);
    }

    @Test public void unknownNeighborIsNotAssumedToConflict() {
        List<ScoutEngine.Observation> observations = Arrays.asList(observation(WPA2), observation("Venue", "02:00:00:00:00:02", null, -55, 0));
        ScoutEngine.Result result = ScoutEngine.evaluate(observations, allow("Venue"), true);
        assertNotNull(result.candidate);
        assertFalse(result.groups.get(0).conflicted);
        assertTrue(has(result.groups.get(0), "SECURITY_UNKNOWN"));
        assertTrue(has(result.groups.get(0), "MULTIPLE_ACCESS_POINTS"));
    }

    @Test public void strongerPrivateNetworkIsNotAJoinCandidate() {
        List<ScoutEngine.Observation> observations = Arrays.asList(observation(WPA2), observation("Private", "02:00:00:00:00:02", "[RSN-SAE-CCMP][ESS]", -30, 0));
        ScoutEngine.Result result = ScoutEngine.evaluate(observations, allow("Venue"), true);
        assertEquals("Venue", result.candidate.ssid);
        assertFalse(result.groups.get(1).authorized);
        assertFalse(result.groups.get(1).eligible);
    }

    @Test public void noAuthorizationMeansNoRecommendation() {
        ScoutEngine.Result result = ScoutEngine.evaluate(Collections.singletonList(observation(WPA2)), Collections.emptySet(), true);
        assertNull(result.candidate);
        assertTrue(result.recommendationExplanation.contains("allowed"));
    }

    @Test public void staleBatchCannotRecommendEvenWhenPerApAgeIsYoung() {
        ScoutEngine.Result result = ScoutEngine.evaluate(Collections.singletonList(observation(WPA2)), allow("Venue"), false);
        assertNull(result.candidate);
        assertFalse(result.fresh);
        assertFalse(result.groups.get(0).eligible);
    }

    @Test public void observationAgeBoundaryAndUnknownTimingAreRespected() {
        for (long age : new long[]{-1, 30001, Long.MAX_VALUE}) {
            assertNull(ScoutEngine.evaluate(Collections.singletonList(observation("Venue", "02:00:00:00:00:01", WPA2, -55, age)), allow("Venue"), true).candidate);
        }
        assertNotNull(ScoutEngine.evaluate(Collections.singletonList(observation("Venue", "02:00:00:00:00:01", WPA2, -55, 30000)), allow("Venue"), true).candidate);
    }

    @Test public void oldApDoesNotBeatCurrentAp() {
        List<ScoutEngine.Observation> observations = Arrays.asList(observation("Venue", "02:00:00:00:00:01", WPA2, -30, 60000), observation("Venue", "02:00:00:00:00:02", WPA2, -65, 10));
        assertEquals("02:00:00:00:00:02", ScoutEngine.evaluate(observations, allow("Venue"), true).candidate.bssid);
    }

    @Test public void weakAndUnavailableSignalCannotRecommend() {
        for (Integer dbm : Arrays.asList(null, -128, -76, 0, 3)) {
            assertNull(ScoutEngine.evaluate(Collections.singletonList(new ScoutEngine.Observation("Venue", "02:00:00:00:00:01", dbm, 5180, WPA2, 0)), allow("Venue"), true).candidate);
        }
        assertNotNull(ScoutEngine.evaluate(Collections.singletonList(observation("Venue", "02:00:00:00:00:01", WPA2, -75, 0)), allow("Venue"), true).candidate);
    }

    @Test public void equivalentSignalTierUsesStableAddressRatherThanRawDbm() {
        List<ScoutEngine.Observation> observations = Arrays.asList(observation("Venue", "02:00:00:00:00:02", WPA2, -30, 0), observation("Venue", "02:00:00:00:00:01", WPA2, -59, 0));
        assertEquals("02:00:00:00:00:01", ScoutEngine.evaluate(observations, allow("Venue"), true).candidate.bssid);
    }

    @Test public void authorizedBetterProtectionWinsBeforeSignalTier() {
        List<ScoutEngine.Observation> observations = Arrays.asList(observation("Open", "02:00:00:00:00:01", "[ESS]", -30, 0), observation("Protected", "02:00:00:00:00:02", WPA2, -70, 0));
        assertEquals("Protected", ScoutEngine.evaluate(observations, allow("Open", "Protected"), true).candidate.ssid);
    }

    @Test public void redactedOrMissingAddressesCannotRecommend() {
        for (String bssid : Arrays.asList(null, "", "unknown", "02:00:00:00:00:00", "00:00:00:00:00:00", "FF:FF:FF:FF:FF:FF", "01:00:00:00:00:01")) {
            assertNull(ScoutEngine.evaluate(Collections.singletonList(observation("Venue", bssid, WPA2, -55, 0)), allow("Venue"), true).candidate);
        }
    }

    @Test public void exactNamesRemainSeparateAndHiddenNamesNeverMerge() {
        List<ScoutEngine.Observation> observations = Arrays.asList(observation("Cafe", "02:00:00:00:00:01", WPA2, -55, 0), observation("cafe", "02:00:00:00:00:02", WPA2, -55, 0), observation(null, "02:00:00:00:00:03", WPA2, -55, 0), observation("", "02:00:00:00:00:04", WPA2, -55, 0));
        ScoutEngine.Result result = ScoutEngine.evaluate(observations, allow("Cafe", "", "CAFE"), true);
        assertEquals(4, result.groups.size());
        assertEquals("Cafe", result.candidate.ssid);
        assertFalse(result.groups.get(1).authorized);
        assertFalse(result.groups.get(2).authorized);
        assertFalse(result.groups.get(3).authorized);
    }

    @Test public void hostileNamesAreDataAndControlsAreEscapedOnlyForDisplay() {
        String name = "<img src=x onerror=alert(1)>\n\u202eFake";
        ScoutEngine.Observation observation = observation(name, "02:00:00:00:00:01", WPA2, -55, 0);
        ScoutEngine.Result result = ScoutEngine.evaluate(Collections.singletonList(observation), allow(name), true);
        assertEquals(name, result.candidate.ssid);
        assertEquals(name, result.groups.get(0).ssid);
        assertTrue(ScoutEngine.displayName(name).contains("\\u000a\\u202e"));
        assertNull(ScoutEngine.evaluate(Collections.singletonList(observation), allow(ScoutEngine.displayName(name)), true).candidate);
    }

    @Test public void resultsDoNotRetainMutableInputs() {
        List<ScoutEngine.Observation> input = new ArrayList<>(Collections.singletonList(observation(WPA2)));
        ScoutEngine.Result result = ScoutEngine.evaluate(input, allow("Venue"), true);
        input.clear();
        assertEquals(1, result.groups.get(0).observations.size());
        try { result.groups.clear(); fail("Expected immutable groups"); } catch (UnsupportedOperationException expected) {}
        try { result.groups.get(0).findings.clear(); fail("Expected immutable findings"); } catch (UnsupportedOperationException expected) {}
    }

    @Test public void explicitDemoExercisesBothRecommendationOutcomes() {
        ScoutEngine.Result airport = ScoutEngine.evaluate(ScoutEngine.demo(), allow("Airport Guest"), true);
        ScoutEngine.Result cafe = ScoutEngine.evaluate(ScoutEngine.demo(), allow("Juniper Café"), true);
        assertNull(airport.candidate);
        assertEquals("Juniper Café", cafe.candidate.ssid);
        assertEquals("Best observed candidate", cafe.recommendationTitle);
        assertTrue(cafe.limitations.toString().contains("cannot confirm"));
    }

    @Test public void channelsHandleSpecialCasesWithoutInventingUnknownValues() {
        assertEquals(Integer.valueOf(1), ScoutEngine.channel(2412));
        assertEquals(Integer.valueOf(14), ScoutEngine.channel(2484));
        assertEquals(Integer.valueOf(36), ScoutEngine.channel(5180));
        assertEquals(Integer.valueOf(2), ScoutEngine.channel(5935));
        assertEquals(Integer.valueOf(5), ScoutEngine.channel(5975));
        assertNull(ScoutEngine.channel(1234));
        assertEquals("6 GHz", ScoutEngine.bandLabel(5975));
    }
}
