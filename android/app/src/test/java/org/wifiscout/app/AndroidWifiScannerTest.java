package org.wifiscout.app;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import org.junit.Test;
import org.wifiscout.app.core.ScoutEngine;

/** Pure timing checks; these do not claim to exercise Android radios or permissions. */
public final class AndroidWifiScannerTest {
    @Test public void missingAndFutureTimesRemainUnknown() {
        assertEquals(-1, AndroidWifiScanner.observationAgeMillis(0, 8_000_000));
        assertEquals(-1, AndroidWifiScanner.observationAgeMillis(-1, 8_000_000));
        assertEquals(-1, AndroidWifiScanner.observationAgeMillis(8_000_001, 8_000_000));
        assertEquals(-1, AndroidWifiScanner.observationAgeMillis(1, -1));
    }

    @Test public void microsecondsBecomeMillisecondsWithoutTreatingThemAsUnixTime() {
        assertEquals(0, AndroidWifiScanner.observationAgeMillis(8_000_000, 8_000_000));
        assertEquals(1, AndroidWifiScanner.observationAgeMillis(7_999_999, 8_000_000));
        assertEquals(1_501, AndroidWifiScanner.observationAgeMillis(6_499_999, 8_000_000));
        assertEquals(-1, AndroidWifiScanner.observationAgeMillis(1_700_000_000_000_000L, 8_000_000));
    }

    @Test public void oneMicrosecondPastFreshnessLimitCannotRoundBackIntoEligibility() {
        long now = 100_000_000L;
        long boundary = now - ScoutEngine.MAX_OBSERVATION_AGE_MS * 1_000L;
        assertEquals(ScoutEngine.MAX_OBSERVATION_AGE_MS,
                AndroidWifiScanner.observationAgeMillis(boundary, now));
        assertTrue(AndroidWifiScanner.observationAgeMillis(boundary - 1, now)
                > ScoutEngine.MAX_OBSERVATION_AGE_MS);
    }

    @Test public void ceilingCalculationDoesNotOverflowOnLargeValidElapsedValues() {
        long difference = Long.MAX_VALUE - 1;
        assertEquals(difference / 1_000L + 1,
                AndroidWifiScanner.observationAgeMillis(1, Long.MAX_VALUE));
    }
}
