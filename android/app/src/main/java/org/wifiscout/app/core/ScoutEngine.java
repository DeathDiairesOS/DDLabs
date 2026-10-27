package org.wifiscout.app.core;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Offline interpretation of ordinary Android Wi-Fi observations. No network operations. */
public final class ScoutEngine {
    private ScoutEngine() {}

    /** A usability freshness policy, not an attack-detection threshold. */
    public static final long MAX_OBSERVATION_AGE_MS = 30_000L;
    private static final Pattern BLOCK = Pattern.compile("\\[([^\\[\\]]+)\\]");
    private static final Pattern ADDRESS = Pattern.compile("(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}");
    private static final String CIPHER = "(?:CCMP-256|GCMP-256|CCMP|GCMP|TKIP|WEP-104|WEP-40|WEP|NONE)";
    private static final Pattern PROTECTED = Pattern.compile("^(WPA2|WPA3|WPA|RSN)-([A-Z0-9_+/-]+)-(" + CIPHER + "(?:\\+" + CIPHER + ")*)$");
    private static final Set<String> AUXILIARY = set("ESS", "IBSS", "WPS", "WPS-PBC", "WPS-PIN", "UTF-8", "MFPC", "MFPR", "P2P");

    public static final class Observation {
        public final String ssid;
        public final String bssid;
        public final Integer signalDbm;
        public final Integer frequencyMhz;
        public final String capabilities;
        /** Android's monotonic observation age; -1 denotes missing or invalid timing. */
        public final long ageMillis;

        public Observation(String ssid, String bssid, Integer signalDbm, Integer frequencyMhz,
                           String capabilities, long ageMillis) {
            this.ssid = ssid;
            this.bssid = bssid;
            this.signalDbm = signalDbm;
            this.frequencyMhz = frequencyMhz;
            this.capabilities = capabilities;
            this.ageMillis = ageMillis;
        }
    }

    public static final class Security {
        public final List<String> protocols;
        public final List<String> authentication;
        public final List<String> ciphers;
        public final boolean known;
        public final int rank;
        public final String label;

        private Security(Set<String> protocols, Set<String> authentication, Set<String> ciphers,
                         boolean known) {
            this.protocols = immutable(protocols);
            this.authentication = immutable(authentication);
            this.ciphers = immutable(ciphers);
            this.known = known && !protocols.isEmpty();
            boolean legacy = protocols.contains("WEP") || protocols.contains("WPA") || legacyCipher(ciphers);
            if (legacy) {
                rank = 0;
                label = "Legacy wireless protection advertised";
            } else if (!this.known) {
                rank = -1;
                label = "Unknown or incomplete security";
            } else if (protocols.contains("OPEN")) {
                rank = 1;
                label = protocols.contains("OWE") ? "Open / Enhanced Open transition advertised" : "Open wireless link";
            } else if (protocols.equals(set("OWE"))) {
                rank = 2;
                label = "Enhanced Open (OWE) advertised";
            } else if (protocols.equals(set("WPA3"))) {
                rank = 4;
                label = "WPA3 advertised";
            } else if (protocols.contains("WPA2")) {
                rank = 3;
                label = protocols.contains("WPA3") ? "WPA2 / WPA3 transition advertised" : "WPA2 advertised";
            } else {
                rank = -1;
                label = "Unknown or incomplete security";
            }
        }
    }

    public static final class Finding {
        public final String id;
        public final String severity;
        public final String title;
        public final String explanation;

        private Finding(String id, String severity, String title, String explanation) {
            this.id = id;
            this.severity = severity;
            this.title = title;
            this.explanation = explanation;
        }
    }

    public static final class Group {
        public final String id;
        public final String ssid;
        public final String securityLabel;
        public final String signalLabel;
        public final String identityLabel = "Who runs it: not confirmed";
        public final List<Observation> observations;
        public final List<Finding> findings;
        public final boolean authorized;
        public final boolean conflicted;
        public final boolean eligible;

        private Group(String id, String ssid, List<Observation> observations, List<Finding> findings,
                      boolean authorized, boolean conflicted, boolean eligible) {
            this.id = id;
            this.ssid = ssid;
            this.observations = immutable(observations);
            this.findings = immutable(findings);
            this.authorized = authorized;
            this.conflicted = conflicted;
            this.eligible = eligible;
            Set<String> securityLabels = new LinkedHashSet<>();
            Set<String> signalLabels = new LinkedHashSet<>();
            for (Observation observation : observations) {
                Security security = parseSecurity(observation.capabilities);
                securityLabels.add(plainSecurityLabel(security));
                signalLabels.add(ScoutEngine.signalLabel(observation.signalDbm));
            }
            securityLabel = conflicted ? "Settings differ" : securityLabels.size() == 1
                    ? securityLabels.iterator().next() : "Some details unavailable";
            signalLabel = signalLabels.size() == 1 ? signalLabels.iterator().next() : "Mixed signal strengths";
        }
    }

    public static final class Result {
        public final List<Group> groups;
        public final Observation candidate;
        public final boolean fresh;
        public final String recommendationTitle;
        public final String recommendationExplanation;
        public final List<String> reasons;
        public final List<String> limitations;

        private Result(List<Group> groups, Observation candidate, boolean fresh, String explanation,
                       List<String> reasons) {
            this.groups = immutable(groups);
            this.candidate = candidate;
            this.fresh = fresh;
            recommendationTitle = candidate == null ? "Cannot confidently recommend" : "Best observed candidate";
            recommendationExplanation = explanation;
            this.reasons = immutable(reasons);
            limitations = immutable(Arrays.asList(
                    "A scan cannot confirm who runs a network. Names and advertised settings can be copied.",
                    "Signal strength does not measure internet speed, congestion, or reliability.",
                    "Ordinary phone scans cannot observe deauthentication traffic or verify a sign-in page.",
                    "The phone may return cached or incomplete observations. Recommendations require a successful scan and observations no older than 30 seconds.",
                    "WiFi Scout never joins automatically. Confirm the network with the venue, then use Android Wi-Fi settings."
            ));
        }
    }

    /**
     * Parse Android's bracketed capabilities conservatively. Unknown authentication,
     * malformed blocks or unfamiliar security flags never become an open network.
     * This interprets advertisements; it does not validate the negotiated connection.
     */
    public static Security parseSecurity(String raw) {
        Set<String> protocols = new LinkedHashSet<>();
        Set<String> authentication = new LinkedHashSet<>();
        Set<String> ciphers = new LinkedHashSet<>();
        if (raw == null || raw.trim().isEmpty()) return new Security(protocols, authentication, ciphers, false);
        String text = raw.trim().toUpperCase(Locale.ROOT);
        Matcher blocks = BLOCK.matcher(text);
        boolean understood = true;
        boolean hasEss = false;
        boolean securitySeen = false;
        int end = 0;
        while (blocks.find()) {
            if (blocks.start() != end) understood = false;
            end = blocks.end();
            String block = blocks.group(1);
            if ("ESS".equals(block)) hasEss = true;
            if (AUXILIARY.contains(block)) continue;
            securitySeen = true;
            if ("WEP".equals(block)) {
                protocols.add("WEP");
                continue;
            }
            if ("OWE_TRANSITION".equals(block)) {
                protocols.add("OPEN");
                protocols.add("OWE");
                authentication.add("NONE");
                authentication.add("OWE");
                continue;
            }
            Matcher protectedBlock = PROTECTED.matcher(block);
            if (!protectedBlock.matches()) {
                understood = false;
                continue;
            }
            String family = protectedBlock.group(1);
            String[] methods = protectedBlock.group(2).split("\\+", -1);
            for (String cipher : protectedBlock.group(3).split("\\+")) {
                ciphers.add(cipher);
                if ("NONE".equals(cipher)) understood = false;
            }
            for (String method : methods) {
                String auth;
                String protocol;
                if (set("PSK", "FT/PSK", "PSK-SHA256", "PSK/SHA256").contains(method)) {
                    auth = "PSK";
                    protocol = "WPA2";
                } else if (set("SAE", "FT/SAE").contains(method)) {
                    auth = "SAE";
                    protocol = "WPA3";
                } else if (set("EAP", "FT/EAP", "EAP/SHA1", "EAP/SHA256").contains(method)) {
                    auth = "EAP";
                    protocol = "WPA3".equals(family) ? "WPA3" : "WPA2";
                } else if (set("EAP_SUITE_B_192", "EAP-SUITE-B-192", "SUITE_B_192").contains(method)) {
                    auth = "EAP";
                    protocol = "WPA3";
                } else if ("OWE".equals(method)) {
                    auth = "OWE";
                    protocol = "OWE";
                } else if ("OWE_TRANSITION".equals(method)) {
                    auth = "OWE";
                    protocol = "OWE";
                    protocols.add("OPEN");
                    authentication.add("NONE");
                } else {
                    understood = false;
                    continue;
                }
                if ("WPA".equals(family)) {
                    if (!"PSK".equals(auth) && !"EAP".equals(auth)) understood = false;
                    protocol = "WPA";
                } else if ("WPA3".equals(family) && !"WPA3".equals(protocol)) {
                    // A contradictory family/authentication claim is not usable evidence.
                    understood = false;
                }
                authentication.add(auth);
                protocols.add(protocol);
            }
        }
        if (end != text.length()) understood = false;
        if (!securitySeen && understood && hasEss) {
            protocols.add("OPEN");
            authentication.add("NONE");
        }
        return new Security(protocols, authentication, ciphers, understood);
    }

    public static Result evaluate(List<Observation> input, Set<String> allowedSsids, boolean fresh) {
        List<Observation> observations = input == null ? Collections.emptyList() : new ArrayList<>(input);
        Set<String> allowed = allowedSsids == null ? Collections.emptySet() : new LinkedHashSet<>(allowedSsids);
        Map<String, List<Observation>> grouped = new LinkedHashMap<>();
        int hidden = 0;
        for (Observation observation : observations) {
            if (observation == null) continue;
            String key = hasName(observation.ssid) ? "name:" + observation.ssid : "hidden:" + hidden++;
            if (!grouped.containsKey(key)) grouped.put(key, new ArrayList<>());
            grouped.get(key).add(observation);
        }
        List<Group> groups = new ArrayList<>();
        List<Observation> candidates = new ArrayList<>();
        for (Map.Entry<String, List<Observation>> entry : grouped.entrySet()) {
            List<Observation> members = entry.getValue();
            String ssid = members.get(0).ssid;
            boolean authorized = hasName(ssid) && allowed.contains(ssid);
            LinkedHashMap<String, Finding> findings = new LinkedHashMap<>();
            boolean conflict = false;
            Set<String> addresses = new LinkedHashSet<>();
            for (int i = 0; i < members.size(); i++) {
                Observation observation = members.get(i);
                Security security = parseSecurity(observation.capabilities);
                if (validBssid(observation.bssid)) addresses.add(observation.bssid.toLowerCase(Locale.ROOT));
                addSecurityFindings(findings, security);
                if (!isCurrent(observation)) add(findings, "OBSERVATION_STALE", "info", "A fresh reading is needed",
                        "This access-point reading is older than 30 seconds or has unknown timing. Scan again before relying on it.");
                for (int j = i + 1; j < members.size(); j++) {
                    if (securityDiffers(security, parseSecurity(members.get(j).capabilities))) conflict = true;
                }
            }
            if (conflict) add(findings, "SECURITY_CONFLICT", "medium", "Same name, different protection",
                    "Access points with this name advertise different settings. Reconfiguration, unrelated operators, or copying the name can explain it. Ask the venue what to expect; this scan cannot identify the cause.");
            else if (addresses.size() > 1) add(findings, "MULTIPLE_ACCESS_POINTS", "info", "Several access points share this name",
                    "This is normal for larger venues and mesh networks. A shared name does not prove shared ownership, and unavailable settings remain unknown.");
            boolean eligible = false;
            for (Observation observation : members) {
                Security security = parseSecurity(observation.capabilities);
                if (fresh && authorized && !conflict && security.known && security.rank >= 1
                        && signalTier(observation.signalDbm) >= 1 && validBssid(observation.bssid)
                        && isCurrent(observation)) {
                    candidates.add(observation);
                    eligible = true;
                }
            }
            groups.add(new Group(entry.getKey(), ssid, members, new ArrayList<>(findings.values()), authorized, conflict, eligible));
        }
        candidates.sort(Comparator
                .comparingInt((Observation item) -> parseSecurity(item.capabilities).rank).reversed()
                .thenComparing(Comparator.comparingInt((Observation item) -> signalTier(item.signalDbm)).reversed())
                .thenComparing(item -> item.ssid)
                .thenComparing(item -> item.bssid.toLowerCase(Locale.ROOT)));
        Observation candidate = candidates.isEmpty() ? null : candidates.get(0);
        List<String> reasons = new ArrayList<>();
        String explanation;
        if (!fresh) {
            explanation = "A new scan is needed before comparing options. Older observations may still be shown below.";
            reasons.add("The latest scan was not confirmed fresh. Wait and try again.");
        } else if (groups.isEmpty()) {
            explanation = "No nearby Wi-Fi was observed. Check Wi-Fi and scan again.";
            reasons.add("An empty scan does not prove there are no nearby access points.");
        } else if (allowed.isEmpty()) {
            explanation = "First confirm which networks you are allowed to use and have the sign-in details for.";
            reasons.add("Seeing a network does not grant permission to join it.");
        } else if (candidate == null) {
            explanation = "The networks you selected need clearer or fresher evidence. Ask staff about the expected settings, or use your own hotspot.";
            reasons.add("Weak reception, missing information, old protection, or conflicting settings can withhold a recommendation.");
        } else {
            explanation = "An option to consider among the Wi-Fi you said you can use. Confirm the name and sign-in instructions with staff.";
            reasons.add("You confirmed permission and access to this network.");
            reasons.add(parseSecurity(candidate.capabilities).label + "; " + signalLabel(candidate.signalDbm).toLowerCase(Locale.ROOT) + " in this observation.");
            reasons.add("Compared advertised protection, then broad signal strength. Neither establishes operator trust or internet speed.");
            if (candidates.size() == 1) reasons.add("Only one access point had enough eligible evidence, so this is a limited comparison.");
            if (parseSecurity(candidate.capabilities).protocols.contains("OPEN")) reasons.add("An open connection has no wireless-link encryption. Correctly secured HTTPS websites still protect their content.");
        }
        return new Result(groups, candidate, fresh, explanation, reasons);
    }

    private static void addSecurityFindings(Map<String, Finding> findings, Security security) {
        if (!security.known) add(findings, "SECURITY_UNKNOWN", "info", "Some protection details are unavailable",
                "The phone did not provide security settings this version can interpret. Missing information does not mean an attack.");
        if (security.protocols.contains("WEP") || security.protocols.contains("WPA")) add(findings, "SECURITY_LEGACY", "high", "Older protection needs attention",
                "WEP and original WPA are outdated. Prefer another network you can use, or your own hotspot. This setting does not establish malicious intent.");
        if (legacyCipher(security.ciphers)) add(findings, "SECURITY_LEGACY_CIPHER", "high", "Outdated encryption is advertised",
                "TKIP or WEP encryption is advertised, including alongside newer settings. The scan cannot establish what your phone would negotiate.");
        if (security.protocols.contains("OPEN")) add(findings, "SECURITY_OPEN", "medium", "An open connection is advertised",
                "The open connection does not encrypt the Wi-Fi link. HTTPS still protects correctly secured website content. A sign-in page does not itself add Wi-Fi encryption.");
        if (security.protocols.contains("OWE")) add(findings, "SECURITY_OWE", "info", "Enhanced Open is advertised",
                "OWE can encrypt the Wi-Fi link without a password. It does not verify the operator; transition mode can also offer an open connection.");
        if (security.known && security.rank >= 3) add(findings, "SECURITY_MODERN", "info", "Modern protection is advertised",
                "WPA2 or WPA3 protects the wireless link when correctly negotiated. It does not establish who operates the network.");
    }

    private static boolean securityDiffers(Security a, Security b) {
        if (a.known && b.known && !new LinkedHashSet<>(a.protocols).equals(new LinkedHashSet<>(b.protocols))) return true;
        if (!a.authentication.isEmpty() && !b.authentication.isEmpty()
                && !new LinkedHashSet<>(a.authentication).equals(new LinkedHashSet<>(b.authentication))) return true;
        return !a.ciphers.isEmpty() && !b.ciphers.isEmpty()
                && !new LinkedHashSet<>(a.ciphers).equals(new LinkedHashSet<>(b.ciphers));
    }

    private static boolean legacyCipher(Iterable<String> ciphers) {
        for (String cipher : ciphers) if ("TKIP".equals(cipher) || cipher.startsWith("WEP")) return true;
        return false;
    }

    private static boolean isCurrent(Observation observation) {
        return observation.ageMillis >= 0 && observation.ageMillis <= MAX_OBSERVATION_AGE_MS;
    }

    private static boolean hasName(String name) {
        return name != null && !name.isEmpty() && !"<unknown ssid>".equalsIgnoreCase(name);
    }

    private static boolean validBssid(String value) {
        return value != null && ADDRESS.matcher(value).matches()
                && (Integer.parseInt(value.substring(0, 2), 16) & 1) == 0
                && !"00:00:00:00:00:00".equals(value)
                && !"ff:ff:ff:ff:ff:ff".equalsIgnoreCase(value)
                && !"02:00:00:00:00:00".equals(value);
    }

    private static String plainSecurityLabel(Security security) {
        if (security.rank == 0) return "Older protection";
        if (!security.known) return "Unknown / incomplete";
        if (security.protocols.contains("OPEN")) return "Open connection advertised";
        if (security.protocols.contains("OWE")) return "Encrypted, without a password";
        return "Encryption advertised";
    }

    private static int signalTier(Integer value) {
        if (value == null || value < -127 || value >= 0) return -1;
        return value >= -60 ? 2 : value >= -75 ? 1 : 0;
    }

    public static String signalLabel(Integer value) {
        switch (signalTier(value)) {
            case 2: return "Strong signal";
            case 1: return "Moderate signal";
            case 0: return "Weak signal";
            default: return "Unknown signal";
        }
    }

    public static String bandLabel(Integer frequency) {
        if (frequency == null) return "Unknown";
        if (frequency >= 2400 && frequency <= 2500) return "2.4 GHz";
        if (frequency >= 4900 && frequency < 5925) return "5 GHz";
        if (frequency >= 5925 && frequency <= 7125) return "6 GHz";
        if (frequency >= 57000 && frequency <= 71000) return "60 GHz";
        return "Unknown";
    }

    public static Integer channel(Integer frequency) {
        if (frequency == null) return null;
        if (frequency == 2484) return 14;
        if (frequency >= 2412 && frequency <= 2472 && (frequency - 2407) % 5 == 0) return (frequency - 2407) / 5;
        if (frequency >= 4910 && frequency <= 4980 && frequency % 5 == 0) return (frequency - 4000) / 5;
        if (frequency >= 5000 && frequency <= 5895 && frequency % 5 == 0) return (frequency - 5000) / 5;
        if (frequency == 5935) return 2;
        if (frequency >= 5955 && frequency <= 7115 && (frequency - 5950) % 5 == 0) return (frequency - 5950) / 5;
        return null;
    }

    /** For visible labels only. Grouping and authorization always use the original SSID. */
    public static String displayName(String ssid) {
        if (!hasName(ssid)) return "Unnamed Wi-Fi";
        StringBuilder safe = new StringBuilder();
        for (int i = 0; i < ssid.length(); i++) {
            char c = ssid.charAt(i);
            if (Character.isISOControl(c) || Character.getType(c) == Character.FORMAT) {
                safe.append(String.format(Locale.ROOT, "\\u%04x", (int) c));
            } else safe.append(c);
        }
        return safe.toString();
    }

    /** Invented examples for an explicit, clearly labeled demo mode only. */
    public static List<Observation> demo() {
        return immutable(Arrays.asList(
                new Observation("Airport Guest", "02:aa:00:00:00:01", -49, 2412, "[WPA2-PSK-CCMP][ESS]", 0),
                new Observation("Airport Guest", "02:aa:00:00:00:02", -39, 2462, "[ESS]", 0),
                new Observation("Juniper Café", "02:11:22:33:44:01", -54, 5180, "[WPA2-PSK-CCMP][ESS]", 0),
                new Observation("Juniper Café", "02:11:22:33:44:02", -69, 2437, "[WPA2-PSK-CCMP][ESS]", 0),
                new Observation("Airport Staff", "02:ff:00:00:00:01", -38, 5975, "[RSN-SAE-CCMP][ESS]", 0),
                new Observation("Lounge Guest", "02:cc:00:00:00:01", -61, 5220, null, 0),
                new Observation("Old Printer", "02:dd:00:00:00:01", -66, 2437, "[WEP][ESS]", 0)
        ));
    }

    private static void add(Map<String, Finding> findings, String id, String severity, String title, String explanation) {
        if (!findings.containsKey(id)) findings.put(id, new Finding(id, severity, title, explanation));
    }

    private static Set<String> set(String... values) {
        return new LinkedHashSet<>(Arrays.asList(values));
    }

    private static <T> List<T> immutable(Iterable<T> source) {
        List<T> copy = new ArrayList<>();
        for (T item : source) copy.add(item);
        return Collections.unmodifiableList(copy);
    }
}
