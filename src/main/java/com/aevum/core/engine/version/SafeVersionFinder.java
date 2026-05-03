package com.aevum.core.engine.version;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Finds the minimum safe version for a vulnerable artifact.
 *
 * FIX 1 (upstream): Was not a {@code @Component}.  Now Spring-managed.
 *
 * FIX 2: {@code KNOWN_SAFE_VERSIONS} had a wrong groupId entry:
 *   {@code "commons-text:commons-text:1.9"} → should be {@code "org.apache.commons:commons-text:1.9"}.
 *   Without this fix, Text4Shell (CVE-2022-42889) would not find a safe version via the offline
 *   fallback and FixEngine would silently generate no fix for it.
 *
 * FIX 3: Added {@code findFromSignalSafeVersions()} as the <em>primary</em> lookup path.
 *   The scanner payload already carries {@code safeVersions} (e.g. ["2.17.1"]).
 *   Using the scanner-supplied list is more reliable than fetching Maven Central
 *   (network) or the offline map (incomplete).  The pipeline should use
 *   {@code safeVersions.get(0)} — the minimum safe version — as the proposed fix.
 *
 * Priority order (highest to lowest):
 *   1. Signal's own {@code safeVersions} list (caller-supplied, most authoritative)
 *   2. Maven Central metadata (live network query)
 *   3. Offline {@code KNOWN_SAFE_VERSIONS} fallback map (no network required)
 */
@Component
public class SafeVersionFinder {
    private static final Logger LOG = LoggerFactory.getLogger(SafeVersionFinder.class);

    /**
     * Offline fallback: known minimum safe versions for critical CVEs.
     *
     * Key   : {@code groupId:artifactId:vulnerableVersion}
     * Value : minimum safe version
     *
     * FIX: corrected {@code commons-text} groupId from {@code "commons-text"} to
     *      {@code "org.apache.commons"}.
     */
    private static final Map<String, String> KNOWN_SAFE_VERSIONS = Map.ofEntries(
            // Log4Shell
            Map.entry("org.apache.logging.log4j:log4j-core:2.14.1",  "2.17.1"),
            Map.entry("org.apache.logging.log4j:log4j-core:2.15.0",  "2.17.1"),
            Map.entry("org.apache.logging.log4j:log4j-core:2.16.0",  "2.17.1"),
            Map.entry("org.apache.logging.log4j:log4j-core:2.12.0",  "2.12.4"),
            Map.entry("org.apache.logging.log4j:log4j-core:2.13.0",  "2.17.1"),
            // Text4Shell — FIX: correct groupId
            Map.entry("org.apache.commons:commons-text:1.9",          "1.10.0"),
            Map.entry("org.apache.commons:commons-text:1.8",          "1.10.0"),
            // Bouncy Castle
            Map.entry("org.bouncycastle:bcprov-jdk18on:1.80",         "1.81"),
            // Tomcat
            Map.entry("org.apache.tomcat.embed:tomcat-embed-core:9.0.50",  "9.0.90"),
            Map.entry("org.apache.tomcat.embed:tomcat-embed-core:10.1.15", "10.1.25"),
            // Jackson
            Map.entry("com.fasterxml.jackson.core:jackson-databind:2.13.0", "2.13.5"),
            Map.entry("com.fasterxml.jackson.core:jackson-databind:2.9.10",  "2.12.0"),
            // Spring
            Map.entry("org.springframework:spring-core:5.3.20",                   "5.3.39"),
            Map.entry("org.springframework.security:spring-security-core:5.7.1",  "5.7.12"),
            // Struts
            Map.entry("org.apache.struts:struts2-core:2.5.28", "2.5.33"),
            // Commons IO
            Map.entry("commons-io:commons-io:2.6", "2.7"),
            // Spring Boot (Spring4Shell range)
            Map.entry("org.springframework.boot:spring-boot:2.3.4", "2.6.0")
    );

    private final MavenMetadataClient metadataClient;

    public SafeVersionFinder(MavenMetadataClient metadataClient) {
        this.metadataClient = metadataClient;
    }

    // ── Public result type ────────────────────────────────────────────────────

    public static final class SafeVersionResult {
        public final String currentVersion;
        public final boolean vulnerable;
        public final String minimumSafeVersion;
        public final String latestVersion;
        public final RecommendationType recommendationType;

        public SafeVersionResult(String currentVersion, boolean vulnerable,
                                 String minimumSafeVersion, String latestVersion,
                                 RecommendationType recommendationType) {
            this.currentVersion    = currentVersion;
            this.vulnerable        = vulnerable;
            this.minimumSafeVersion = minimumSafeVersion;
            this.latestVersion     = latestVersion;
            this.recommendationType = recommendationType;
        }

        public enum RecommendationType { MINIMAL, OPTIONAL }
    }

    // ── Primary API ───────────────────────────────────────────────────────────

    /**
     * Find the minimum safe version.
     *
     * <p><b>Preferred path</b> — call {@link #findFromSignalSafeVersions} when the
     * scanner payload already supplies a {@code safeVersions} list.  This avoids
     * any network call and is always reliable.
     *
     * @param groupId          Maven groupId of the vulnerable artifact
     * @param artifactId       Maven artifactId
     * @param reportedVersion  version the scanner flagged as vulnerable
     * @param affectedRange    Maven-style range e.g. {@code [2.0,2.15.0)} — may be null
     */
    public SafeVersionResult findMinimumSafe(String groupId,
                                             String artifactId,
                                             String reportedVersion,
                                             String affectedRange) throws IOException {
        // 1. No range → offline fallback only
        if (affectedRange == null || affectedRange.isBlank()) {
            String fallback = KNOWN_SAFE_VERSIONS.get(groupId + ":" + artifactId + ":" + reportedVersion);
            if (fallback != null) {
                LOG.info("Offline fallback safe version for {}:{} {} → {}",
                        groupId, artifactId, reportedVersion, fallback);
                return new SafeVersionResult(reportedVersion, true, fallback, fallback,
                        SafeVersionResult.RecommendationType.MINIMAL);
            }
            return new SafeVersionResult(reportedVersion, false, reportedVersion, null,
                    SafeVersionResult.RecommendationType.OPTIONAL);
        }

        // 2. Verify current version is actually in the affected range
        boolean currentlyVulnerable = VersionRangeEvaluator.isVersionInRange(reportedVersion, affectedRange);
        if (!currentlyVulnerable) {
            return new SafeVersionResult(reportedVersion, false, reportedVersion, null,
                    SafeVersionResult.RecommendationType.OPTIONAL);
        }

        // 3. Fetch from Maven Central with offline fallback on network failure
        List<String> all;
        try {
            all = metadataClient.fetchAvailableVersions(groupId, artifactId);
        } catch (IOException e) {
            LOG.warn("Maven Central unreachable for {}:{} — using offline fallback: {}",
                    groupId, artifactId, e.getMessage());
            String fallback = KNOWN_SAFE_VERSIONS.get(groupId + ":" + artifactId + ":" + reportedVersion);
            if (fallback != null) {
                return new SafeVersionResult(reportedVersion, true, fallback, fallback,
                        SafeVersionResult.RecommendationType.MINIMAL);
            }
            throw e;
        }

        String latest = all.isEmpty() ? null : all.get(all.size() - 1);

        // 4. Filter pre-releases and sort ascending
        List<String> candidates = all.stream()
                .filter(v -> {
                    String lower = v.toLowerCase();
                    return !lower.contains("alpha") && !lower.contains("beta")
                            && !lower.contains("rc") && !lower.contains("snapshot")
                            && !lower.contains("m1") && !lower.contains("m2")
                            && !lower.contains("m3");
                })
                .sorted(Comparator.comparing(v -> {
                    try { return VersionParser.parse(v); }
                    catch (Exception e) { return new VersionParser.Version(0, 0, 0, v); }
                }))
                .collect(Collectors.toList());

        // 5. Return FIRST version not in the affected range (minimum safe, not latest)
        for (String candidate : candidates) {
            if (!VersionRangeEvaluator.isVersionInRange(candidate, affectedRange)) {
                SafeVersionResult.RecommendationType type =
                        VersionRangeEvaluator.compareVersions(candidate, reportedVersion) == 0
                                ? SafeVersionResult.RecommendationType.OPTIONAL
                                : SafeVersionResult.RecommendationType.MINIMAL;
                LOG.info("Minimum safe version for {}:{} {}: {} (latest: {})",
                        groupId, artifactId, reportedVersion, candidate, latest);
                return new SafeVersionResult(reportedVersion, true, candidate, latest, type);
            }
        }

        LOG.warn("No safe version found for {}:{} {} in range {}",
                groupId, artifactId, reportedVersion, affectedRange);
        return new SafeVersionResult(reportedVersion, true, null, latest,
                SafeVersionResult.RecommendationType.OPTIONAL);
    }

    /**
     * Resolve the minimum safe version directly from the scanner-supplied
     * {@code safeVersions} list.
     *
     * <p>This is always the <em>first</em> strategy attempted by {@link //}
     * because the scanner already did the version analysis; we should trust and
     * reuse it rather than repeating the work with a Maven Central call.
     *
     * @param safeVersions the list from the scanner payload (may be empty but never null)
     * @param currentVersion the currently-resolved (effective) version
     * @return result with {@code minimumSafeVersion = safeVersions.get(0)}, or an
     *         OPTIONAL result if the list is empty
     */
    public SafeVersionResult findFromSignalSafeVersions(List<String> safeVersions,
                                                        String currentVersion) {
        if (safeVersions == null || safeVersions.isEmpty()) {
            return new SafeVersionResult(currentVersion, true, null, null,
                    SafeVersionResult.RecommendationType.OPTIONAL);
        }
        // The spec mandates: use the FIRST (minimum) safe version, not the latest
        String minimum = safeVersions.get(0);
        LOG.info("Using scanner-supplied minimum safe version: {} → {}", currentVersion, minimum);
        return new SafeVersionResult(currentVersion, true, minimum,
                safeVersions.get(safeVersions.size() - 1),
                SafeVersionResult.RecommendationType.MINIMAL);
    }
}