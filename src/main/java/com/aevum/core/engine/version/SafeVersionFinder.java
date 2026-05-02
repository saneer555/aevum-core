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
 * FIX 1: Was not a @Component — SafeVersionFinder was instantiated via `new` inside FixEngine's
 * old manual constructor. Now a proper Spring @Component injected into FixEngine.
 *
 * FIX 2: Added a known-safe versions fallback map. If Maven Central is unreachable (no network,
 * CI environment, etc.), SafeVersionFinder would throw IOException and FixEngine would catch it
 * and silently skip version alignment fixes — leaving users with no remediation suggestions.
 * The fallback map covers well-known critical CVEs so fixes are always generated for them
 * even in offline environments.
 *
 * FIX 3: Re-checks CVE for candidate version — if the candidate is also in the affected range
 * (shouldn't happen with proper range parsing, but can happen with malformed ranges), it is
 * skipped. This is already handled by the range evaluator loop, but explicitly documented.
 */
@Component
public class SafeVersionFinder {
    private static final Logger LOG = LoggerFactory.getLogger(SafeVersionFinder.class);

    /**
     * Offline fallback: known minimum safe versions for critical CVEs.
     * Key: groupId:artifactId:vulnerableVersion → safeVersion
     * Used when Maven Central is unreachable.
     */
    private static final Map<String, String> KNOWN_SAFE_VERSIONS = Map.ofEntries(
            Map.entry("org.apache.logging.log4j:log4j-core:2.14.1", "2.17.1"),
            Map.entry("org.apache.logging.log4j:log4j-core:2.15.0", "2.17.1"),
            Map.entry("org.apache.logging.log4j:log4j-core:2.16.0", "2.17.1"),
            Map.entry("org.apache.logging.log4j:log4j-core:2.12.0", "2.12.4"),
            Map.entry("org.apache.logging.log4j:log4j-core:2.13.0", "2.17.1"),
            Map.entry("org.bouncycastle:bcprov-jdk18on:1.80", "1.81"),
            Map.entry("org.apache.tomcat.embed:tomcat-embed-core:9.0.50", "9.0.90"),
            Map.entry("org.apache.tomcat.embed:tomcat-embed-core:10.1.15", "10.1.25"),
            Map.entry("com.fasterxml.jackson.core:jackson-databind:2.13.0", "2.13.5"),
            Map.entry("org.springframework:spring-core:5.3.20", "5.3.39"),
            Map.entry("org.springframework.security:spring-security-core:5.7.1", "5.7.12"),
            Map.entry("commons-text:commons-text:1.9", "1.10.0"),
            Map.entry("org.apache.struts:struts2-core:2.5.28", "2.5.33")
    );

    private final MavenMetadataClient metadataClient;

    public SafeVersionFinder(MavenMetadataClient metadataClient) {
        this.metadataClient = metadataClient;
    }

    public static final class SafeVersionResult {
        public final String currentVersion;
        public final boolean vulnerable;
        public final String minimumSafeVersion;
        public final String latestVersion;
        public final RecommendationType recommendationType;

        public SafeVersionResult(String currentVersion, boolean vulnerable,
                                 String minimumSafeVersion, String latestVersion,
                                 RecommendationType recommendationType) {
            this.currentVersion = currentVersion;
            this.vulnerable = vulnerable;
            this.minimumSafeVersion = minimumSafeVersion;
            this.latestVersion = latestVersion;
            this.recommendationType = recommendationType;
        }

        public enum RecommendationType { MINIMAL, OPTIONAL }
    }

    /**
     * Find the minimum safe version for a given artifact + optional affected range.
     *
     * Algorithm:
     * 1. If affectedRange is null/blank, use the offline fallback map.
     * 2. Fetch all versions from Maven Central metadata.
     * 3. Filter out pre-releases (alpha, beta, RC, SNAPSHOT).
     * 4. Sort ascending by version.
     * 5. Return the FIRST version that is NOT in the affected range.
     *    (First = minimum safe, not latest — per AEVUM design rule.)
     * 6. If Maven Central is unreachable, fall back to offline map.
     *
     * @param groupId       Maven groupId
     * @param artifactId    Maven artifactId
     * @param reportedVersion  the version flagged as vulnerable
     * @param affectedRange    Maven-style range like [1.0,2.17.1) — may be null
     */
    public SafeVersionResult findMinimumSafe(String groupId, String artifactId,
                                             String reportedVersion,
                                             String affectedRange) throws IOException {
        // If no range provided, use offline fallback directly
        if (affectedRange == null || affectedRange.isBlank()) {
            String fallback = KNOWN_SAFE_VERSIONS.get(groupId + ":" + artifactId + ":" + reportedVersion);
            if (fallback != null) {
                LOG.info("Using offline fallback safe version for {}:{} {} → {}",
                        groupId, artifactId, reportedVersion, fallback);
                return new SafeVersionResult(reportedVersion, true, fallback, fallback,
                        SafeVersionResult.RecommendationType.MINIMAL);
            }
            // No range and no fallback — can't determine safety
            return new SafeVersionResult(reportedVersion, false, reportedVersion, null,
                    SafeVersionResult.RecommendationType.OPTIONAL);
        }

        // Check if the current version is actually vulnerable
        boolean currentlyVulnerable = VersionRangeEvaluator.isVersionInRange(reportedVersion, affectedRange);
        if (!currentlyVulnerable) {
            return new SafeVersionResult(reportedVersion, false, reportedVersion, null,
                    SafeVersionResult.RecommendationType.OPTIONAL);
        }

        // Fetch from Maven Central with offline fallback
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
            throw e; // Re-throw if we have no fallback at all
        }

        String latest = all.isEmpty() ? null : all.get(all.size() - 1);

        // Filter pre-releases and sort ascending
        List<String> candidates = all.stream()
                .filter(v -> {
                    String lower = v.toLowerCase();
                    return !lower.contains("alpha") && !lower.contains("beta")
                            && !lower.contains("rc") && !lower.contains("snapshot")
                            && !lower.contains("m1") && !lower.contains("m2") && !lower.contains("m3");
                })
                .sorted(Comparator.comparing(v -> {
                    try { return VersionParser.parse(v); }
                    catch (Exception e) { return new VersionParser.Version(0, 0, 0, v); }
                }))
                .collect(Collectors.toList());

        // Find FIRST candidate not in the affected range (minimum safe, not latest)
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

        // All available versions are still in the vulnerable range — no safe version found
        LOG.warn("No safe version found for {}:{} {} in range {}",
                groupId, artifactId, reportedVersion, affectedRange);
        return new SafeVersionResult(reportedVersion, true, null, latest,
                SafeVersionResult.RecommendationType.OPTIONAL);
    }
}