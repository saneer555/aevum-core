package com.aevum.core.engine.version;

import java.io.IOException;
import java.util.Comparator;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

/**
 * Find the minimum safe version given available versions and an affected range.
 */
public class SafeVersionFinder {
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

        public SafeVersionResult(String currentVersion, boolean vulnerable, String minimumSafeVersion, String latestVersion, RecommendationType recommendationType) {
            this.currentVersion = currentVersion;
            this.vulnerable = vulnerable;
            this.minimumSafeVersion = minimumSafeVersion;
            this.latestVersion = latestVersion;
            this.recommendationType = recommendationType;
        }

        public enum RecommendationType { MINIMAL, OPTIONAL }
    }

    public SafeVersionResult findMinimumSafe(String groupId, String artifactId, String reportedVersion, String affectedRange) throws IOException {
        List<String> all = metadataClient.fetchAvailableVersions(groupId, artifactId);
        String latest = all.isEmpty() ? null : all.get(all.size() - 1);
        boolean currentlyVulnerable = VersionRangeEvaluator.isVersionInRange(reportedVersion, affectedRange);
        if (!currentlyVulnerable) {
            return new SafeVersionResult(reportedVersion, false, reportedVersion, latest, SafeVersionResult.RecommendationType.OPTIONAL);
        }

        // Filter out pre-releases (qualifiers) and find the first version above the range
        List<String> candidates = all.stream()
            .filter(v -> !v.toLowerCase().contains("rc") && !v.toLowerCase().contains("alpha") && !v.toLowerCase().contains("beta") && !v.toLowerCase().contains("snapshot"))
            .sorted(Comparator.comparing(VersionParser::parse))
            .collect(Collectors.toList());

        for (String candidate : candidates) {
            if (!VersionRangeEvaluator.isVersionInRange(candidate, affectedRange)) {
                // first candidate not in affected range
                SafeVersionResult.RecommendationType type = VersionRangeEvaluator.compareVersions(candidate, reportedVersion) == 0
                    ? SafeVersionResult.RecommendationType.OPTIONAL
                    : SafeVersionResult.RecommendationType.MINIMAL;
                return new SafeVersionResult(reportedVersion, true, candidate, latest, type);
            }
        }

        // no safe version found
        return new SafeVersionResult(reportedVersion, true, null, latest, SafeVersionResult.RecommendationType.OPTIONAL);
    }
}

