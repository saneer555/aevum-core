package com.aevum.core.engine.fix;

import com.aevum.core.domain.model.FixOption;
import com.aevum.core.engine.version.VersionParser;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.util.*;
import java.util.stream.Collectors;

/**
 * Ranks fix options based on impact, minimal change, and validation.
 *
 * Ranking Criteria (by priority):
 * 1. Validated fixes first (unvalidated last)
 * 2. Minimal change strategy (smallest version bump)
 * 3. Least affected artifacts
 * 4. Version proximity (closest to current)
 * 5. Fix type priority (VERSION_ALIGNMENT > EXCLUSION > PARENT_UPGRADE)
 */
@Component
public class FixRankingService {
    private static final Logger LOG = LoggerFactory.getLogger(FixRankingService.class);

    public static final class RankedFixOptions {
        public final FixOption recommendedFix;
        public final List<FixOption> alternativeFixes;

        public RankedFixOptions(FixOption recommendedFix, List<FixOption> alternativeFixes) {
            this.recommendedFix = recommendedFix;
            this.alternativeFixes = alternativeFixes;
        }

        public List<FixOption> getAllFixes() {
            List<FixOption> all = new ArrayList<>();
            if (recommendedFix != null) all.add(recommendedFix);
            all.addAll(alternativeFixes);
            return all;
        }
    }

    /**
     * Rank fixes and return recommended + alternatives.
     * Only returns validated fixes as alternatives.
     * If no validated fixes exist, recommends the best candidate anyway (unvalidated).
     */
    public RankedFixOptions rankFixes(List<FixOption> fixes, String currentVersion) {
        if (fixes.isEmpty()) {
            return new RankedFixOptions(null, Collections.emptyList());
        }

        // Separate validated from unvalidated
        List<FixOption> validated = fixes.stream()
            .filter(FixOption::isValidated)
            .collect(Collectors.toList());

        List<FixOption> unvalidated = fixes.stream()
            .filter(f -> !f.isValidated())
            .collect(Collectors.toList());

        // Sort all by ranking criteria
        List<FixOption> sorted = new ArrayList<>(validated);
        sorted.addAll(unvalidated);
        sorted.sort(this.createComparator(currentVersion));

        if (sorted.isEmpty()) {
            return new RankedFixOptions(null, Collections.emptyList());
        }

        FixOption recommended = sorted.get(0);
        List<FixOption> alternatives = sorted.stream()
            .skip(1)
            .filter(FixOption::isValidated)  // Alternatives must be validated
            .collect(Collectors.toList());

        LOG.info("Ranked {} fixes: recommended={}, alternatives={}",
            fixes.size(), recommended.getDescription(), alternatives.size());

        return new RankedFixOptions(recommended, alternatives);
    }

    /**
     * Create a comparator for ranking fixes.
     */
    private Comparator<FixOption> createComparator(String currentVersion) {
        return Comparator
            // 1. Validated first (unvalidated last)
            .comparing(FixOption::isValidated).reversed()
            // 2. Minimal impact: fewer affected artifacts
            .thenComparing(f -> f.getAffectedArtifacts().size())
            // 3. Version proximity: closest version bump
            .thenComparing(f -> calculateVersionDistance(currentVersion, f.getProposedVersion() != null ? f.getProposedVersion() : ""))
            // 4. Fix type priority
            .thenComparing(f -> getFixTypePriority(f.getFixType()));
    }

    /**
     * Calculate version distance (semantic versioning).
     * Lower = closer = better.
     *
     * Example:
     *   current=2.14.1, proposed=2.17.1 → distance=3 (minor bump)
     *   current=2.14.1, proposed=3.0.0 → distance=10 (major bump, higher)
     */
    private int calculateVersionDistance(String current, String proposed) {
        if (proposed == null || proposed.isEmpty()) {
            return Integer.MAX_VALUE;
        }

        try {
            VersionParser.Version cv = VersionParser.parse(current);
            VersionParser.Version pv = VersionParser.parse(proposed);

            // Major version difference (highest weight)
            int majorDiff = Math.abs(pv.major - cv.major) * 1000;

            // Minor version difference
            int minorDiff = Math.abs(pv.minor - cv.minor) * 100;

            // Patch version difference
            int patchDiff = Math.abs(pv.patch - cv.patch);

            return majorDiff + minorDiff + patchDiff;
        } catch (Exception e) {
            LOG.warn("Could not calculate version distance: {} -> {}", current, proposed);
            return Integer.MAX_VALUE;
        }
    }

    /**
     * Return priority value for fix type.
     * Lower = higher priority = ranked first.
     */
    private int getFixTypePriority(com.aevum.core.domain.enums.FixType fixType) {
        return switch (fixType) {
            case VERSION_ALIGNMENT -> 1;      // Preferred: minimal change
            case DEPENDENCY_EXCLUSION -> 2;   // Secondary: removes dependency
            case PARENT_UPGRADE -> 3;         // Tertiary: large change
        };
    }

    /**
     * Check if a fix is considered "minimal change".
     * True if: version alignment with small bump (major.minor only)
     */
    public boolean isMinimalChange(FixOption fix, String currentVersion) {
        if (fix.getFixType() != com.aevum.core.domain.enums.FixType.VERSION_ALIGNMENT) {
            return false;
        }

        if (fix.getProposedVersion() == null) {
            return false;
        }

        try {
            VersionParser.Version current = VersionParser.parse(currentVersion);
            VersionParser.Version proposed = VersionParser.parse(fix.getProposedVersion());

            // Minimal if major version same, minor version differs by <=2
            return current.major == proposed.major &&
                   Math.abs(proposed.minor - current.minor) <= 2;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Generate explanation for why this fix is recommended.
     */
    public String generateRecommendationReasoning(FixOption fix, boolean isMinimal, int affectedCount, boolean isValidated) {
        List<String> reasons = new ArrayList<>();

        reasons.add("Fix type: " + fix.getFixType());

        if (isMinimal) {
            reasons.add("Minimal change strategy");
        }

        reasons.add("Affected artifacts: " + affectedCount);

        if (isValidated) {
            reasons.add("Validated by build & tests");
        } else {
            reasons.add("Requires validation before applying");
        }

        return String.join(" | ", reasons);
    }
}

