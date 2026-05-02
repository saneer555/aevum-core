package com.aevum.core.engine.fix;

import com.aevum.core.domain.enums.FixType;
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
 * 5. Fix type priority (VERSION_ALIGNMENT > EXCLUSION > PARENT_UPGRADE > NO_FIX_REQUIRED)
 *
 * FIX: getFixTypePriority() switch was missing a case for NO_FIX_REQUIRED — would throw
 * MatchException at runtime on Java 21 exhaustive switch expressions. Added explicit case
 * and converted to switch statement with default to be safe on Java 17.
 */
@Component
public class FixRankingService {
    private static final Logger LOG = LoggerFactory.getLogger(FixRankingService.class);

    public static final class RankedFixOptions {
        public final FixOption recommendedFix;
        public final List<FixOption> alternativeFixes;

        public RankedFixOptions(FixOption recommendedFix, List<FixOption> alternativeFixes) {
            this.recommendedFix = recommendedFix;
            this.alternativeFixes = List.copyOf(alternativeFixes != null ? alternativeFixes : List.of());
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
        if (fixes == null || fixes.isEmpty()) {
            return new RankedFixOptions(null, Collections.emptyList());
        }

        // Sort all by ranking criteria
        List<FixOption> sorted = new ArrayList<>(fixes);
        sorted.sort(createComparator(currentVersion));

        FixOption recommended = sorted.get(0);
        List<FixOption> alternatives = sorted.stream()
                .skip(1)
                .filter(FixOption::isValidated)  // Alternatives must be validated
                .collect(Collectors.toList());

        LOG.info("Ranked {} fixes: recommended={}, alternatives={}",
                fixes.size(), recommended.getDescription(), alternatives.size());

        return new RankedFixOptions(recommended, alternatives);
    }

    private Comparator<FixOption> createComparator(String currentVersion) {
        return Comparator
                // 1. Validated first
                .comparing(FixOption::isValidated).reversed()
                // 2. Minimal impact: fewer affected artifacts
                .thenComparingInt(f -> f.getAffectedArtifacts().size())
                // 3. Version proximity
                .thenComparingInt(f -> calculateVersionDistance(
                        currentVersion != null ? currentVersion : "0.0.0",
                        f.getProposedVersion() != null ? f.getProposedVersion() : ""))
                // 4. Fix type priority
                .thenComparingInt(f -> getFixTypePriority(f.getFixType()));
    }

    /**
     * Calculate version distance (semantic versioning).
     * Lower = closer = better.
     */
    private int calculateVersionDistance(String current, String proposed) {
        if (proposed == null || proposed.isEmpty()) {
            return Integer.MAX_VALUE;
        }
        try {
            VersionParser.Version cv = VersionParser.parse(current);
            VersionParser.Version pv = VersionParser.parse(proposed);
            int majorDiff = Math.abs(pv.major - cv.major) * 1000;
            int minorDiff = Math.abs(pv.minor - cv.minor) * 100;
            int patchDiff = Math.abs(pv.patch - cv.patch);
            return majorDiff + minorDiff + patchDiff;
        } catch (Exception e) {
            LOG.warn("Could not calculate version distance: {} -> {}", current, proposed);
            return Integer.MAX_VALUE;
        }
    }

    /**
     * Return priority value for fix type. Lower = higher priority.
     *
     * FIX: Original switch expression had no case for NO_FIX_REQUIRED — runtime crash.
     * Now uses explicit switch statement with default.
     */
    private int getFixTypePriority(FixType fixType) {
        if (fixType == null) return 99;
        switch (fixType) {
            case VERSION_ALIGNMENT:    return 1;
            case DEPENDENCY_EXCLUSION: return 2;
            case PARENT_UPGRADE:       return 3;
            case NO_FIX_REQUIRED:      return 99;
            default:                   return 99;
        }
    }

    /**
     * Check if a fix is considered "minimal change".
     */
    public boolean isMinimalChange(FixOption fix, String currentVersion) {
        if (fix.getFixType() != FixType.VERSION_ALIGNMENT) return false;
        if (fix.getProposedVersion() == null) return false;
        try {
            VersionParser.Version current = VersionParser.parse(currentVersion);
            VersionParser.Version proposed = VersionParser.parse(fix.getProposedVersion());
            return current.major == proposed.major && Math.abs(proposed.minor - current.minor) <= 2;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Generate human-readable explanation for why this fix is recommended.
     */
    public String generateRecommendationReasoning(FixOption fix, boolean isMinimal,
                                                  int affectedCount, boolean isValidated) {
        List<String> reasons = new ArrayList<>();
        reasons.add("Fix type: " + fix.getFixType());
        if (isMinimal) reasons.add("Minimal change strategy");
        reasons.add("Affected artifacts: " + affectedCount);
        if (isValidated) {
            reasons.add("Validated by build & tests");
        } else {
            reasons.add("Requires validation before applying");
        }
        return String.join(" | ", reasons);
    }
}