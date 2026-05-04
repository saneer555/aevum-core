package com.aevum.core.engine.version;

import java.util.Objects;

/**
 * Evaluate Maven-style version ranges. Minimal support for [a,b), (a,b], (a,b) and plain version strings.
 *
 * FIX: Added {@code resolveRangeToConcreteVersion()} to convert Maven version ranges to a
 *      concrete version string. This is needed because Artifact.version stores the resolved
 *      version, and ranges like [4.5.0,4.5.14) cannot be used for classpath checks or
 *      vulnerability range comparisons.
 */
public final class VersionRangeEvaluator {

    private VersionRangeEvaluator() {
        // utility
    }

    public static boolean isVersionInRange(String version, String range) {
        if (version == null || range == null) return false;
        version = version.trim();
        range = range.trim();
        if (version.isEmpty() || range.isEmpty()) return false;

        // Not a range: direct equality
        if (!(range.startsWith("[") || range.startsWith("("))) {
            return version.equals(range);
        }

        boolean leftInclusive = range.startsWith("[");
        boolean rightInclusive = range.endsWith("]");

        // Remove outer brackets/parens and split on the first comma
        String inner = range.substring(1, range.length() - 1);
        String left = "";
        String right = "";
        int commaIdx = inner.indexOf(',');
        if (commaIdx >= 0) {
            left = inner.substring(0, commaIdx).trim();
            right = inner.substring(commaIdx + 1).trim();
        } else {
            left = inner.trim();
        }

        VersionParser.Version v = VersionParser.parse(version);

        if (!left.isEmpty()) {
            VersionParser.Version lv = VersionParser.parse(left);
            int cmp = v.compareTo(lv);
            if (cmp < 0 || (cmp == 0 && !leftInclusive)) return false;
        }

        if (!right.isEmpty()) {
            VersionParser.Version rv = VersionParser.parse(right);
            int cmp = v.compareTo(rv);
            if (cmp > 0 || (cmp == 0 && !rightInclusive)) return false;
        }

        return true;
    }

    public static int compareVersions(String a, String b) {
        Objects.requireNonNull(a);
        Objects.requireNonNull(b);
        return VersionParser.parse(a).compareTo(VersionParser.parse(b));
    }

    /**
     * Resolves a Maven version range to a concrete version string.
     *
     * Strategy:
     * - If the input is not a range (no brackets), return as-is.
     * - For soft upper bound {@code [a,b)} -> return {@code b} with patch decremented by 1
     *   (e.g. [4.5.0,4.5.14) -> 4.5.13).
     * - For hard upper bound {@code [a,b]} -> return {@code b}.
     * - For open-ended {@code [a,)} -> return {@code a} (fallback).
     *
     * @param range Maven version range string
     * @return concrete version string, or original input if not a range or unparseable
     */
    public static String resolveRangeToConcreteVersion(String range) {
        if (range == null || range.isBlank()) return range;
        range = range.trim();
        if (!(range.startsWith("[") || range.startsWith("("))) {
            return range; // Not a range
        }

        boolean rightInclusive = range.endsWith("]");

        // Extract inner content and split
        String inner = range.substring(1, range.length() - 1);
        String leftVer = "";
        String rightVer = "";
        int commaIdx = inner.indexOf(',');
        if (commaIdx >= 0) {
            leftVer = inner.substring(0, commaIdx).trim();
            rightVer = inner.substring(commaIdx + 1).trim();
        } else {
            leftVer = inner.trim();
        }

        if (!rightVer.isEmpty()) {
            return rightInclusive ? rightVer : decrementPatch(rightVer);
        }

        if (!leftVer.isEmpty()) {
            return leftVer;
        }

        return range;
    }

    /**
     * Decrement the patch version by 1. E.g. "4.5.14" -> "4.5.13".
     * If patch is 0, decrements minor. If minor is 0, decrements major.
     * If parsing fails, attempts a best-effort string fallback.
     */
    private static String decrementPatch(String version) {
        if (version == null || version.isBlank()) return version;
        try {
            VersionParser.Version v = VersionParser.parse(version);
            if (v.patch > 0) {
                return v.major + "." + v.minor + "." + (v.patch - 1);
            } else if (v.minor > 0) {
                return v.major + "." + (v.minor - 1) + ".0";
            } else if (v.major > 0) {
                return (v.major - 1) + ".0.0";
            }
        } catch (Exception ignored) {
            // fall through to string fallback
        }

        // String fallback: decrement last numeric segment if possible
        int lastDot = version.lastIndexOf('.');
        if (lastDot >= 0 && lastDot < version.length() - 1) {
            String prefix = version.substring(0, lastDot + 1);
            String patchStr = version.substring(lastDot + 1);
            try {
                int patch = Integer.parseInt(patchStr);
                if (patch > 0) {
                    return prefix + (patch - 1);
                } else {
                    // patch == 0: try to decrement previous segment
                    int prevDot = prefix.lastIndexOf('.', lastDot - 1);
                    if (prevDot >= 0 && prevDot < lastDot - 1) {
                        String minorStr = prefix.substring(prevDot + 1, lastDot);
                        String majorPrefix = prefix.substring(0, prevDot + 1);
                        try {
                            int minor = Integer.parseInt(minorStr);
                            if (minor > 0) {
                                return majorPrefix + (minor - 1) + ".0.0";
                            }
                        } catch (NumberFormatException ignored2) { }
                    }
                }
            } catch (NumberFormatException ignored) { }
        }

        return version;
    }
}
