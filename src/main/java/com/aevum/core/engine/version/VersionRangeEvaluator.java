package com.aevum.core.engine.version;

/**
 * Evaluate Maven-style version ranges. Minimal support for [a,b), (a,b], (a,b) and plain version ranges.
 */
public final class VersionRangeEvaluator {

    public static boolean isVersionInRange(String version, String range) {
        if (range == null || range.isBlank()) return false;
        range = range.trim();
        // If range looks like a single version, compare equality
        if (!(range.startsWith("[") || range.startsWith("("))) {
            return version.equals(range);
        }

        boolean leftInclusive = range.startsWith("[");
        boolean rightInclusive = range.endsWith("]");
        String inner = range.substring(1, range.length() - 1);
        String[] parts = inner.split(",");
        String left = parts.length > 0 ? parts[0].trim() : "";
        String right = parts.length > 1 ? parts[1].trim() : "";

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
        return VersionParser.parse(a).compareTo(VersionParser.parse(b));
    }
}

