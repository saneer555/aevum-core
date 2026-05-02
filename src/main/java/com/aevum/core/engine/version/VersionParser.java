package com.aevum.core.engine.version;

import java.util.Objects;

/**
 * Lightweight semantic version parser and comparator.
 */
public final class VersionParser {

    public static final class Version implements Comparable<Version> {
        public final int major;
        public final int minor;
        public final int patch;
        public final String qualifier;

        public Version(int major, int minor, int patch, String qualifier) {
            this.major = major; this.minor = minor; this.patch = patch; this.qualifier = qualifier;
        }

        @Override
        public int compareTo(Version o) {
            if (this.major != o.major) return Integer.compare(this.major, o.major);
            if (this.minor != o.minor) return Integer.compare(this.minor, o.minor);
            if (this.patch != o.patch) return Integer.compare(this.patch, o.patch);
            if (this.qualifier == null && o.qualifier != null) return 1;
            if (this.qualifier != null && o.qualifier == null) return -1;
            if (this.qualifier == null) return 0;
            return this.qualifier.compareTo(o.qualifier);
        }

        @Override
        public String toString() {
            return major + "." + minor + "." + patch + (qualifier != null ? "-" + qualifier : "");
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (!(o instanceof Version)) return false;
            Version v = (Version) o;
            return major == v.major && minor == v.minor && patch == v.patch && Objects.equals(qualifier, v.qualifier);
        }

        @Override
        public int hashCode() {
            return Objects.hash(major, minor, patch, qualifier);
        }
    }

    public static Version parse(String input) {
        if (input == null) throw new IllegalArgumentException("version required");
        // strip common qualifiers we consider pre-release
        String sanitized = input.trim();
        String qualifier = null;
        int dash = sanitized.indexOf('-');
        if (dash >= 0) {
            qualifier = sanitized.substring(dash + 1);
            sanitized = sanitized.substring(0, dash);
            // ignore rc/beta qualifiers by marking as qualifier; they will sort before releases
        }

        String[] parts = sanitized.split("\\.");
        int major = parts.length > 0 ? parsePart(parts[0]) : 0;
        int minor = parts.length > 1 ? parsePart(parts[1]) : 0;
        int patch = parts.length > 2 ? parsePart(parts[2]) : 0;
        return new Version(major, minor, patch, qualifier);
    }

    private static int parsePart(String p) {
        StringBuilder sb = new StringBuilder();
        for (char c : p.toCharArray()) {
            if (Character.isDigit(c)) sb.append(c);
            else break;
        }
        if (sb.length() == 0) return 0;
        return Integer.parseInt(sb.toString());
    }
}

