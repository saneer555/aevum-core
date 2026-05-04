package com.aevum.core.domain.model;

import com.aevum.core.domain.enums.Scope;
import java.util.Objects;

/**
 * Immutable representation of a Maven artifact coordinate.
 *
 * FIX: Added {@code optional} flag to track Maven <optional>true</optional> dependencies.
 *      Optional dependencies are not transitive — they should be skipped in classpath checks.
 */
public final class Artifact {
    private final String groupId;
    private final String artifactId;
    private final String version;
    private final Scope scope;
    private final boolean optional;
    private final String classifier;
    private final String type;

    public Artifact(String groupId, String artifactId, String version, Scope scope) {
        this(groupId, artifactId, version, scope, false, "", "jar");
    }

    public Artifact(String groupId, String artifactId, String version, Scope scope, boolean optional) {
        this(groupId, artifactId, version, scope, optional, "", "jar");
    }

    public Artifact(String groupId, String artifactId, String version, Scope scope,
                    boolean optional, String classifier, String type) {
        this.groupId = Objects.requireNonNull(groupId, "groupId cannot be null");
        this.artifactId = Objects.requireNonNull(artifactId, "artifactId cannot be null");
        this.version = Objects.requireNonNull(version, "version cannot be null");
        this.scope = Objects.requireNonNull(scope, "scope cannot be null");
        this.optional = optional;
        this.classifier = classifier != null ? classifier : "";
        this.type = type != null ? type : "jar";
    }

    public String getGroupId() { return groupId; }
    public String getArtifactId() { return artifactId; }
    public String getVersion() { return version; }
    public Scope getScope() { return scope; }
    public boolean isOptional() { return optional; }
    public String getClassifier() { return classifier; }
    public String getType() { return type; }

    public String getCoordinate() {
        return groupId + ":" + artifactId + ":" + version;
    }

    public String getShortCoordinate() {
        return groupId + ":" + artifactId;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof Artifact)) return false;
        Artifact artifact = (Artifact) o;
        return optional == artifact.optional &&
                Objects.equals(groupId, artifact.groupId) &&
                Objects.equals(artifactId, artifact.artifactId) &&
                Objects.equals(version, artifact.version) &&
                scope == artifact.scope;
    }

    @Override
    public int hashCode() {
        return Objects.hash(groupId, artifactId, version, scope, optional);
    }

    @Override
    public String toString() {
        return getCoordinate() + (optional ? " [optional]" : "");
    }
}