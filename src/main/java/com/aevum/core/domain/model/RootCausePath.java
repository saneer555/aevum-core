package com.aevum.core.domain.model;

import java.util.*;

/**
 * Exact root cause dependency path.
 */
public final class RootCausePath {
    private final List<Artifact> path;
    private final Artifact vulnerableArtifact;
    private final String mediationRule;
    private final int depth;

    public RootCausePath(List<Artifact> path, Artifact vulnerableArtifact, String mediationRule, int depth) {
        this.path = List.copyOf(path);
        this.vulnerableArtifact = Objects.requireNonNull(vulnerableArtifact);
        this.mediationRule = mediationRule;
        this.depth = depth;
    }

    public List<Artifact> getPath() { return path; }
    public Artifact getVulnerableArtifact() { return vulnerableArtifact; }
    public String getMediationRule() { return mediationRule; }
    public int getDepth() { return depth; }

    public String getPathString() {
        return String.join(" → ", path.stream().map(Artifact::getShortCoordinate).toList()) +
               " → " + vulnerableArtifact.getShortCoordinate() + ":" + vulnerableArtifact.getVersion();
    }

    @Override
    public String toString() {
        return getPathString() + " [" + mediationRule + "]";
    }
}
