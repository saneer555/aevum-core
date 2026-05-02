package com.aevum.core.domain.model;

import java.util.*;

/**
 * Represents a BOM (Bill of Materials) declaration in dependencyManagement.
 */
public final class BomDeclaration {
    private final Artifact bomArtifact;
    private final Map<String, String> managedVersions;
    private final Map<String, List<String>> exclusions;

    public BomDeclaration(Artifact bomArtifact, Map<String, String> managedVersions) {
        this(bomArtifact, managedVersions, Collections.emptyMap());
    }

    public BomDeclaration(Artifact bomArtifact, Map<String, String> managedVersions, Map<String, List<String>> exclusions) {
        this.bomArtifact = Objects.requireNonNull(bomArtifact);
        this.managedVersions = Map.copyOf(managedVersions != null ? managedVersions : Collections.emptyMap());
        this.exclusions = Map.copyOf(exclusions != null ? exclusions : Collections.emptyMap());
    }

    public Artifact getBomArtifact() { return bomArtifact; }
    public Map<String, String> getManagedVersions() { return managedVersions; }
    public Map<String, List<String>> getExclusions() { return exclusions; }

    public Optional<String> getManagedVersion(String groupId, String artifactId) {
        return Optional.ofNullable(managedVersions.get(groupId + ":" + artifactId));
    }

    @Override
    public String toString() {
        return "BOM[" + bomArtifact.getCoordinate() + ", managed=" + managedVersions.size() + "]";
    }
}
