package com.aevum.core.domain.model;

import java.util.*;

/**
 * Represents the fully resolved effective POM after BOM resolution.
 */
public final class EffectivePom {
    private final String projectId;
    private final List<Artifact> directDependencies;
    private final List<BomDeclaration> bomDeclarations;
    private final Map<String, String> properties;
    private final Map<String, Artifact> resolvedDependencies;
    private final List<DependencyNode> dependencyTree;

    public EffectivePom(String projectId,
                        List<Artifact> directDependencies,
                        List<BomDeclaration> bomDeclarations,
                        Map<String, String> properties,
                        Map<String, Artifact> resolvedDependencies,
                        List<DependencyNode> dependencyTree) {
        this.projectId = Objects.requireNonNull(projectId);
        this.directDependencies = List.copyOf(directDependencies);
        this.bomDeclarations = List.copyOf(bomDeclarations);
        this.properties = Map.copyOf(properties);
        this.resolvedDependencies = Map.copyOf(resolvedDependencies);
        this.dependencyTree = List.copyOf(dependencyTree);
    }

    public String getProjectId() { return projectId; }
    public List<Artifact> getDirectDependencies() { return directDependencies; }
    public List<BomDeclaration> getBomDeclarations() { return bomDeclarations; }
    public Map<String, String> getProperties() { return properties; }
    public Map<String, Artifact> getResolvedDependencies() { return resolvedDependencies; }
    public List<DependencyNode> getDependencyTree() { return dependencyTree; }

    public Optional<Artifact> getResolvedArtifact(String groupId, String artifactId) {
        return Optional.ofNullable(resolvedDependencies.get(groupId + ":" + artifactId));
    }

    public boolean hasArtifact(String groupId, String artifactId) {
        return resolvedDependencies.containsKey(groupId + ":" + artifactId);
    }
}
