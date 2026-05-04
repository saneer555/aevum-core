package com.aevum.core.domain.model;

import com.aevum.core.domain.enums.Scope;
import java.util.*;

/**
 * Represents the fully resolved effective POM after BOM resolution.
 *
 * FIX: Added {@code isRuntimeArtifact()} helper to filter out PROVIDED, TEST, and optional
 *      dependencies. These should not be checked for classpath presence.
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

    /**
     * Returns true if the artifact is a runtime dependency (not provided, test, or optional).
     * Used by ClasspathPresenceStage to skip non-runtime artifacts.
     */
    public boolean isRuntimeArtifact(String groupId, String artifactId) {
        Artifact artifact = resolvedDependencies.get(groupId + ":" + artifactId);
        if (artifact == null) return false;
        if (artifact.getScope() == Scope.PROVIDED) return false;
        if (artifact.getScope() == Scope.TEST) return false;
        if (artifact.isOptional()) return false;
        return true;
    }
}