package com.aevum.core.engine.fix;

import com.aevum.core.domain.model.Artifact;
import com.aevum.core.domain.model.EffectivePom;
import com.aevum.core.domain.model.DependencyNode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.util.*;
import java.util.stream.Collectors;

/**
 * Detects version conflicts in dependency tree.
 *
 * A conflict occurs when the same artifact (groupId:artifactId) appears
 * with multiple different versions in the resolved dependency tree.
 *
 * Example: bcprov-jdk18on appears as both 1.80 and 1.81
 *
 * This is important for understanding why a fix may impact multiple paths.
 */
@Component
public class VersionConflictDetector {
    private static final Logger LOG = LoggerFactory.getLogger(VersionConflictDetector.class);

    public static final class VersionConflict {
        public final String coordinate;              // groupId:artifactId
        public final Set<String> conflictingVersions; // All versions of this artifact
        public final List<ConflictPath> paths;        // Paths where this version appears

        public VersionConflict(String coordinate, Set<String> conflictingVersions, List<ConflictPath> paths) {
            this.coordinate = coordinate;
            this.conflictingVersions = conflictingVersions;
            this.paths = paths;
        }

        public boolean isConflict() {
            return conflictingVersions.size() > 1;
        }

        @Override
        public String toString() {
            return coordinate + " CONFLICT: " + String.join(", ", conflictingVersions) +
                   " (" + paths.size() + " paths)";
        }
    }

    public static final class ConflictPath {
        public final String version;
        public final List<String> path;  // Chain: root → ... → artifact@version
        public final int depth;

        public ConflictPath(String version, List<String> path, int depth) {
            this.version = version;
            this.path = path;
            this.depth = depth;
        }

        public String getPathString() {
            return String.join(" → ", path);
        }
    }

    /**
     * Detect all version conflicts in the effective POM.
     */
    public List<VersionConflict> detectConflicts(EffectivePom effectivePom) {
        Map<String, List<ConflictPath>> versionMap = new HashMap<>();

        // Scan all artifacts in dependency tree
        scanDependencyTree(effectivePom.getDependencyTree(), versionMap, new ArrayList<>());

        // Filter to only actual conflicts (multiple versions)
        List<VersionConflict> conflicts = versionMap.entrySet().stream()
            .filter(e -> e.getValue().stream()
                .map(cp -> cp.version)
                .collect(Collectors.toSet())
                .size() > 1)
            .map(e -> {
                Set<String> versions = e.getValue().stream()
                    .map(cp -> cp.version)
                    .collect(Collectors.toSet());
                return new VersionConflict(e.getKey(), versions, e.getValue());
            })
            .sorted(Comparator.comparing(c -> c.coordinate))
            .collect(Collectors.toList());

        if (!conflicts.isEmpty()) {
            LOG.warn("Detected {} version conflicts in dependency tree", conflicts.size());
            conflicts.forEach(c -> LOG.warn("  {}", c));
        }

        return conflicts;
    }

    /**
     * Recursively scan dependency tree.
     */
    private void scanDependencyTree(List<DependencyNode> nodes,
                                    Map<String, List<ConflictPath>> versionMap,
                                    List<String> currentPath) {
        for (DependencyNode node : nodes) {
            Artifact artifact = node.getArtifact();
            String coordinate = artifact.getShortCoordinate();

            // Build path: currentPath + this node
            List<String> nodePath = new ArrayList<>(currentPath);
            nodePath.add(artifact.getCoordinate());

            // Record this occurrence
            versionMap.computeIfAbsent(coordinate, k -> new ArrayList<>())
                .add(new ConflictPath(artifact.getVersion(), nodePath, node.getDepth()));

            // Recurse to children
            scanDependencyTree(node.getChildren(), versionMap, nodePath);
        }
    }

    /**
     * Check if a specific artifact has conflicts.
     */
    public boolean hasConflict(EffectivePom effectivePom, String groupId, String artifactId) {
        List<VersionConflict> conflicts = detectConflicts(effectivePom);
        String coordinate = groupId + ":" + artifactId;
        return conflicts.stream()
            .anyMatch(c -> c.coordinate.equals(coordinate) && c.isConflict());
    }

    /**
     * Get all versions where a specific artifact appears.
     */
    public Set<String> getAllVersions(EffectivePom effectivePom, String groupId, String artifactId) {
        String coordinate = groupId + ":" + artifactId;
        Map<String, List<ConflictPath>> versionMap = new HashMap<>();
        scanDependencyTree(effectivePom.getDependencyTree(), versionMap, new ArrayList<>());

        return versionMap.getOrDefault(coordinate, Collections.emptyList()).stream()
            .map(cp -> cp.version)
            .collect(Collectors.toSet());
    }

    /**
     * Generate warning message for conflicts.
     */
    public String generateConflictWarning(VersionConflict conflict) {
        if (!conflict.isConflict()) {
            return null;
        }

        String versions = String.join(", ", conflict.conflictingVersions);
        return String.format(
            "VERSION CONFLICT: %s has multiple versions [%s] across %d dependency paths. " +
            "Maven will select one at runtime (nearest wins). This may cause unexpected behavior.",
            conflict.coordinate, versions, conflict.paths.size()
        );
    }
}

