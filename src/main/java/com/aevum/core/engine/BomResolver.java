package com.aevum.core.engine;

import com.aevum.core.domain.model.*;
import com.aevum.core.domain.enums.Scope;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Maven BOM Resolution Engine.
 * Implements exact Maven dependency mediation rules:
 * 1. Direct dependency overrides BOM
 * 2. Nearest definition wins
 * 3. First declaration wins
 * 4. Explicit version overrides managed version
 */
@Component
public class BomResolver {
    private static final Logger LOG = LoggerFactory.getLogger(BomResolver.class);

    /**
     * Resolves the effective version of an artifact given the project context.
     */
    public ResolutionResult resolveEffectiveVersion(String groupId, String artifactId,
                                                     EffectivePom effectivePom) {
        String coordinate = groupId + ":" + artifactId;
        LOG.debug("Resolving effective version for: {}", coordinate);

        // Rule 1: Check direct dependencies first (highest precedence)
        Optional<Artifact> directMatch = effectivePom.getDirectDependencies().stream()
            .filter(d -> d.getShortCoordinate().equals(coordinate))
            .findFirst();

        if (directMatch.isPresent()) {
            Artifact direct = directMatch.get();
            return new ResolutionResult(
                direct,
                "DIRECT_DEPENDENCY_OVERRIDES_BOM",
                0,
                true,
                "Direct dependency has highest precedence"
            );
        }

        // Rule 2 & 3: Traverse dependency tree - nearest wins, first wins at same depth
        Optional<TreeMatch> treeMatch = findInDependencyTree(groupId, artifactId, effectivePom.getDependencyTree());
        if (treeMatch.isPresent()) {
            TreeMatch match = treeMatch.get();
            return new ResolutionResult(
                match.node().getArtifact(),
                "NEAREST_DEFINITION_WINS",
                match.node().getDepth(),
                false,
                "Found at depth " + match.node().getDepth() + " via " + match.path()
            );
        }

        // Rule 4: Check BOM managed versions
        for (BomDeclaration bom : effectivePom.getBomDeclarations()) {
            Optional<String> managedVersion = bom.getManagedVersion(groupId, artifactId);
            if (managedVersion.isPresent()) {
                Artifact managed = new Artifact(groupId, artifactId, managedVersion.get(), Scope.COMPILE);
                return new ResolutionResult(
                    managed,
                    "MANAGED_VERSION_FROM_BOM",
                    -1,
                    false,
                    "Version managed by BOM: " + bom.getBomArtifact().getCoordinate()
                );
            }
        }

        // Not found
        return ResolutionResult.notFound(groupId, artifactId);
    }

    private Optional<TreeMatch> findInDependencyTree(String groupId, String artifactId,
                                                      List<DependencyNode> tree) {
        String target = groupId + ":" + artifactId;
        TreeMatch bestMatch = null;

        for (DependencyNode root : tree) {
            TreeMatch match = findNearest(root, target, 0);
            if (match != null) {
                if (bestMatch == null || match.node().getDepth() < bestMatch.node().getDepth()) {
                    bestMatch = match;
                }
            }
        }
        return Optional.ofNullable(bestMatch);
    }

    private TreeMatch findNearest(DependencyNode node, String target, int currentDepth) {
        if (node.getArtifact().getShortCoordinate().equals(target) && !node.isExcluded()) {
            return new TreeMatch(node, node.getPathString());
        }
        TreeMatch best = null;
        for (DependencyNode child : node.getChildren()) {
            TreeMatch match = findNearest(child, target, currentDepth + 1);
            if (match != null) {
                if (best == null || match.node().getDepth() < best.node().getDepth()) {
                    best = match;
                }
            }
        }
        return best;
    }

    public record ResolutionResult(
        Artifact resolvedArtifact,
        String mediationRule,
        int depth,
        boolean isDirect,
        String trace
    ) {
        public static ResolutionResult notFound(String groupId, String artifactId) {
            return new ResolutionResult(
                new Artifact(groupId, artifactId, "NOT_FOUND", Scope.COMPILE),
                "NOT_FOUND",
                -1,
                false,
                "Artifact not found in dependency tree or BOM"
            );
        }

        public boolean isFound() {
            return !"NOT_FOUND".equals(mediationRule);
        }
    }

    private record TreeMatch(DependencyNode node, String path) {}
}
