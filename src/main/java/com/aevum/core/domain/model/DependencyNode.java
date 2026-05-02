package com.aevum.core.domain.model;

import java.util.*;

/**
 * Node in the dependency tree. Immutable after construction.
 */
public final class DependencyNode {
    private final Artifact artifact;
    private final List<DependencyNode> children;
    private final DependencyNode parent;
    private final int depth;
    private final boolean isDirect;
    private final String exclusionReason;

    private DependencyNode(Artifact artifact, DependencyNode parent, List<DependencyNode> children,
                           int depth, boolean isDirect, String exclusionReason) {
        this.artifact = Objects.requireNonNull(artifact);
        this.parent = parent;
        this.children = List.copyOf(children != null ? children : Collections.emptyList());
        this.depth = depth;
        this.isDirect = isDirect;
        this.exclusionReason = exclusionReason;
    }

    public static DependencyNode root(Artifact artifact) {
        return new DependencyNode(artifact, null, null, 0, true, null);
    }

    public static DependencyNode child(Artifact artifact, DependencyNode parent, boolean isDirect) {
        return new DependencyNode(artifact, parent, null, parent.depth + 1, isDirect, null);
    }

    public static DependencyNode excluded(Artifact artifact, DependencyNode parent, String reason) {
        return new DependencyNode(artifact, parent, null, parent.depth + 1, false, reason);
    }

    public DependencyNode withChildren(List<DependencyNode> children) {
        return new DependencyNode(this.artifact, this.parent, children, this.depth, this.isDirect, this.exclusionReason);
    }

    public Artifact getArtifact() { return artifact; }
    public List<DependencyNode> getChildren() { return children; }
    public DependencyNode getParent() { return parent; }
    public int getDepth() { return depth; }
    public boolean isDirect() { return isDirect; }
    public boolean isExcluded() { return exclusionReason != null; }
    public String getExclusionReason() { return exclusionReason; }

    /**
     * Returns the full path from root to this node.
     */
    public List<Artifact> getPath() {
        List<Artifact> path = new ArrayList<>();
        DependencyNode current = this;
        while (current != null) {
            path.add(0, current.artifact);
            current = current.parent;
        }
        return path;
    }

    /**
     * Returns path as string: parent -> child -> target
     */
    public String getPathString() {
        return String.join(" → ", getPath().stream().map(Artifact::getShortCoordinate).toList());
    }

    @Override
    public String toString() {
        return artifact.getCoordinate() + " (depth=" + depth + ")";
    }
}
