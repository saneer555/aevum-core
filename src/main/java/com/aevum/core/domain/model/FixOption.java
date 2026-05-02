package com.aevum.core.domain.model;

import com.aevum.core.domain.enums.FixType;
import java.util.*;

/**
 * A validated fix option.
 */
public final class FixOption {
    private final FixType fixType;
    private final String description;
    private final String targetDependency;
    private final String proposedVersion;
    private final String exclusionTarget;
    private final boolean validated;
    private final String validationLog;
    private final List<String> affectedArtifacts;

    private FixOption(Builder builder) {
        this.fixType = Objects.requireNonNull(builder.fixType);
        this.description = Objects.requireNonNull(builder.description);
        this.targetDependency = builder.targetDependency;
        this.proposedVersion = builder.proposedVersion;
        this.exclusionTarget = builder.exclusionTarget;
        this.validated = builder.validated;
        this.validationLog = builder.validationLog;
        this.affectedArtifacts = List.copyOf(builder.affectedArtifacts != null ? builder.affectedArtifacts : Collections.emptyList());
    }

    public FixType getFixType() { return fixType; }
    public String getDescription() { return description; }
    public String getTargetDependency() { return targetDependency; }
    public String getProposedVersion() { return proposedVersion; }
    public String getExclusionTarget() { return exclusionTarget; }
    public boolean isValidated() { return validated; }
    public String getValidationLog() { return validationLog; }
    public List<String> getAffectedArtifacts() { return affectedArtifacts; }

    public static Builder builder() { return new Builder(); }

    public static class Builder {
        private FixType fixType;
        private String description;
        private String targetDependency;
        private String proposedVersion;
        private String exclusionTarget;
        private boolean validated;
        private String validationLog;
        private List<String> affectedArtifacts;

        public Builder fixType(FixType val) { this.fixType = val; return this; }
        public Builder description(String val) { this.description = val; return this; }
        public Builder targetDependency(String val) { this.targetDependency = val; return this; }
        public Builder proposedVersion(String val) { this.proposedVersion = val; return this; }
        public Builder exclusionTarget(String val) { this.exclusionTarget = val; return this; }
        public Builder validated(boolean val) { this.validated = val; return this; }
        public Builder validationLog(String val) { this.validationLog = val; return this; }
        public Builder affectedArtifacts(List<String> val) { this.affectedArtifacts = val; return this; }

        public FixOption build() { return new FixOption(this); }
    }

    @Override
    public String toString() {
        return "Fix[" + fixType + "]: " + description + (validated ? " [VALIDATED]" : " [UNVALIDATED]");
    }
}
