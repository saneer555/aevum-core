package com.aevum.core.domain.model;

import com.aevum.core.domain.enums.VerificationStatus;
import java.time.Instant;
import java.util.*;

/**
 * Final result of the 6-stage verification pipeline.
 */
public final class VerificationResult {
    private final String resultId;
    private final String signalId;
    private final VulnerabilitySignal originalSignal;
    private final VerificationStatus status;
    private final ConfidenceScore confidenceScore;
    private final RootCausePath rootCausePath;
    private final Artifact effectiveArtifact;
    private final boolean isInClasspath;
    private final boolean isReachable;
    private final List<FixOption> fixOptions;
    private final ProofPackage proofPackage;
    private final Instant completedAt;
    private final List<String> stageLogs;
    private final Map<String, Object> metadata;

    private VerificationResult(Builder builder) {
        this.resultId = Objects.requireNonNull(builder.resultId);
        this.signalId = Objects.requireNonNull(builder.signalId);
        this.originalSignal = builder.originalSignal;
        this.status = Objects.requireNonNull(builder.status);
        this.confidenceScore = builder.confidenceScore;
        this.rootCausePath = builder.rootCausePath;
        this.effectiveArtifact = builder.effectiveArtifact;
        this.isInClasspath = builder.isInClasspath;
        this.isReachable = builder.isReachable;
        this.fixOptions = List.copyOf(builder.fixOptions != null ? builder.fixOptions : Collections.emptyList());
        this.proofPackage = builder.proofPackage;
        this.completedAt = builder.completedAt != null ? builder.completedAt : Instant.now();
        this.stageLogs = List.copyOf(builder.stageLogs != null ? builder.stageLogs : Collections.emptyList());
        this.metadata = Map.copyOf(builder.metadata != null ? builder.metadata : Collections.emptyMap());
    }

    public String getResultId() { return resultId; }
    public String getSignalId() { return signalId; }
    public VulnerabilitySignal getOriginalSignal() { return originalSignal; }
    public VerificationStatus getStatus() { return status; }
    public ConfidenceScore getConfidenceScore() { return confidenceScore; }
    public RootCausePath getRootCausePath() { return rootCausePath; }
    public Artifact getEffectiveArtifact() { return effectiveArtifact; }
    public boolean isInClasspath() { return isInClasspath; }
    public boolean isReachable() { return isReachable; }
    public List<FixOption> getFixOptions() { return fixOptions; }
    public ProofPackage getProofPackage() { return proofPackage; }
    public Instant getCompletedAt() { return completedAt; }
    public List<String> getStageLogs() { return stageLogs; }
    public Map<String, Object> getMetadata() { return metadata; }

    public boolean hasFixOptions() {
        return status == VerificationStatus.CONFIRMED && !fixOptions.isEmpty();
    }

    public static Builder builder() { return new Builder(); }

    public static class Builder {
        private String resultId;
        private String signalId;
        private VulnerabilitySignal originalSignal;
        private VerificationStatus status;
        private ConfidenceScore confidenceScore;
        private RootCausePath rootCausePath;
        private Artifact effectiveArtifact;
        private boolean isInClasspath;
        private boolean isReachable;
        private List<FixOption> fixOptions;
        private ProofPackage proofPackage;
        private Instant completedAt;
        private List<String> stageLogs;
        private Map<String, Object> metadata;

        public Builder resultId(String val) { this.resultId = val; return this; }
        public Builder signalId(String val) { this.signalId = val; return this; }
        public Builder originalSignal(VulnerabilitySignal val) { this.originalSignal = val; return this; }
        public Builder status(VerificationStatus val) { this.status = val; return this; }
        public Builder confidenceScore(ConfidenceScore val) { this.confidenceScore = val; return this; }
        public Builder rootCausePath(RootCausePath val) { this.rootCausePath = val; return this; }
        public Builder effectiveArtifact(Artifact val) { this.effectiveArtifact = val; return this; }
        public Builder isInClasspath(boolean val) { this.isInClasspath = val; return this; }
        public Builder isReachable(boolean val) { this.isReachable = val; return this; }
        public Builder fixOptions(List<FixOption> val) { this.fixOptions = val; return this; }
        public Builder proofPackage(ProofPackage val) { this.proofPackage = val; return this; }
        public Builder completedAt(Instant val) { this.completedAt = val; return this; }
        public Builder stageLogs(List<String> val) { this.stageLogs = val; return this; }
        public Builder metadata(Map<String, Object> val) { this.metadata = val; return this; }

        public VerificationResult build() { return new VerificationResult(this); }
    }

    @Override
    public String toString() {
        return "Result[" + signalId + " " + status + " confidence=" + confidenceScore + "]";
    }
}
