package com.aevum.core.domain.model;

import java.time.Instant;
import java.util.*;

/**
 * Cryptographic proof package for auditors.
 */
public final class ProofPackage {
    private final String packageId;
    private final String signalId;
    private final String beforeClasspath;
    private final String afterClasspath;
    private final String buildLog;
    private final String testResults;
    private final String sha256Hash;
    private final Instant generatedAt;
    private final Map<String, String> evidence;

    public ProofPackage(String packageId, String signalId, String beforeClasspath, String afterClasspath,
                        String buildLog, String testResults, String sha256Hash,
                        Map<String, String> evidence) {
        this.packageId = Objects.requireNonNull(packageId);
        this.signalId = Objects.requireNonNull(signalId);
        this.beforeClasspath = beforeClasspath;
        this.afterClasspath = afterClasspath;
        this.buildLog = buildLog;
        this.testResults = testResults;
        this.sha256Hash = sha256Hash;
        this.generatedAt = Instant.now();
        this.evidence = Map.copyOf(evidence != null ? evidence : Collections.emptyMap());
    }

    public String getPackageId() { return packageId; }
    public String getSignalId() { return signalId; }
    public String getBeforeClasspath() { return beforeClasspath; }
    public String getAfterClasspath() { return afterClasspath; }
    public String getBuildLog() { return buildLog; }
    public String getTestResults() { return testResults; }
    public String getSha256Hash() { return sha256Hash; }
    public Instant getGeneratedAt() { return generatedAt; }
    public Map<String, String> getEvidence() { return evidence; }

    @Override
    public String toString() {
        return "Proof[" + packageId + " SHA=" + sha256Hash + "]";
    }
}
