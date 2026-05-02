package com.aevum.core.dto;

import com.aevum.core.domain.enums.VerificationStatus;
import java.util.*;

/**
 * Response DTO for vulnerability scan verification.
 */
public record ScanResponse(
    String scanId,
    String projectId,
    List<VulnerabilityResult> confirmed,
    List<VulnerabilityResult> falsePositives,
    List<VulnerabilityResult> inconclusive,
    List<ConfirmedVulnerability> confirmedVulnerabilities,
    List<FalsePositiveDetail> falsePositiveDetails,
    ScanMetrics metrics
) {
    public record VulnerabilityResult(
        String cveId,
        String coordinate,
        VerificationStatus status,
        int confidenceScore,
        String rootCausePath,
        boolean inClasspath,
        boolean reachable,
        List<FixOptionDto> fixOptions,
        List<String> stageLogs
    ) {}

    public record FixOptionDto(
        String fixType,
        String description,
        String targetDependency,
        String proposedVersion,
        boolean validated,
        String validationLog,
        String proofPackageId
    ) {}

    public record ConfirmedVulnerability(
        String cveId,
        String coordinate,
        VerificationStatus status,
        int confidenceScore,
        String rootCausePath,
        boolean inClasspath,
        boolean reachable,
        List<FixOptionDto> fixOptions,
        String proofPackageId,
        List<String> stageLogs
    ) {}

    public record FalsePositiveDetail(
        String cveId,
        String coordinate,
        String reason,
        List<String> evidence
    ) {}

    public record ScanMetrics(
        int totalSignals,
        int confirmedCount,
        int falsePositiveCount,
        int inconclusiveCount,
        long durationMs,
        double falsePositiveRate
    ) {}
}
