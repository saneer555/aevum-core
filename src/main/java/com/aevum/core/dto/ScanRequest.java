package com.aevum.core.dto;

import java.util.List;

/**
 * Request DTO for vulnerability scan verification.
 *
 * FIX: Added {@code signalId} to {@link VulnerabilityInput} so that callers who supply
 * an explicit ID (e.g. "S1-DEDUP-01") have it preserved through the pipeline.
 * Without this field, every signal was assigned a random UUID and the original scanner
 * signal ID was silently discarded, making log correlation impossible.
 */
public record ScanRequest(
        String projectId,
        String pomContent,
        String buildOutputPath,
        List<String> entryPointClasses,
        boolean networkExposed,
        List<VulnerabilityInput> signals
) {
    public record VulnerabilityInput(
            /**
             * Optional caller-supplied ID (e.g. "S1-DEDUP-01"). When present it is
             * used as-is; otherwise a UUID is generated in {@code normalizeSignals()}.
             */
            String signalId,
            String scannerSource,
            String cveId,
            String groupId,
            String artifactId,
            String version,
            String vulnerableRange,
            List<String> safeVersions,
            String severity,
            double cvssScore,
            String description
    ) {}
}