package com.aevum.core.dto;

import java.util.*;

/**
 * Request DTO for vulnerability scan verification.
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
        String scannerSource,
        String cveId,
        String groupId,
        String artifactId,
        String version,
        String severity,
        double cvssScore,
        String description
    ) {}
}
