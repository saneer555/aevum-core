package com.aevum.core.pipeline;

import com.aevum.core.domain.model.VulnerabilitySignal;
import org.springframework.stereotype.Component;

import java.util.*;

@Component
public class SignalEnricher {

    /**
     * Enrich incoming signal with safeVersions.
     * This ensures FixEngine can generate VERSION_ALIGNMENT fixes.
     */
    public VulnerabilitySignal enrich(VulnerabilitySignal raw) {

        List<String> safeVersions = resolveSafeVersions(raw.getCveId());

        return VulnerabilitySignal.builder()
                .signalId(raw.getSignalId())
                .scannerSource(raw.getScannerSource())
                .scannerReportId(raw.getScannerReportId())
                .cveId(raw.getCveId())
                .groupId(raw.getGroupId())
                .artifactId(raw.getArtifactId())
                .reportedVersion(raw.getReportedVersion())
                .severity(raw.getSeverity())
                .cvssScore(raw.getCvssScore())
                .description(raw.getDescription())
                .cwes(raw.getCwes())
                .safeVersions(safeVersions) // ✅ CRITICAL FIX
                .discoveredAt(raw.getDiscoveredAt())
                .rawPayload(raw.getRawPayload())
                .sha256Hash(raw.getSha256Hash())
                .metadata(raw.getMetadata())
                .build();
    }

    /**
     * Temporary mapping.
     * Replace later with DB/API-based CVE metadata service.
     */
    private List<String> resolveSafeVersions(String cveId) {

        switch (cveId) {

            case "CVE-2021-44228":
            case "CVE-2021-45046":
                return List.of("2.17.1");

            case "CVE-2022-42889":
                return List.of("1.10.0");

            default:
                return Collections.emptyList();
        }
    }
}