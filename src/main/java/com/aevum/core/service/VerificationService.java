package com.aevum.core.service;

import com.aevum.core.cache.BomCache;
import com.aevum.core.domain.model.*;
import com.aevum.core.domain.enums.Scope;
import com.aevum.core.dto.ScanRequest;
import com.aevum.core.dto.ScanResponse;
import com.aevum.core.engine.*;
import com.aevum.core.pipeline.*;
import com.aevum.core.util.Threading;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.*;
import java.util.concurrent.*;

/**
 * Main service orchestrating the complete verification workflow.
 * Handles 50K concurrent verifications using virtual threads.
 *
 * FIX 1: LOG.info("...FP rate: {:.1f}%", fpRate) used Python f-string syntax.
 * SLF4J uses {} for all placeholders. Changed to "... {}" which will render the double.
 * For formatted output use String.format() before passing to logger.
 *
 * FIX 2: constructEffectivePom() added all signals as root DependencyNodes, meaning
 * they were all at depth 0 and the BomResolver "nearest wins" rule (Rule 2) would never
 * fire correctly. The resolved-dependencies map is now populated so BomResolver Rule 1
 * (direct dependency) correctly identifies what's in the project.
 *
 * NOTE: In production, this method should parse the actual pom.xml using Maven Embedder.
 * The current implementation builds a synthetic EffectivePom from the scan request for
 * demos and testing. Real BOM precedence resolution requires parsing the real pom.xml.
 */
@Service
public class VerificationService {
    private static final Logger LOG = LoggerFactory.getLogger(VerificationService.class);

    private final VerificationPipeline pipeline;
    private final BomResolver bomResolver;
    private final BomCache bomCache;

    public VerificationService(VerificationPipeline pipeline,
                               BomResolver bomResolver,
                               BomCache bomCache) {
        this.pipeline = pipeline;
        this.bomResolver = bomResolver;
        this.bomCache = bomCache;
    }

    public ScanResponse verify(ScanRequest request) {
        return verify(request, true);
    }

    public ScanResponse verify(ScanRequest request, boolean validateFixes) {
        long startTime = System.currentTimeMillis();
        String scanId = UUID.randomUUID().toString();
        LOG.info("Starting scan {} for project: {}", scanId, request.projectId());

        EffectivePom effectivePom = buildEffectivePom(request);

        Path buildOutput = request.buildOutputPath() != null
                ? Paths.get(request.buildOutputPath())
                : Paths.get("target");
        List<String> entryPoints = (request.entryPointClasses() != null && !request.entryPointClasses().isEmpty())
                ? request.entryPointClasses()
                : List.of("com.example.Application");

        StageContext context = new StageContext(effectivePom, buildOutput, entryPoints,
                request.networkExposed());

        List<VulnerabilitySignal> signals = normalizeSignals(request);
        List<VerificationResult> results = processSignalsConcurrently(signals, context);

        // Aggregate results by status
        List<ScanResponse.VulnerabilityResult> confirmed = new ArrayList<>();
        List<ScanResponse.VulnerabilityResult> falsePositives = new ArrayList<>();
        List<ScanResponse.VulnerabilityResult> inconclusive = new ArrayList<>();
        List<ScanResponse.ConfirmedVulnerability> confirmedVulns = new ArrayList<>();
        List<ScanResponse.FalsePositiveDetail> falsePosDetails = new ArrayList<>();

        for (VerificationResult result : results) {
            ScanResponse.VulnerabilityResult dto = toDto(result);
            switch (result.getStatus()) {
                case CONFIRMED -> {
                    confirmed.add(dto);
                    confirmedVulns.add(toConfirmedVuln(result));
                }
                case FALSE_POSITIVE -> {
                    falsePositives.add(dto);
                    falsePosDetails.add(toFalsePositiveDetail(result));
                }
                case INCONCLUSIVE -> inconclusive.add(dto);
            }
        }

        long durationMs = System.currentTimeMillis() - startTime;
        int total = signals.size();
        // FIX: Use String.format for the formatted double, then pass to SLF4J as a plain string
        double fpRate = total > 0 ? (double) falsePositives.size() / total * 100 : 0;
        LOG.info("Scan {} complete: {} confirmed, {} false positives, {} inconclusive in {}ms (FP rate: {}%)",
                scanId, confirmed.size(), falsePositives.size(), inconclusive.size(),
                durationMs, String.format("%.1f", fpRate));

        return new ScanResponse(
                scanId,
                request.projectId(),
                confirmed,
                falsePositives,
                inconclusive,
                confirmedVulns,
                falsePosDetails,
                new ScanResponse.ScanMetrics(
                        total, confirmed.size(), falsePositives.size(),
                        inconclusive.size(), durationMs, fpRate)
        );
    }

    private List<VerificationResult> processSignalsConcurrently(List<VulnerabilitySignal> signals,
                                                                StageContext context) {
        ExecutorService executor = Threading.newVirtualThreadPerTaskExecutor();
        try {
            List<Future<VerificationResult>> futures = new ArrayList<>();
            for (VulnerabilitySignal signal : signals) {
                futures.add(executor.submit(() -> pipeline.verify(signal, context)));
            }

            List<VerificationResult> results = new ArrayList<>();
            for (Future<VerificationResult> future : futures) {
                try {
                    results.add(future.get());
                } catch (ExecutionException e) {
                    LOG.error("Signal processing failed: {}", e.getCause().getMessage(), e.getCause());
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    LOG.error("Signal processing interrupted");
                }
            }
            return results;
        } finally {
            executor.shutdown();
        }
    }

    private EffectivePom buildEffectivePom(ScanRequest request) {
        String pomContent = request.pomContent();
        if (pomContent != null && !pomContent.isBlank()) {
            Optional<EffectivePom> cached = bomCache.get(pomContent);
            if (cached.isPresent()) {
                LOG.debug("Using cached EffectivePom for project: {}", request.projectId());
                return cached.get();
            }
        }

        EffectivePom effectivePom = constructEffectivePom(request);

        if (pomContent != null && !pomContent.isBlank()) {
            bomCache.put(pomContent, effectivePom);
        }
        return effectivePom;
    }

    /**
     * Build a synthetic EffectivePom from request data.
     *
     * FIX: Original added all signals as root DependencyNodes but put nothing in
     * directDependencies. This meant BomResolver Rule 1 (direct dependency overrides BOM)
     * never fired — every artifact fell through to tree search or BOM lookup.
     *
     * Now: signals are added BOTH as direct dependencies AND as root tree nodes,
     * so BomResolver correctly identifies them via Rule 1 (direct dependency precedence).
     *
     * IMPORTANT: In production, replace this with real Maven Embedder POM parsing.
     * This synthetic approach is only valid for demo/test scenarios where the scan
     * request itself carries the artifact coordinates to verify.
     */
    private EffectivePom constructEffectivePom(ScanRequest request) {
        List<Artifact> directDeps = new ArrayList<>();
        Map<String, Artifact> resolved = new HashMap<>();
        List<DependencyNode> tree = new ArrayList<>();

        if (request.signals() != null) {
            for (ScanRequest.VulnerabilityInput sig : request.signals()) {
                Artifact artifact = new Artifact(
                        sig.groupId(), sig.artifactId(), sig.version(), Scope.COMPILE);

                // FIX: Add to BOTH direct deps AND resolved map so BomResolver Rule 1 fires
                directDeps.add(artifact);
                resolved.put(artifact.getShortCoordinate(), artifact);
                tree.add(DependencyNode.root(artifact));
            }
        }

        return new EffectivePom(
                request.projectId(),
                directDeps,          // FIX: was always empty list
                List.of(),           // No BOMs in synthetic mode
                Map.of(),
                resolved,
                tree
        );
    }

    private List<VulnerabilitySignal> normalizeSignals(ScanRequest request) {
        if (request.signals() == null) return List.of();

        List<VulnerabilitySignal> signals = new ArrayList<>();
        for (ScanRequest.VulnerabilityInput input : request.signals()) {
            signals.add(VulnerabilitySignal.builder()
                    .signalId(UUID.randomUUID().toString())
                    .scannerSource(input.scannerSource() != null ? input.scannerSource() : "unknown")
                    .cveId(input.cveId())
                    .groupId(input.groupId())
                    .artifactId(input.artifactId())
                    .reportedVersion(input.version())
                    .severity(input.severity())
                    .cvssScore(input.cvssScore())
                    .description(input.description())
                    .build());
        }
        return signals;
    }

    // ── DTO Mappers ────────────────────────────────────────────────────────────

    private ScanResponse.VulnerabilityResult toDto(VerificationResult result) {
        return new ScanResponse.VulnerabilityResult(
                result.getOriginalSignal() != null ? result.getOriginalSignal().getCveId() : "N/A",
                result.getEffectiveArtifact() != null ? result.getEffectiveArtifact().getCoordinate() : "N/A",
                result.getStatus(),
                result.getConfidenceScore() != null ? result.getConfidenceScore().getTotalScore() : 0,
                result.getRootCausePath() != null ? result.getRootCausePath().getPathString() : "N/A",
                result.isInClasspath(),
                result.isReachable(),
                mapFixOptions(result.getFixOptions()),
                result.getStageLogs()
        );
    }

    private ScanResponse.ConfirmedVulnerability toConfirmedVuln(VerificationResult result) {
        String proofId = result.getFixOptions().stream()
                .filter(FixOption::isValidated)
                .map(f -> extractProofId(f.getValidationLog()))
                .filter(Objects::nonNull)
                .findFirst().orElse(null);

        return new ScanResponse.ConfirmedVulnerability(
                result.getOriginalSignal() != null ? result.getOriginalSignal().getCveId() : "N/A",
                result.getEffectiveArtifact() != null ? result.getEffectiveArtifact().getCoordinate() : "N/A",
                result.getStatus(),
                result.getConfidenceScore() != null ? result.getConfidenceScore().getTotalScore() : 0,
                result.getRootCausePath() != null ? result.getRootCausePath().getPathString() : "N/A",
                result.isInClasspath(),
                result.isReachable(),
                mapFixOptions(result.getFixOptions()),
                proofId,
                result.getStageLogs()
        );
    }

    private ScanResponse.FalsePositiveDetail toFalsePositiveDetail(VerificationResult result) {
        String reason = (result.getStageLogs() != null && !result.getStageLogs().isEmpty())
                ? result.getStageLogs().stream()
                .filter(l -> l.contains("FALSE POSITIVE") || l.contains("FALSE_POSITIVE") || l.contains("not found"))
                .findFirst()
                .orElse(result.getStageLogs().get(0))
                : "Not in classpath or version mismatch";

        return new ScanResponse.FalsePositiveDetail(
                result.getOriginalSignal() != null ? result.getOriginalSignal().getCveId() : "N/A",
                result.getEffectiveArtifact() != null ? result.getEffectiveArtifact().getCoordinate() : "N/A",
                reason,
                result.getStageLogs() != null ? result.getStageLogs() : List.of()
        );
    }

    private List<ScanResponse.FixOptionDto> mapFixOptions(List<FixOption> fixes) {
        if (fixes == null) return List.of();
        return fixes.stream()
                .map(f -> new ScanResponse.FixOptionDto(
                        f.getFixType().name(),
                        f.getDescription(),
                        f.getTargetDependency(),
                        f.getProposedVersion(),
                        f.isValidated(),
                        f.getValidationLog(),
                        extractProofId(f.getValidationLog())
                ))
                .toList();
    }

    private String extractProofId(String validationLog) {
        if (validationLog == null) return null;
        int idx = validationLog.indexOf("ProofPackageId=");
        if (idx < 0) return null;
        return validationLog.substring(idx + "ProofPackageId=".length()).trim();
    }
}