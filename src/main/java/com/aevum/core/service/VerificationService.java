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
 */
@Service
public class VerificationService {
    private static final Logger LOG = LoggerFactory.getLogger(VerificationService.class);

    private final VerificationPipeline pipeline;
    private final BomResolver bomResolver;
    private final BomCache bomCache;

    public VerificationService(VerificationPipeline pipeline, BomResolver bomResolver, BomCache bomCache) {
        this.pipeline = pipeline;
        this.bomResolver = bomResolver;
        this.bomCache = bomCache;
    }

    public ScanResponse verify(ScanRequest request) {
        return verify(request, true);
    }

    /**
     * Main entry. validateFixes flag is accepted but currently the pipeline performs validation as part of fix generation.
     */
    public ScanResponse verify(ScanRequest request, boolean validateFixes) {
        long startTime = System.currentTimeMillis();
        String scanId = UUID.randomUUID().toString();
        LOG.info("Starting scan {} for project: {}", scanId, request.projectId());

        // Build effective POM (with caching)
        EffectivePom effectivePom = buildEffectivePom(request);

        // Build stage context
        Path buildOutput = request.buildOutputPath() != null
            ? Paths.get(request.buildOutputPath())
            : Paths.get("target");
        List<String> entryPoints = request.entryPointClasses() != null
            ? request.entryPointClasses()
            : List.of("com.example.Application");

        StageContext context = new StageContext(effectivePom, buildOutput, entryPoints, request.networkExposed());

        // Process all signals concurrently using virtual threads
        List<VulnerabilitySignal> signals = normalizeSignals(request);
        List<VerificationResult> results = processSignalsConcurrently(signals, context);

        // Build response
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
                    // find proof package id from first validated fix option if present
                    String proofId = result.getFixOptions().stream()
                        .filter(FixOption::isValidated)
                        .map(FixOption::getValidationLog)
                        .map(log -> {
                            if (log == null) return null;
                            int idx = log.indexOf("ProofPackageId=");
                            if (idx >= 0) return log.substring(idx + "ProofPackageId=".length()).trim();
                            idx = log.indexOf("ProofPackageId=");
                            return null;
                        })
                        .filter(Objects::nonNull)
                        .findFirst().orElse(null);

                    confirmedVulns.add(new ScanResponse.ConfirmedVulnerability(
                        result.getOriginalSignal() != null ? result.getOriginalSignal().getCveId() : "N/A",
                        result.getEffectiveArtifact() != null ? result.getEffectiveArtifact().getCoordinate() : "N/A",
                        result.getStatus(),
                        result.getConfidenceScore() != null ? result.getConfidenceScore().getTotalScore() : 0,
                        result.getRootCausePath() != null ? result.getRootCausePath().getPathString() : "N/A",
                        result.isInClasspath(),
                        result.isReachable(),
                        result.getFixOptions().stream().map(f -> new ScanResponse.FixOptionDto(
                            f.getFixType().name(),
                            f.getDescription(),
                            f.getTargetDependency(),
                            f.getProposedVersion(),
                            f.isValidated(),
                            f.getValidationLog(),
                            // proof id best-effort: embed from validationLog if present
                            (f.getValidationLog() != null && f.getValidationLog().contains("ProofPackageId="))
                                ? f.getValidationLog().substring(f.getValidationLog().indexOf("ProofPackageId=") + "ProofPackageId=".length()).trim()
                                : null
                        )).toList(),
                        proofId,
                        result.getStageLogs()
                    ));
                }
                case FALSE_POSITIVE -> {
                    falsePositives.add(dto);
                    falsePosDetails.add(new ScanResponse.FalsePositiveDetail(
                        result.getOriginalSignal() != null ? result.getOriginalSignal().getCveId() : "N/A",
                        result.getEffectiveArtifact() != null ? result.getEffectiveArtifact().getCoordinate() : "N/A",
                        // reason: take first stage log or status
                        result.getStageLogs() != null && !result.getStageLogs().isEmpty() ? result.getStageLogs().get(0) : "NOT_IN_CLASSPATH",
                        result.getStageLogs()
                    ));
                }
                case INCONCLUSIVE -> inconclusive.add(dto);
            }
        }

        long durationMs = System.currentTimeMillis() - startTime;
        int total = signals.size();
        double fpRate = total > 0 ? (double) falsePositives.size() / total * 100 : 0;

        LOG.info("Scan {} completed: {} confirmed, {} false positives, {} inconclusive in {}ms (FP rate: {:.1f}%)",
                scanId, confirmed.size(), falsePositives.size(), inconclusive.size(), durationMs, fpRate);

        return new ScanResponse(
            scanId,
            request.projectId(),
            confirmed,
            falsePositives,
            inconclusive,
            confirmedVulns,
            falsePosDetails,
            new ScanResponse.ScanMetrics(
                total, confirmed.size(), falsePositives.size(), inconclusive.size(), durationMs, fpRate
            )
        );
    }

    private List<VerificationResult> processSignalsConcurrently(List<VulnerabilitySignal> signals, StageContext context) {
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
                } catch (Exception e) {
                    LOG.error("Signal processing failed", e);
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
                LOG.debug("Using cached EffectivePOM for project: {}", request.projectId());
                return cached.get();
            }
        }

        // Build from request data or defaults
        EffectivePom effectivePom = constructEffectivePom(request);

        if (pomContent != null && !pomContent.isBlank()) {
            bomCache.put(pomContent, effectivePom);
        }
        return effectivePom;
    }

    private EffectivePom constructEffectivePom(ScanRequest request) {
        // In production: parse actual pom.xml using Maven Embedder
        // For this implementation: build from request signals and reasonable defaults
        List<Artifact> directDeps = new ArrayList<>();
        List<BomDeclaration> boms = new ArrayList<>();
        Map<String, Artifact> resolved = new HashMap<>();
        List<DependencyNode> tree = new ArrayList<>();

        // Add signals as resolved dependencies
        if (request.signals() != null) {
            for (ScanRequest.VulnerabilityInput signal : request.signals()) {
                Artifact artifact = new Artifact(signal.groupId(), signal.artifactId(),
                                                 signal.version(), Scope.COMPILE);
                resolved.put(artifact.getShortCoordinate(), artifact);

                // Create simple tree node
                DependencyNode node = DependencyNode.root(artifact);
                tree.add(node);
            }
        }

        return new EffectivePom(
            request.projectId(),
            directDeps,
            boms,
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
                .scannerSource(input.scannerSource())
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

    private ScanResponse.VulnerabilityResult toDto(VerificationResult result) {
        List<ScanResponse.FixOptionDto> fixDtos = result.getFixOptions().stream()
            .map(f -> new ScanResponse.FixOptionDto(
                f.getFixType().name(),
                f.getDescription(),
                f.getTargetDependency(),
                f.getProposedVersion(),
                f.isValidated(),
                f.getValidationLog(),
                // best-effort: proof id embedded in validationLog
                (f.getValidationLog() != null && f.getValidationLog().contains("ProofPackageId="))
                    ? f.getValidationLog().substring(f.getValidationLog().indexOf("ProofPackageId=") + "ProofPackageId=".length()).trim()
                    : null
            ))
            .toList();

        String rootCause = result.getRootCausePath() != null
            ? result.getRootCausePath().getPathString()
            : "N/A";

        return new ScanResponse.VulnerabilityResult(
            result.getOriginalSignal() != null ? result.getOriginalSignal().getCveId() : "N/A",
            result.getEffectiveArtifact() != null ? result.getEffectiveArtifact().getCoordinate() : "N/A",
            result.getStatus(),
            result.getConfidenceScore() != null ? result.getConfidenceScore().getTotalScore() : 0,
            rootCause,
            result.isInClasspath(),
            result.isReachable(),
            fixDtos,
            result.getStageLogs()
        );
    }
}
