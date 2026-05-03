package com.aevum.core.engine;

import com.aevum.core.domain.enums.FixType;
import com.aevum.core.domain.enums.VerificationStatus;
import com.aevum.core.domain.model.*;
import com.aevum.core.engine.fix.FixRankingService;
import com.aevum.core.engine.fix.FixValidator;
import com.aevum.core.engine.fix.VersionConflictDetector;
import com.aevum.core.engine.version.SafeVersionFinder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.nio.file.Path;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.*;
import java.util.stream.Collectors;

@Component
public class FixEngine {
    private static final Logger LOG = LoggerFactory.getLogger(FixEngine.class);

    private final SafeVersionFinder safeVersionFinder;
    private final FixValidator fixValidator;
    private final FixRankingService fixRankingService;
    private final VersionConflictDetector conflictDetector;
    private static final Semaphore BUILD_SEMAPHORE = new Semaphore(4);

    public FixEngine(SafeVersionFinder safeVersionFinder,
                     FixValidator fixValidator,
                     FixRankingService fixRankingService,
                     VersionConflictDetector conflictDetector) {
        this.safeVersionFinder = safeVersionFinder;
        this.fixValidator = fixValidator;
        this.fixRankingService = fixRankingService;
        this.conflictDetector = conflictDetector;
    }

    public List<FixOption> generateFixes(VerificationResult result, EffectivePom effectivePom, boolean validate) {
        if (result.getStatus() != VerificationStatus.CONFIRMED) {
            return Collections.emptyList();
        }
        int score = result.getConfidenceScore() != null ? result.getConfidenceScore().getTotalScore() : 0;
        if (score < 90) {
            return Collections.emptyList();
        }

        Artifact vulnerable = result.getEffectiveArtifact();
        if (vulnerable == null) {
            return Collections.emptyList();
        }

        LOG.info("Generating fixes for: {} ({})", result.getSignalId(), vulnerable.getCoordinate());

        List<FixOption> candidates = new ArrayList<>();

        // PRIMARY: Use signal's safeVersions directly
        buildVersionAlignmentFix(vulnerable, result, candidates);

        buildExclusionFix(result, effectivePom, candidates);
        buildParentUpgradeFix(result, effectivePom, candidates);

        if (candidates.isEmpty()) {
            LOG.warn("No fix candidates for: {}", vulnerable.getCoordinate());
            return Collections.emptyList();
        }

        if (!validate) {
            return candidates;
        }

        List<FixOption> validated = validateCandidatesInParallel(candidates, result);
        if (validated.isEmpty()) {
            return Collections.emptyList();
        }

        return fixRankingService.rankFixes(validated, vulnerable.getVersion()).getAllFixes();
    }

    // ONLY buildVersionAlignmentFix method — uses signal.getSafeVersions() directly
    private void buildVersionAlignmentFix(Artifact vulnerable, VerificationResult result, List<FixOption> out) {
        VulnerabilitySignal signal = result.getOriginalSignal();
        String currentVersion = vulnerable.getVersion();

        LOG.info("DEBUG FIX: signal={}, safeVersions={}, current={}",
                signal != null ? signal.getCveId() : "null",
                signal != null ? signal.getSafeVersions() : "null",
                currentVersion);

        if (signal == null || signal.getSafeVersions() == null || signal.getSafeVersions().isEmpty()) {
            LOG.warn("No safeVersions for: {}", vulnerable.getShortCoordinate());
            return;
        }

        String minimum = signal.getSafeVersions().get(0);
        if (minimum.equals(currentVersion)) {
            LOG.warn("Safe version same as current: {}", currentVersion);
            return;
        }

        out.add(FixOption.builder()
                .fixType(FixType.VERSION_ALIGNMENT)
                .description("Align " + vulnerable.getShortCoordinate()
                        + " from " + currentVersion + " to " + minimum + " (minimum safe version)")
                .targetDependency(vulnerable.getShortCoordinate())
                .proposedVersion(minimum)
                .validated(false)
                .validationLog("Candidate — awaiting build+test validation")
                .affectedArtifacts(List.of(vulnerable.getShortCoordinate()))
                .build());

        LOG.info("Added fix: {} → {}", currentVersion, minimum);
    }

    private void buildExclusionFix(VerificationResult result, EffectivePom effectivePom, List<FixOption> out) {
        RootCausePath rootCause = result.getRootCausePath();
        if (rootCause == null || rootCause.getPath().size() < 2) return;
        if (rootCause.getDepth() == 0) return;

        Artifact sourceDep = rootCause.getPath().get(rootCause.getPath().size() - 2);
        Artifact vulnerable = result.getEffectiveArtifact();

        out.add(FixOption.builder()
                .fixType(FixType.DEPENDENCY_EXCLUSION)
                .description("Exclude " + vulnerable.getShortCoordinate()
                        + " from " + sourceDep.getShortCoordinate())
                .targetDependency(sourceDep.getShortCoordinate())
                .exclusionTarget(vulnerable.getShortCoordinate())
                .validated(false)
                .validationLog("Candidate — awaiting build+test validation")
                .affectedArtifacts(List.of(sourceDep.getShortCoordinate(), vulnerable.getShortCoordinate()))
                .build());
    }

    private void buildParentUpgradeFix(VerificationResult result, EffectivePom effectivePom, List<FixOption> out) {
        RootCausePath rootCause = result.getRootCausePath();
        if (rootCause == null || rootCause.getPath().isEmpty()) return;

        Artifact rootDep = rootCause.getPath().get(0);
        String currentVersion = rootDep.getVersion();
        String[] parts = currentVersion.split("\\.");
        if (parts.length < 2) return;

        try {
            int minor = Integer.parseInt(parts[1].replaceAll("[^0-9]", ""));
            String proposedVersion = parts[0] + "." + (minor + 1) + ".0";

            out.add(FixOption.builder()
                    .fixType(FixType.PARENT_UPGRADE)
                    .description("Upgrade " + rootDep.getShortCoordinate()
                            + " from " + currentVersion + " to " + proposedVersion)
                    .targetDependency(rootDep.getShortCoordinate())
                    .proposedVersion(proposedVersion)
                    .validated(false)
                    .validationLog("Candidate — parent upgrade requires regression testing")
                    .affectedArtifacts(List.of(rootDep.getShortCoordinate()))
                    .build());
        } catch (NumberFormatException e) {
            LOG.debug("Cannot parse version: {}", currentVersion);
        }
    }

    private List<FixOption> validateCandidatesInParallel(List<FixOption> candidates, VerificationResult result) {
        ExecutorService exec = com.aevum.core.util.Threading.newVirtualThreadPerTaskExecutor();
        try {
            List<CompletableFuture<Optional<FixOption>>> futures = candidates.stream()
                    .map(c -> CompletableFuture.supplyAsync(() -> validateOne(c, Path.of(".")), exec))
                    .collect(Collectors.toList());

            return futures.stream()
                    .map(CompletableFuture::join)
                    .filter(Optional::isPresent)
                    .map(Optional::get)
                    .collect(Collectors.toList());
        } finally {
            exec.shutdown();
        }
    }

    private Optional<FixOption> validateOne(FixOption candidate, Path projectDir) {
        try {
            BUILD_SEMAPHORE.acquire();
            FixValidator.FixValidationResult res = fixValidator.validateFix(projectDir, candidate, Duration.ofMinutes(5));

            if (res.passed) {
                String proofId = res.proofPackage != null ? res.proofPackage.getId() : "unknown";
                return Optional.of(FixOption.builder()
                        .fixType(candidate.getFixType())
                        .description(candidate.getDescription())
                        .targetDependency(candidate.getTargetDependency())
                        .proposedVersion(candidate.getProposedVersion())
                        .exclusionTarget(candidate.getExclusionTarget())
                        .validated(true)
                        .validationLog("PASSED — ProofPackageId=" + proofId)
                        .affectedArtifacts(candidate.getAffectedArtifacts())
                        .build());
            }
            return Optional.empty();
        } catch (Exception e) {
            LOG.warn("Validation exception: {}", e.getMessage());
            return Optional.empty();
        } finally {
            BUILD_SEMAPHORE.release();
        }
    }
}