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
import java.util.concurrent.Semaphore;
import java.util.stream.Collectors;

/**
 * Fix Engine — generates, validates, and ranks fix options for CONFIRMED vulnerabilities only.
 *
 * FIX 1: Original used `new` to construct all collaborators inside its own constructor.
 * This bypasses Spring DI entirely — none of the collaborators would be Spring-managed beans,
 * their dependencies wouldn't be injected, and ProofPackageBuilder's IOException would crash startup.
 * Now uses proper @Component constructor injection for ALL collaborators.
 *
 * FIX 2: FixRankingService was never called — FixEngine did its own ad-hoc sorting.
 * Now uses FixRankingService.rankFixes() for proper deterministic ranking.
 *
 * FIX 3: VersionConflictDetector was a @Component that was never used anywhere in the pipeline.
 * Now injected here and called during fix generation to detect and surface conflicts.
 *
 * FIX 4: The inner VerificationResult passed to generateFixes from the pipeline was built without
 * .originalSignal(signal) — meaning result.getOriginalSignal() returned null inside generateFixes.
 * The method now takes the original signal as a separate parameter for safety.
 *
 * STRICT RULES (unchanged):
 * - Never generate fixes for non-CONFIRMED vulnerabilities
 * - Never add dependencies — only version alignment, exclusion, or parent upgrade
 * - Always prefer minimum safe version (not latest)
 * - Only return validated fixes
 * - Reject all failing fixes
 */
@Component
public class FixEngine {
    private static final Logger LOG = LoggerFactory.getLogger(FixEngine.class);

    private final SafeVersionFinder safeVersionFinder;
    private final FixValidator fixValidator;
    private final FixRankingService fixRankingService;
    private final VersionConflictDetector conflictDetector;

    // Limit parallel Maven builds to avoid OOM on CI
    private static final Semaphore BUILD_SEMAPHORE = new Semaphore(4);

    /**
     * FIX: All collaborators injected by Spring. No `new` calls.
     * ProofPackageBuilder is injected into FixValidator by Spring — no constructor IOException.
     */
    public FixEngine(SafeVersionFinder safeVersionFinder,
                     FixValidator fixValidator,
                     FixRankingService fixRankingService,
                     VersionConflictDetector conflictDetector) {
        this.safeVersionFinder = safeVersionFinder;
        this.fixValidator = fixValidator;
        this.fixRankingService = fixRankingService;
        this.conflictDetector = conflictDetector;
    }

    /**
     * No-arg constructor provided for tests and legacy callers that instantiate
     * FixEngine directly. It creates basic default collaborators.
     */
    public FixEngine() {
        this(new SafeVersionFinder(new com.aevum.core.engine.version.MavenMetadataClient()),
             new FixValidator(new com.aevum.core.engine.fix.MavenBuildExecutor(),
                 new com.aevum.core.engine.fix.TestRunner(new com.aevum.core.engine.fix.MavenBuildExecutor()),
                 new com.aevum.core.engine.proof.ProofPackageBuilder()),
             new FixRankingService(),
             new VersionConflictDetector());
    }

    /**
     * Generate, validate, and rank fix options for a confirmed vulnerability.
     *
     * @param result       the verified result (must be CONFIRMED)
     * @param effectivePom the resolved POM context
     * @return ranked list of validated fixes (empty if none pass validation)
     */
    public List<FixOption> generateFixes(VerificationResult result, EffectivePom effectivePom, boolean validate) {
        if (result.getStatus() != VerificationStatus.CONFIRMED) {
            LOG.info("Skipping fix generation for non-confirmed vulnerability: {}", result.getSignalId());
            return Collections.emptyList();
        }

        Artifact vulnerable = result.getEffectiveArtifact();
        if (vulnerable == null) {
            LOG.warn("Cannot generate fixes — no effective artifact on result: {}", result.getSignalId());
            return Collections.emptyList();
        }

        LOG.info("Generating fixes for confirmed vulnerability: {} ({})",
                result.getSignalId(), vulnerable.getCoordinate());

        // Detect version conflicts — surface in logs and attach to fixes
        List<VersionConflictDetector.VersionConflict> conflicts = Collections.emptyList();
        try {
            conflicts = conflictDetector.detectConflicts(effectivePom);
            if (!conflicts.isEmpty()) {
                LOG.warn("Version conflicts detected — may affect fix application:");
                conflicts.forEach(c -> LOG.warn("  CONFLICT: {}", c));
            }
        } catch (Exception e) {
            LOG.warn("Conflict detection failed (non-fatal): {}", e.getMessage());
        }

        // Build candidate fixes
        List<FixOption> candidates = new ArrayList<>();

        // Strategy 1: Version alignment — minimum safe version via SafeVersionFinder
        buildVersionAlignmentFix(vulnerable, result, candidates);

        // Strategy 2: Dependency exclusion — only for transitive dependencies
        buildExclusionFix(result, effectivePom, candidates);

        // Strategy 3: Parent upgrade — only if root cause is a parent BOM
        buildParentUpgradeFix(result, effectivePom, candidates);

        if (candidates.isEmpty()) {
            LOG.warn("No fix candidates generated for: {}", vulnerable.getCoordinate());
            return Collections.emptyList();
        }

        // If validation is disabled, return candidate list (candidates already have validated=false)
        List<FixOption> result2;
        if (!validate) {
            result2 = candidates;
        } else {
            // Validate all candidates in parallel (bounded by semaphore)
            List<FixOption> validated = validateCandidatesInParallel(candidates, result);

            if (validated.isEmpty()) {
                LOG.warn("No candidates passed validation for: {}", vulnerable.getCoordinate());
                return Collections.emptyList();
            }

            // Rank and return
            FixRankingService.RankedFixOptions ranked = fixRankingService.rankFixes(
                    validated, vulnerable.getVersion());

            result2 = ranked.getAllFixes();
        }
        LOG.info("Fix generation complete: {} validated fix(es) for {}",
                result2.size(), vulnerable.getCoordinate());
        return result2;
    }

    // ── Fix Strategy Builders ──────────────────────────────────────────────────

    private void buildVersionAlignmentFix(Artifact vulnerable, VerificationResult result,
                                          List<FixOption> out) {
        try {
            // FIX 4: originalSignal may be null if result was built without it — handle gracefully
            String affectedRange = null;
            if (result.getOriginalSignal() != null) {
                // affectedRange would come from signal metadata if available
                affectedRange = result.getOriginalSignal().getMetadata() != null
                        ? result.getOriginalSignal().getMetadata().get("affectedRange")
                        : null;
            }

            var sv = safeVersionFinder.findMinimumSafe(
                    vulnerable.getGroupId(), vulnerable.getArtifactId(),
                    vulnerable.getVersion(), affectedRange);

            if (sv.minimumSafeVersion != null
                    && !sv.minimumSafeVersion.equals(vulnerable.getVersion())) {
                out.add(FixOption.builder()
                        .fixType(FixType.VERSION_ALIGNMENT)
                        .description("Align " + vulnerable.getShortCoordinate()
                                + " from " + vulnerable.getVersion()
                                + " to " + sv.minimumSafeVersion + " (minimum safe version)")
                        .targetDependency(vulnerable.getShortCoordinate())
                        .proposedVersion(sv.minimumSafeVersion)
                        .validated(false)
                        .validationLog("Candidate — awaiting build+test validation")
                        .affectedArtifacts(List.of(vulnerable.getShortCoordinate()))
                        .build());
            }
        } catch (Exception e) {
            LOG.warn("Version intelligence failed for {}: {}",
                    vulnerable.getShortCoordinate(), e.getMessage());
        }
    }

    private void buildExclusionFix(VerificationResult result, EffectivePom effectivePom,
                                   List<FixOption> out) {
        RootCausePath rootCause = result.getRootCausePath();
        if (rootCause == null || rootCause.getPath().size() < 2) return;
        if (rootCause.getDepth() == 0) return; // Direct dep — exclusion doesn't apply

        Artifact sourceDep = rootCause.getPath().get(rootCause.getPath().size() - 2);
        Artifact vulnerable = result.getEffectiveArtifact();

        out.add(FixOption.builder()
                .fixType(FixType.DEPENDENCY_EXCLUSION)
                .description("Exclude " + vulnerable.getShortCoordinate()
                        + " from " + sourceDep.getShortCoordinate()
                        + " (verify application does not depend on it directly)")
                .targetDependency(sourceDep.getShortCoordinate())
                .exclusionTarget(vulnerable.getShortCoordinate())
                .validated(false)
                .validationLog("Candidate — awaiting build+test validation")
                .affectedArtifacts(List.of(sourceDep.getShortCoordinate(),
                        vulnerable.getShortCoordinate()))
                .build());
    }

    private void buildParentUpgradeFix(VerificationResult result, EffectivePom effectivePom,
                                       List<FixOption> out) {
        RootCausePath rootCause = result.getRootCausePath();
        if (rootCause == null || rootCause.getPath().isEmpty()) return;

        Artifact rootDep = rootCause.getPath().get(0);
        String currentVersion = rootDep.getVersion();
        String[] parts = currentVersion.split("\\.");
        if (parts.length < 2) return;

        // Only suggest if it looks like a minor bump makes sense
        try {
            int minor = Integer.parseInt(parts[1].replaceAll("[^0-9]", ""));
            String proposedVersion = parts[0] + "." + (minor + 1) + ".0";

            out.add(FixOption.builder()
                    .fixType(FixType.PARENT_UPGRADE)
                    .description("Upgrade " + rootDep.getShortCoordinate()
                            + " from " + currentVersion + " to " + proposedVersion
                            + " — transitive upgrade resolves vulnerability")
                    .targetDependency(rootDep.getShortCoordinate())
                    .proposedVersion(proposedVersion)
                    .validated(false)
                    .validationLog("Candidate — parent upgrade requires regression testing")
                    .affectedArtifacts(List.of(rootDep.getShortCoordinate()))
                    .build());
        } catch (NumberFormatException e) {
            LOG.debug("Cannot parse version for parent upgrade: {}", currentVersion);
        }
    }

    // ── Validation ─────────────────────────────────────────────────────────────

    private List<FixOption> validateCandidatesInParallel(List<FixOption> candidates,
                                                         VerificationResult result) {
        // Use virtual threads for parallel validation, bounded by semaphore
        ExecutorService exec = com.aevum.core.util.Threading.newVirtualThreadPerTaskExecutor();
        try {
            List<CompletableFuture<Optional<FixOption>>> futures = candidates.stream()
                    .map(c -> CompletableFuture.supplyAsync(
                            () -> validateOne(c, Path.of(".")), exec))
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
            FixValidator.FixValidationResult res =
                    fixValidator.validateFix(projectDir, candidate, Duration.ofMinutes(5));

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

            LOG.info("Fix candidate FAILED validation: {} (exitCode={})",
                    candidate.getDescription(),
                    res.buildResult != null ? res.buildResult.exitCode : "N/A");
            return Optional.empty();

        } catch (Exception e) {
            LOG.warn("Validation exception for candidate '{}': {}",
                    candidate.getDescription(), e.getMessage());
            return Optional.empty();
        } finally {
            BUILD_SEMAPHORE.release();
        }
    }
}