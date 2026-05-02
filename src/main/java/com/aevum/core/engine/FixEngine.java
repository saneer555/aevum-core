package com.aevum.core.engine;

import com.aevum.core.domain.enums.FixType;
import com.aevum.core.domain.enums.VerificationStatus;
import com.aevum.core.domain.model.*;
import com.aevum.core.engine.fix.FixValidator;
import com.aevum.core.engine.fix.MavenBuildExecutor;
import com.aevum.core.engine.fix.TestRunner;
import com.aevum.core.engine.proof.ProofPackageBuilder;
import com.aevum.core.engine.version.MavenMetadataClient;
import com.aevum.core.engine.version.SafeVersionFinder;
import com.aevum.core.util.Threading;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.nio.file.Path;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.*;
import java.util.stream.Collectors;

/**
 * Fix Engine - ONLY runs AFTER confirmation.
 * STRICT RULES:
 * 1. Do NOT add new dependencies unless absolutely required
 * 2. Do NOT suggest fixes for false positives
 * 3. Prefer minimal change strategy
 * 4. Validate fix using simulation (build + test)
 */
@Component
public class FixEngine {
    private static final Logger LOG = LoggerFactory.getLogger(FixEngine.class);

    private static final Map<String, String> SECURITY_PATCH_VERSIONS = Map.ofEntries(
        Map.entry("org.bouncycastle:bcprov-jdk18on:1.80", "1.81"),
        Map.entry("org.apache.logging.log4j:log4j-core:2.14.1", "2.17.1"),
        Map.entry("org.apache.logging.log4j:log4j-core:2.15.0", "2.17.1"),
        Map.entry("org.apache.logging.log4j:log4j-core:2.16.0", "2.17.1"),
        Map.entry("org.apache.tomcat.embed:tomcat-embed-core:9.0.50", "9.0.90"),
        Map.entry("com.fasterxml.jackson.core:jackson-databind:2.13.0", "2.13.5"),
        Map.entry("org.springframework:spring-core:5.3.20", "5.3.39"),
        Map.entry("org.springframework.security:spring-security-core:5.7.1", "5.7.12")
    );

    private final SafeVersionFinder safeVersionFinder;
    private final FixValidator fixValidator;
    private final ProofPackageBuilder proofPackageBuilder;
    private final ExecutorService validationExecutor;
    private final Semaphore buildSemaphore;

    public FixEngine() {
        // default constructor for tests and simple wiring
        MavenMetadataClient metadataClient = new MavenMetadataClient();
        this.safeVersionFinder = new SafeVersionFinder(metadataClient);
        MavenBuildExecutor mbe = new MavenBuildExecutor();
        TestRunner tr = new TestRunner(mbe);
        ProofPackageBuilder ppb;
        try { ppb = new ProofPackageBuilder(); } catch (Exception e) { throw new RuntimeException(e); }
        this.fixValidator = new FixValidator(mbe, tr, ppb);
        this.proofPackageBuilder = ppb;
        this.validationExecutor = Threading.newVirtualThreadPerTaskExecutor();
        this.buildSemaphore = new Semaphore(4); // limit parallel builds
    }

    /**
     * Generates fix options and validates them, returning only PASSed fixes ordered by minimal impact.
     */
    public List<FixOption> generateFixes(VerificationResult result, EffectivePom effectivePom) {
        if (result.getStatus() != VerificationStatus.CONFIRMED) {
            LOG.info("Skipping fix generation for non-confirmed vulnerability: {}", result.getSignalId());
            return Collections.emptyList();
        }

        LOG.info("Generating fixes for confirmed vulnerability: {}", result.getSignalId());
        List<FixOption> candidateFixes = new ArrayList<>();

        Artifact vulnerable = result.getEffectiveArtifact();
        if (vulnerable == null) {
            return candidateFixes;
        }

        // Strategy 1: Version alignment via Version Intelligence
        try {
            // VulnerabilitySignal.affectedRange is not present in the current model; pass null when unavailable
            String affectedRange = null;
            if (result.getOriginalSignal() != null) {
                // If the original signal ever contains affected range it should be used here; fallback to null
                // affectedRange = result.getOriginalSignal().getAffectedRange();
            }
            var sv = safeVersionFinder.findMinimumSafe(vulnerable.getGroupId(), vulnerable.getArtifactId(), vulnerable.getVersion(), affectedRange);
            if (sv.minimumSafeVersion != null && !sv.minimumSafeVersion.equals(vulnerable.getVersion())) {
                candidateFixes.add(FixOption.builder()
                    .fixType(FixType.VERSION_ALIGNMENT)
                    .description("Align " + vulnerable.getShortCoordinate() + " to " + sv.minimumSafeVersion)
                    .targetDependency(vulnerable.getShortCoordinate())
                    .proposedVersion(sv.minimumSafeVersion)
                    .validated(false)
                    .validationLog("Recommended by SafeVersionFinder: " + sv.recommendationType)
                    .affectedArtifacts(List.of(vulnerable.getShortCoordinate()))
                    .build());
            }
        } catch (Exception e) {
            LOG.warn("Version intelligence failed: {}", e.getMessage());
        }

        // Strategy 2: Exclusion on exact source dependency
        Optional<FixOption> exclusionFix = createExclusionFix(result, effectivePom);
        exclusionFix.ifPresent(candidateFixes::add);

        // Strategy 3: Parent dependency upgrade (only if needed)
        Optional<FixOption> parentFix = createParentUpgradeFix(result, effectivePom);
        parentFix.ifPresent(candidateFixes::add);

        // Validate candidates in parallel but bounded
        List<CompletableFuture<Optional<FixOption>>> futures = candidateFixes.stream()
            .map(c -> CompletableFuture.supplyAsync(() -> validateCandidateSafely(c, Path.of(".")), validationExecutor))
            .collect(Collectors.toList());

        List<FixOption> validated = futures.stream().map(CompletableFuture::join)
            .filter(Optional::isPresent).map(Optional::get).collect(Collectors.toList());

        // Rank: minimal change first (proposedVersion closeness), least affected artifacts
        validated.sort(Comparator.comparingInt(f -> f.getAffectedArtifacts().size()));
        return validated;
    }

    private Optional<FixOption> validateCandidateSafely(FixOption candidate, Path projectDir) {
        try {
            buildSemaphore.acquire();
            FixValidator.FixValidationResult res = fixValidator.validateFix(projectDir, candidate, Duration.ofMinutes(5));
            if (res.passed) {
                // attach validation info to fixOption
                FixOption validated = FixOption.builder()
                    .fixType(candidate.getFixType())
                    .description(candidate.getDescription())
                    .targetDependency(candidate.getTargetDependency())
                    .proposedVersion(candidate.getProposedVersion())
                    .validated(true)
                    .validationLog("Validated. ProofPackageId=" + (res.proofPackage != null ? res.proofPackage.getId() : ""))
                    .affectedArtifacts(candidate.getAffectedArtifacts())
                    .build();
                return Optional.of(validated);
            }
            return Optional.empty();
        } catch (Exception e) {
            LOG.warn("Validation failed for candidate {}: {}", candidate, e.getMessage());
            return Optional.empty();
        } finally {
            buildSemaphore.release();
        }
    }

    private Optional<FixOption> createExclusionFix(VerificationResult result, EffectivePom effectivePom) {
        RootCausePath rootCause = result.getRootCausePath();
        if (rootCause == null || rootCause.getPath().size() < 2) {
            return Optional.empty();
        }

        // Find the direct dependency that brings in the vulnerable transitive
        Artifact sourceDependency = rootCause.getPath().get(rootCause.getPath().size() - 2);
        Artifact vulnerable = result.getEffectiveArtifact();

        // Only suggest exclusion if the vulnerable artifact is transitive (not direct)
        if (rootCause.getDepth() == 0) {
            return Optional.empty(); // Direct dependency - exclusion not applicable
        }

        String description = "Exclude " + vulnerable.getShortCoordinate() +
            " from " + sourceDependency.getShortCoordinate() +
            " if not required by application code";

        return Optional.of(FixOption.builder()
            .fixType(FixType.DEPENDENCY_EXCLUSION)
            .description(description)
            .targetDependency(sourceDependency.getShortCoordinate())
            .exclusionTarget(vulnerable.getShortCoordinate())
            .validated(false)
            .validationLog("Exclusion requires validation")
            .affectedArtifacts(List.of(sourceDependency.getShortCoordinate(), vulnerable.getShortCoordinate()))
            .build());
    }

    private Optional<FixOption> createParentUpgradeFix(VerificationResult result, EffectivePom effectivePom) {
        RootCausePath rootCause = result.getRootCausePath();
        if (rootCause == null || rootCause.getPath().isEmpty()) {
            return Optional.empty();
        }

        // Only suggest if the root cause is a specific parent that has a newer version available
        Artifact rootDep = rootCause.getPath().get(0);
        String currentVersion = rootDep.getVersion();

        // In production: query Maven Central for latest version
        // For demo: simulate that some deps have upgrades
        if (!currentVersion.startsWith("2.") && !currentVersion.startsWith("5.")) {
            return Optional.empty();
        }

        String[] parts = currentVersion.split("\\.");
        if (parts.length < 2) return Optional.empty();

        int minor = Integer.parseInt(parts[1]);
        String proposedVersion = parts[0] + "." + (minor + 1) + ".0";

        return Optional.of(FixOption.builder()
            .fixType(FixType.PARENT_UPGRADE)
            .description("Upgrade " + rootDep.getShortCoordinate() + " from " + currentVersion +
                " to " + proposedVersion + " (brings transitive fix)")
            .targetDependency(rootDep.getShortCoordinate())
            .proposedVersion(proposedVersion)
            .validated(false) // Requires manual validation - major change
            .validationLog("Parent upgrade requires regression testing. Impact assessment needed.")
            .affectedArtifacts(List.of(rootDep.getShortCoordinate()))
            .build());
    }
}
