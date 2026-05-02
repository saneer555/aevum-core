package com.aevum.core.pipeline;

import com.aevum.core.domain.model.*;
import com.aevum.core.domain.enums.VerificationStatus;
import com.aevum.core.engine.*;
import com.aevum.core.engine.fix.VersionConflictDetector;
import com.aevum.core.util.Threading;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.*;
import java.util.concurrent.*;

/**
 * 6-Stage Verification Pipeline.
 *
 * FIX: The VerificationResult passed to fixEngine.generateFixes() was built without
 * .originalSignal(signal) — meaning result.getOriginalSignal() returned null inside FixEngine.
 * The affectedRange metadata lookup in FixEngine would NPE or silently skip.
 * Now the full signal is always attached to the result before fix generation.
 *
 * FIX 2: Stages 3-5 run in parallel sharing a mutable StageContext. This was safe because
 * StageContext now uses ConcurrentHashMap. Documented here explicitly.
 *
 * FIX 3: The inner VerificationResult built for the fix engine call now includes
 * .originalSignal(signal) so FixEngine can read signal metadata.
 */
@Component
public class VerificationPipeline {
    private static final Logger LOG = LoggerFactory.getLogger(VerificationPipeline.class);

    private final NormalizeStage normalizeStage;
    private final EffectiveVersionStage effectiveVersionStage;
    private final ClasspathPresenceStage classpathPresenceStage;
    private final RuntimeReachabilityStage runtimeReachabilityStage;
    private final ExploitabilityStage exploitabilityStage;
    private final ConfidenceScorerStage confidenceScorerStage;
    private final BomResolver bomResolver;
    private final FixEngine fixEngine;
    private final VersionConflictDetector conflictDetector;

    @Autowired
    public VerificationPipeline(NormalizeStage normalizeStage,
                                EffectiveVersionStage effectiveVersionStage,
                                ClasspathPresenceStage classpathPresenceStage,
                                RuntimeReachabilityStage runtimeReachabilityStage,
                                ExploitabilityStage exploitabilityStage,
                                ConfidenceScorerStage confidenceScorerStage,
                                BomResolver bomResolver,
                                FixEngine fixEngine,
                                VersionConflictDetector conflictDetector) {
        this.normalizeStage = normalizeStage;
        this.effectiveVersionStage = effectiveVersionStage;
        this.classpathPresenceStage = classpathPresenceStage;
        this.runtimeReachabilityStage = runtimeReachabilityStage;
        this.exploitabilityStage = exploitabilityStage;
        this.confidenceScorerStage = confidenceScorerStage;
        this.bomResolver = bomResolver;
        this.fixEngine = fixEngine;
        this.conflictDetector = conflictDetector;
    }

    /**
     * Backwards-compatible constructor for tests and legacy callers that don't
     * provide a VersionConflictDetector. Creates a default detector.
     */
    public VerificationPipeline(NormalizeStage normalizeStage,
                                EffectiveVersionStage effectiveVersionStage,
                                ClasspathPresenceStage classpathPresenceStage,
                                RuntimeReachabilityStage runtimeReachabilityStage,
                                ExploitabilityStage exploitabilityStage,
                                ConfidenceScorerStage confidenceScorerStage,
                                BomResolver bomResolver,
                                FixEngine fixEngine) {
        this(normalizeStage, effectiveVersionStage, classpathPresenceStage,
                runtimeReachabilityStage, exploitabilityStage, confidenceScorerStage,
                bomResolver, fixEngine, new VersionConflictDetector());
    }

    public VerificationResult verify(VulnerabilitySignal signal, StageContext context) {
        LOG.info("Starting verification pipeline for: {}", signal.getCveId());
        long startTime = System.currentTimeMillis();
        List<String> stageLogs = new ArrayList<>();
        List<Stage.StageResult> stageResults = new ArrayList<>();

        try {
            // Stage 1: Normalize — always sequential first
            Stage.StageResult s1 = normalizeStage.execute(signal, context);
            stageResults.add(s1);
            stageLogs.add("[S1] " + s1.reasoning());
            if (!s1.passed()) {
                return buildResult(signal, context, stageResults, stageLogs, startTime);
            }

            // Stage 2: Effective Version — must complete before S3-S5 (they need effectiveArtifact)
            Stage.StageResult s2 = effectiveVersionStage.execute(signal, context);
            stageResults.add(s2);
            stageLogs.add("[S2] " + s2.reasoning());
            if (!s2.passed()) {
                return buildResult(signal, context, stageResults, stageLogs, startTime);
            }

            // Stages 3-5 run in parallel — safe because StageContext uses ConcurrentHashMap
            // Stage 3 writes: (nothing new)
            // Stage 4 writes: (nothing new)
            // Stage 5 writes: "exploitabilityResult"
            // No concurrent writes to same key — safe
            ExecutorService executor = Threading.newVirtualThreadPerTaskExecutor();
            try {
                Future<Stage.StageResult> f3 = executor.submit(
                        () -> classpathPresenceStage.execute(signal, context));
                Future<Stage.StageResult> f4 = executor.submit(
                        () -> runtimeReachabilityStage.execute(signal, context));
                Future<Stage.StageResult> f5 = executor.submit(
                        () -> exploitabilityStage.execute(signal, context));

                Stage.StageResult s3 = f3.get();
                Stage.StageResult s4 = f4.get();
                Stage.StageResult s5 = f5.get();

                stageResults.add(s3);
                stageResults.add(s4);
                stageResults.add(s5);
                stageLogs.add("[S3] " + s3.reasoning());
                stageLogs.add("[S4] " + s4.reasoning());
                stageLogs.add("[S5] " + s5.reasoning());

                context.put("stageResult_" + classpathPresenceStage.getName(), s3);
                context.put("stageResult_" + runtimeReachabilityStage.getName(), s4);
                context.put("stageResult_" + exploitabilityStage.getName(), s5);
            } finally {
                executor.shutdown();
            }

            // Stage 6: Confidence Scorer — aggregates all previous results
            context.put("stageResults", stageResults);
            Stage.StageResult s6 = confidenceScorerStage.execute(signal, context);
            stageResults.add(s6);
            stageLogs.add("[S6] " + s6.reasoning());

            return buildResult(signal, context, stageResults, stageLogs, startTime);

        } catch (Exception e) {
            LOG.error("Pipeline failed for signal: {}", signal.getSignalId(), e);
            stageLogs.add("[ERROR] Pipeline exception: " + e.getMessage());
            return buildErrorResult(signal, stageLogs, startTime, e);
        }
    }

    private VerificationResult buildResult(VulnerabilitySignal signal, StageContext context,
                                           List<Stage.StageResult> stageResults,
                                           List<String> stageLogs, long startTime) {
        ConfidenceScore confidence = context.<ConfidenceScore>get("confidenceScore").orElse(null);
        VerificationStatus status = context.<VerificationStatus>get("verificationStatus").orElse(null);

        // Derive confidence/status if pipeline exited early (stage 1 or 2 failed)
        if (confidence == null) {
            Map<String, Integer> scores = new LinkedHashMap<>();
            List<String> reasoning = new ArrayList<>();
            int total = 0;
            for (int i = 0; i < stageResults.size(); i++) {
                Stage.StageResult r = stageResults.get(i);
                scores.put("stage_" + (i + 1), r.score());
                reasoning.add(r.reasoning());
                total += r.score();
            }
            int derived = stageResults.isEmpty() ? 0 : Math.min(100, total / stageResults.size());
            confidence = new ConfidenceScore(derived, scores, reasoning);
        }

        if (status == null) {
            boolean hasFalsePositive = stageResults.stream()
                    .anyMatch(r -> !r.passed() && r.reasoning() != null &&
                            (r.reasoning().contains("FALSE POSITIVE") || r.reasoning().contains("FALSE_POSITIVE")));
            status = hasFalsePositive ? VerificationStatus.FALSE_POSITIVE : VerificationStatus.INCONCLUSIVE;
        }

        Artifact effectiveArtifact = context.<Artifact>get("effectiveArtifact").orElse(null);
        BomResolver.ResolutionResult resolution =
            context.<BomResolver.ResolutionResult>get("resolutionResult").orElse(null);

        RootCausePath rootCause = null;
        if (resolution != null && effectiveArtifact != null) {
            List<Artifact> path = resolution.isFound()
                ? List.of(new Artifact(signal.getGroupId(), signal.getArtifactId(),
                signal.getReportedVersion(), effectiveArtifact.getScope()))
                : List.of();
            rootCause = new RootCausePath(path, effectiveArtifact,
                resolution.mediationRule(), resolution.depth());
        }

        // Detect version conflicts for the effective artifact (if present)
        Map<String, Object> versionConflictMap = Map.of();
        if (effectiveArtifact != null) {
            try {
                List<VersionConflictDetector.VersionConflict> conflicts = conflictDetector.detectConflicts(context.getEffectivePom());
                String coord = effectiveArtifact.getShortCoordinate();
                Optional<VersionConflictDetector.VersionConflict> match = conflicts.stream()
                        .filter(c -> c.coordinate.equals(coord))
                        .findFirst();
                if (match.isPresent()) {
                    List<String> paths = match.get().paths.stream().map(p -> p.getPathString()).toList();
                    versionConflictMap = Map.of("conflictDetected", true, "conflictingPaths", paths);
                } else {
                    versionConflictMap = Map.of("conflictDetected", false, "conflictingPaths", List.of());
                }
            } catch (Exception e) {
                versionConflictMap = Map.of("conflictDetected", false, "conflictingPaths", List.of());
            }
        }

        // Generate fixes ONLY for CONFIRMED vulnerabilities
        // FIX: Pass the full signal via originalSignal so FixEngine can read signal metadata
        List<FixOption> fixes = Collections.emptyList();
        if (status == VerificationStatus.CONFIRMED) {
            VerificationResult interim = VerificationResult.builder()
                    .resultId(UUID.randomUUID().toString())
                    .signalId(signal.getSignalId())
                    .originalSignal(signal)                     // FIX: was missing!
                    .status(status)
                    .confidenceScore(confidence)
                    .rootCausePath(rootCause)
                    .effectiveArtifact(effectiveArtifact)
                    .build();
            // By default don't run expensive build+test validation in unit tests/environment
            boolean validate = context.<Boolean>get("validateFixes").orElse(Boolean.FALSE);
            fixes = fixEngine.generateFixes(interim, context.getEffectivePom(), validate);
        }

        long durationMs = System.currentTimeMillis() - startTime;
        LOG.info("Pipeline completed in {}ms for {} — status: {}", durationMs, signal.getCveId(), status);

        boolean inClasspath = context.<Stage.StageResult>get(
                        "stageResult_" + classpathPresenceStage.getName())
                .map(Stage.StageResult::passed).orElse(false);
        boolean isReachable = context.<Stage.StageResult>get(
                        "stageResult_" + runtimeReachabilityStage.getName())
                .map(Stage.StageResult::passed).orElse(false);

        Map<String, Object> meta = new HashMap<>();
        meta.put("durationMs", durationMs);
        meta.put("stagesCompleted", stageResults.size());
        meta.put("versionConflict", versionConflictMap);

        return VerificationResult.builder()
            .resultId(UUID.randomUUID().toString())
            .signalId(signal.getSignalId())
            .originalSignal(signal)
            .status(status)
            .confidenceScore(confidence)
            .rootCausePath(rootCause)
            .effectiveArtifact(effectiveArtifact)
            .isInClasspath(inClasspath)
            .isReachable(isReachable)
            .fixOptions(fixes)
            .stageLogs(stageLogs)
            .metadata(meta)
            .build();
    }

    private VerificationResult buildErrorResult(VulnerabilitySignal signal, List<String> stageLogs,
                                                long startTime, Exception e) {
        long durationMs = System.currentTimeMillis() - startTime;
        return VerificationResult.builder()
                .resultId(UUID.randomUUID().toString())
                .signalId(signal.getSignalId())
                .originalSignal(signal)
                .status(VerificationStatus.INCONCLUSIVE)
                .confidenceScore(new ConfidenceScore(0, Map.of(),
                        List.of("Pipeline exception: " + e.getMessage())))
                .stageLogs(stageLogs)
                .metadata(Map.of("durationMs", durationMs, "error", e.getMessage()))
                .build();
    }
}