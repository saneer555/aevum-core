package com.aevum.core.pipeline;

import com.aevum.core.domain.model.*;
import com.aevum.core.domain.enums.VerificationStatus;
import com.aevum.core.engine.*;
import com.aevum.core.util.Threading;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.util.*;
import java.util.concurrent.*;

/**
 * 6-Stage Verification Pipeline.
 * Orchestrates sequential + parallel execution of verification stages.
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

    public VerificationPipeline(NormalizeStage normalizeStage,
                                EffectiveVersionStage effectiveVersionStage,
                                ClasspathPresenceStage classpathPresenceStage,
                                RuntimeReachabilityStage runtimeReachabilityStage,
                                ExploitabilityStage exploitabilityStage,
                                ConfidenceScorerStage confidenceScorerStage,
                                BomResolver bomResolver,
                                FixEngine fixEngine) {
        this.normalizeStage = normalizeStage;
        this.effectiveVersionStage = effectiveVersionStage;
        this.classpathPresenceStage = classpathPresenceStage;
        this.runtimeReachabilityStage = runtimeReachabilityStage;
        this.exploitabilityStage = exploitabilityStage;
        this.confidenceScorerStage = confidenceScorerStage;
        this.bomResolver = bomResolver;
        this.fixEngine = fixEngine;
    }

    /**
     * Execute the full 6-stage pipeline for a single signal.
     */
    public VerificationResult verify(VulnerabilitySignal signal, StageContext context) {
        LOG.info("Starting verification pipeline for: {}", signal.getCveId());
        long startTime = System.currentTimeMillis();
        List<String> stageLogs = new ArrayList<>();
        List<Stage.StageResult> stageResults = new ArrayList<>();

        try {
            // Stage 1: Normalize (always sequential)
            Stage.StageResult s1 = normalizeStage.execute(signal, context);
            stageResults.add(s1);
            stageLogs.add("[S1] " + s1.reasoning());
            context.put("stageResult_" + normalizeStage.getName(), s1);
            if (!s1.passed()) {
                return buildResult(signal, context, stageResults, stageLogs, startTime);
            }

            // Stage 2: Effective Version (sequential - must complete before stages 3-5)
            Stage.StageResult s2 = effectiveVersionStage.execute(signal, context);
            stageResults.add(s2);
            stageLogs.add("[S2] " + s2.reasoning());
            context.put("stageResult_" + effectiveVersionStage.getName(), s2);
            if (!s2.passed()) {
                return buildResult(signal, context, stageResults, stageLogs, startTime);
            }

            // Stages 3-5 can run in parallel (independent checks)
            ExecutorService executor = Threading.newVirtualThreadPerTaskExecutor();
            try {
                Future<Stage.StageResult> f3 = executor.submit(() -> classpathPresenceStage.execute(signal, context));
                Future<Stage.StageResult> f4 = executor.submit(() -> runtimeReachabilityStage.execute(signal, context));
                Future<Stage.StageResult> f5 = executor.submit(() -> exploitabilityStage.execute(signal, context));

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

            // Stage 6: Confidence Scorer (sequential - aggregates all previous)
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
                                           List<Stage.StageResult> stageResults, List<String> stageLogs,
                                           long startTime) {
        ConfidenceScore confidence = context.<ConfidenceScore>get("confidenceScore")
            .orElse(null);
        VerificationStatus status = context.<VerificationStatus>get("verificationStatus")
            .orElse(null);

        // If confidence/status not set (early exit), derive from available stageResults
        if (confidence == null) {
            Map<String, Integer> stageScores = new LinkedHashMap<>();
            List<String> reasoningList = new ArrayList<>();
            int total = 0;
            for (Stage.StageResult r : stageResults) {
                String name = r.getClass().getSimpleName();
                stageScores.put(name, r.score());
                reasoningList.add(r.reasoning());
                total += r.score();
            }
            int derivedScore = stageResults.isEmpty() ? 0 : Math.min(100, total / Math.max(1, stageResults.size()));
            confidence = new ConfidenceScore(derivedScore, stageScores, reasoningList);
        }

        if (status == null) {
            // If any stage explicitly declared a FALSE_POSITIVE reason -> mark false positive
            boolean hasFalsePositiveReason = stageResults.stream()
                .anyMatch(r -> r.reasoning() != null && r.reasoning().toUpperCase().contains("FALSE_POSITIVE"));
            if (hasFalsePositiveReason) {
                status = VerificationStatus.FALSE_POSITIVE;
            } else {
                status = VerificationStatus.INCONCLUSIVE;
            }
        }

        Artifact effectiveArtifact = context.<Artifact>get("effectiveArtifact").orElse(null);
        BomResolver.ResolutionResult resolution = context.<BomResolver.ResolutionResult>get("resolutionResult").orElse(null);

        RootCausePath rootCause = null;
        if (resolution != null && effectiveArtifact != null) {
            List<Artifact> path = resolution.isFound()
                ? List.of(new Artifact(signal.getGroupId(), signal.getArtifactId(), signal.getReportedVersion(),
                                       effectiveArtifact.getScope()))
                : List.of();
            rootCause = new RootCausePath(path, effectiveArtifact, resolution.mediationRule(), resolution.depth());
        }

        // Generate fixes ONLY for confirmed vulnerabilities
        List<FixOption> fixes = status == VerificationStatus.CONFIRMED
            ? fixEngine.generateFixes(
                VerificationResult.builder()
                    .resultId(UUID.randomUUID().toString())
                    .signalId(signal.getSignalId())
                    .status(status)
                    .confidenceScore(confidence)
                    .rootCausePath(rootCause)
                    .effectiveArtifact(effectiveArtifact)
                    .build(),
                context.getEffectivePom())
            : List.of();

        long durationMs = System.currentTimeMillis() - startTime;
        LOG.info("Pipeline completed in {}ms for {} with status {}", durationMs, signal.getCveId(), status);

        boolean inClasspath = context.<Stage.StageResult>get("stageResult_" + classpathPresenceStage.getName()).map(Stage.StageResult::passed).orElse(false);
        boolean isReachable = context.<Stage.StageResult>get("stageResult_" + runtimeReachabilityStage.getName()).map(Stage.StageResult::passed).orElse(false);

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
            .metadata(Map.of("durationMs", durationMs, "stagesCompleted", stageResults.size()))
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
            .confidenceScore(new ConfidenceScore(0, Map.of(), List.of("Pipeline error: " + e.getMessage())))
            .stageLogs(stageLogs)
            .metadata(Map.of("durationMs", durationMs, "error", e.getMessage()))
            .build();
    }
}
