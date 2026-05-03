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

    public VerificationResult verify(VulnerabilitySignal signal, StageContext context) {
        long startTime = System.currentTimeMillis();
        List<String> stageLogs = new ArrayList<>();
        List<Stage.StageResult> stageResults = new ArrayList<>();

        try {
            Stage.StageResult s1 = normalizeStage.execute(signal, context);
            stageResults.add(s1);
            stageLogs.add("[S1] " + s1.reasoning());
            if (!s1.passed()) {
                return buildResult(signal, context, stageResults, stageLogs, startTime);
            }

            Stage.StageResult s2 = effectiveVersionStage.execute(signal, context);
            stageResults.add(s2);
            stageLogs.add("[S2] " + s2.reasoning());
            if (!s2.passed()) {
                return buildResult(signal, context, stageResults, stageLogs, startTime);
            }

            ExecutorService executor = Threading.newVirtualThreadPerTaskExecutor();
            Stage.StageResult s3, s4, s5;
            try {
                Future<Stage.StageResult> f3 = executor.submit(() -> classpathPresenceStage.execute(signal, context));
                Future<Stage.StageResult> f4 = executor.submit(() -> runtimeReachabilityStage.execute(signal, context));
                Future<Stage.StageResult> f5 = executor.submit(() -> exploitabilityStage.execute(signal, context));

                s3 = f3.get();
                s4 = f4.get();
                s5 = f5.get();

                stageResults.add(s3);
                stageResults.add(s4);
                stageResults.add(s5);

                stageLogs.add("[S3] " + s3.reasoning());
                stageLogs.add("[S4] " + s4.reasoning());
                stageLogs.add("[S5] " + s5.reasoning());

            } finally {
                executor.shutdown();
            }

            context.put("stageResults", stageResults);
            Stage.StageResult s6 = confidenceScorerStage.execute(signal, context);
            stageResults.add(s6);
            stageLogs.add("[S6] " + s6.reasoning());

            return buildResult(signal, context, stageResults, stageLogs, startTime);

        } catch (Exception e) {
            LOG.error("Pipeline exception for signal {}: {}", signal.getSignalId(), e.getMessage(), e);
            stageLogs.add("[ERROR] " + e.getMessage());
            return buildErrorResult(signal, stageLogs, startTime, e);
        }
    }

    private VerificationResult buildResult(VulnerabilitySignal signal,
                                           StageContext context,
                                           List<Stage.StageResult> stageResults,
                                           List<String> stageLogs,
                                           long startTime) {

        ConfidenceScore confidence = context.<ConfidenceScore>get("confidenceScore").orElse(null);
        VerificationStatus status = context.<VerificationStatus>get("verificationStatus").orElse(null);

        if (status == null) {
            boolean hasFalsePositive = stageResults.stream()
                    .anyMatch(r -> r.reasoning() != null &&
                            r.reasoning().toLowerCase().contains("false positive"));
            status = hasFalsePositive ? VerificationStatus.FALSE_POSITIVE : VerificationStatus.INCONCLUSIVE;
        }

        Artifact effectiveArtifact = context.<Artifact>get("effectiveArtifact").orElse(null);

        boolean isInClasspath = stageResults.stream()
                .filter(r -> r.reasoning() != null)
                .anyMatch(r -> r.reasoning().contains("runtime classpath") && r.passed());

        boolean isReachable = stageResults.stream()
                .filter(r -> r.reasoning() != null)
                .anyMatch(r -> r.reasoning().contains("reachable from application entry points") && r.passed());

        RootCausePath rootCausePath = buildRootCausePath(context, effectiveArtifact);

        // ── Detect version conflicts ──
        Map<String, Object> metadata = new HashMap<>();
        if (effectiveArtifact != null) {
            List<VersionConflictDetector.VersionConflict> conflicts =
                    conflictDetector.detectConflicts(context.getEffectivePom());
            Optional<VersionConflictDetector.VersionConflict> myConflict = conflicts.stream()
                    .filter(c -> c.coordinate.equals(effectiveArtifact.getShortCoordinate()))
                    .findFirst();

            if (myConflict.isPresent()) {
                metadata.put("versionConflict", Map.of(
                        "conflictDetected", true,
                        "conflictingPaths", myConflict.get().paths.stream()
                                .map(VersionConflictDetector.ConflictPath::getPathString)
                                .toList()
                ));
                LOG.info("Version conflict detected for {}: {}", effectiveArtifact.getShortCoordinate(),
                        myConflict.get().conflictingVersions);
            }
        }

        // ── Generate fixes ──
        List<FixOption> fixes = Collections.emptyList();
        if (status == VerificationStatus.CONFIRMED && effectiveArtifact != null) {
            VerificationResult interim = VerificationResult.builder()
                    .resultId(UUID.randomUUID().toString())
                    .signalId(signal.getSignalId())
                    .originalSignal(signal)
                    .status(status)
                    .confidenceScore(confidence)
                    .effectiveArtifact(effectiveArtifact)
                    .rootCausePath(rootCausePath)
                    .isInClasspath(isInClasspath)
                    .isReachable(isReachable)
                    .build();

            boolean validateFixes = context.<Boolean>get("validateFixes").orElse(false);
            LOG.info("Calling FixEngine for signal {} (cve={}, safeVersions={})",
                    signal.getSignalId(), signal.getCveId(), signal.getSafeVersions());
            fixes = fixEngine.generateFixes(interim, context.getEffectivePom(), validateFixes);
            LOG.info("FixEngine returned {} fix option(s) for {}", fixes.size(), signal.getSignalId());
        }

        return VerificationResult.builder()
                .resultId(UUID.randomUUID().toString())
                .signalId(signal.getSignalId())
                .originalSignal(signal)
                .status(status)
                .confidenceScore(confidence)
                .effectiveArtifact(effectiveArtifact)
                .rootCausePath(rootCausePath)
                .isInClasspath(isInClasspath)
                .isReachable(isReachable)
                .fixOptions(fixes)
                .stageLogs(stageLogs)
                .metadata(metadata)
                .build();
    }

    private RootCausePath buildRootCausePath(StageContext context, Artifact effectiveArtifact) {
        BomResolver.ResolutionResult resolution =
                context.<BomResolver.ResolutionResult>get("resolutionResult").orElse(null);

        if (resolution == null || effectiveArtifact == null) {
            return null;
        }

        List<Artifact> path = new ArrayList<>();
        if (resolution.isDirect() || resolution.depth() >= 0) {
            path.add(effectiveArtifact);
        }

        return new RootCausePath(
                path,
                effectiveArtifact,
                resolution.mediationRule(),
                resolution.depth()
        );
    }

    private VerificationResult buildErrorResult(VulnerabilitySignal signal,
                                                List<String> logs,
                                                long startTime,
                                                Exception e) {
        return VerificationResult.builder()
                .resultId(UUID.randomUUID().toString())
                .signalId(signal.getSignalId())
                .originalSignal(signal)
                .status(VerificationStatus.INCONCLUSIVE)
                .confidenceScore(new ConfidenceScore(0, Map.of(), logs))
                .isInClasspath(false)
                .isReachable(false)
                .stageLogs(logs)
                .metadata(Map.of())
                .build();
    }
}