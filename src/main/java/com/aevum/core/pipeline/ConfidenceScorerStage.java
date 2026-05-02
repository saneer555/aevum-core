package com.aevum.core.pipeline;

import com.aevum.core.domain.model.*;
import com.aevum.core.domain.enums.VerificationStatus;
import com.aevum.core.engine.ExploitabilityAssessor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.util.*;

/**
 * Stage 6: Confidence Scorer.
 * Final 0-100 score. <70 = false positive. >=90 = act immediately.
 *
 * FIX: The stageResults retrieval from context was an unsafe raw cast:
 *   (List<StageResult>) context.get("stageResults").orElseThrow(...)
 * StageContext.get() returns Optional<T> — the cast needs to be done properly.
 * Now uses the typed get() with explicit List<Stage.StageResult> and handles
 * the empty case gracefully rather than throwing.
 *
 * FIX 2: failedStageNames was comparing against class simple names ("EffectiveVersionStage",
 * "ClasspathPresenceStage") but StageResult doesn't carry the stage class name — it carries
 * the reasoning string. Changed critical failure detection to check stage result reasoning
 * content (which contains "FALSE POSITIVE") instead of class name matching.
 */
@Component
public class ConfidenceScorerStage implements Stage {
    private static final Logger LOG = LoggerFactory.getLogger(ConfidenceScorerStage.class);

    @Override
    public String getName() { return "STAGE_06_CONFIDENCE_SCORER"; }

    @Override
    @SuppressWarnings("unchecked")
    public StageResult execute(VulnerabilitySignal signal, StageContext context) {
        // FIX: Safe typed retrieval — StageContext stores Object, need explicit cast with guard
        Object raw = context.<Object>get("stageResults").orElse(null);
        if (raw == null) {
            return StageResult.fail(0, "No previous stage results found in context",
                    Map.of("status", VerificationStatus.FALSE_POSITIVE));
        }
        List<StageResult> previousResults = (List<StageResult>) raw;

        Map<String, Integer> stageScores = new LinkedHashMap<>();
        List<String> reasoning = new ArrayList<>();
        int totalScore = 0;
        boolean hasCriticalFailure = false;

        for (StageResult result : previousResults) {
            String stageName = result.reasoning() != null ? result.reasoning() : "unknown";
            // Use index-based key to preserve order
            String key = "stage_" + stageScores.size();
            stageScores.put(key, result.score());
            reasoning.add(result.reasoning());
            totalScore += result.score();

            // FIX: Critical failure is detected by reasoning content (FALSE_POSITIVE in early stages)
            // rather than class name (which was never stored in StageResult)
            if (!result.passed() && result.reasoning() != null &&
                    (result.reasoning().contains("FALSE POSITIVE") ||
                            result.reasoning().contains("FALSE_POSITIVE") ||
                            result.reasoning().contains("not found in resolved dependency tree") ||
                            result.reasoning().contains("NOT present in runtime classpath"))) {
                hasCriticalFailure = true;
            }
        }

        // Normalize to 0-100
        int normalizedScore = previousResults.isEmpty()
                ? 0
                : Math.min(100, totalScore / previousResults.size());

        // Apply heavy penalty if critical stages (S2 effective version or S3 classpath) explicitly failed
        if (hasCriticalFailure && normalizedScore >= 70) {
            normalizedScore = Math.max(0, normalizedScore - 30);
            reasoning.add("PENALTY: Critical stage failure (version mismatch or not in classpath) detected");
        }

        // Boost for KEV — Known Exploited Vulnerabilities deserve immediate action
        Optional<ExploitabilityAssessor.ExploitabilityResult> exploitResult =
                context.get("exploitabilityResult");
        if (exploitResult.isPresent() && exploitResult.get().inKev() && normalizedScore < 90) {
            normalizedScore = Math.min(100, normalizedScore + 15);
            reasoning.add("BOOST: Known Exploited Vulnerability (KEV) detected — confidence elevated");
        }

        LOG.info("Final confidence score for {}: {}/100", signal.getCveId(), normalizedScore);

        VerificationStatus status;
        if (normalizedScore >= 90) {
            status = VerificationStatus.CONFIRMED;
        } else if (normalizedScore < 70) {
            status = VerificationStatus.FALSE_POSITIVE;
        } else {
            status = VerificationStatus.INCONCLUSIVE;
        }

        context.put("confidenceScore", new ConfidenceScore(normalizedScore, stageScores, reasoning));
        context.put("verificationStatus", status);

        return StageResult.pass(normalizedScore,
                "Final confidence: " + normalizedScore + "/100. Status: " + status,
                Map.of("status", status, "stageScores", stageScores));
    }
}