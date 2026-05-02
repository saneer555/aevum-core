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
 */
@Component
public class ConfidenceScorerStage implements Stage {
    private static final Logger LOG = LoggerFactory.getLogger(ConfidenceScorerStage.class);

    @Override
    public String getName() { return "STAGE_06_CONFIDENCE_SCORER"; }

    @Override
    public StageResult execute(VulnerabilitySignal signal, StageContext context) {
        List<StageResult> previousResults = (List<StageResult>) context.get("stageResults")
            .orElseThrow(() -> new IllegalStateException("Previous stage results not found"));

        Map<String, Integer> stageScores = new LinkedHashMap<>();
        List<String> reasoning = new ArrayList<>();
        int totalScore = 0;
        boolean anyFailed = false;
        Set<String> failedStageNames = new HashSet<>();

        for (StageResult result : previousResults) {
            stageScores.put(result.getClass().getSimpleName(), result.score());
            totalScore += result.score();
            reasoning.add(result.reasoning());
            if (!result.passed()) {
                anyFailed = true;
                failedStageNames.add(result.getClass().getSimpleName());
            }
        }

        // Normalize to 0-100
        int normalizedScore = Math.min(100, totalScore / Math.max(1, previousResults.size()));

        // Targeted penalty: only apply heavy penalty if critical stages failed (effective version or classpath)
        boolean criticalFailure = failedStageNames.contains("EffectiveVersionStage") || failedStageNames.contains("ClasspathPresenceStage");
        if (criticalFailure && normalizedScore >= 70) {
            normalizedScore = Math.max(0, normalizedScore - 30);
        }

        // Boost for KEV
        Optional<ExploitabilityAssessor.ExploitabilityResult> exploitResult =
            context.get("exploitabilityResult");
        if (exploitResult.isPresent() && exploitResult.get().inKev() && normalizedScore < 90) {
            normalizedScore = Math.min(100, normalizedScore + 15);
            reasoning.add("BOOST: Known Exploited Vulnerability (KEV) detected");
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
