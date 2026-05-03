package com.aevum.core.pipeline;

import com.aevum.core.domain.model.*;
import com.aevum.core.domain.enums.VerificationStatus;
import com.aevum.core.engine.ExploitabilityAssessor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.util.*;

@Component
public class ConfidenceScorerStage implements Stage {

    private static final Logger LOG = LoggerFactory.getLogger(ConfidenceScorerStage.class);

    @Override
    public String getName() {
        return "STAGE_06_CONFIDENCE_SCORER";
    }

    @Override
    @SuppressWarnings("unchecked")
    public StageResult execute(VulnerabilitySignal signal, StageContext context) {

        Object raw = context.<Object>get("stageResults").orElse(null);

        if (raw == null) {
            return StageResult.fail(
                    0,
                    "No previous stage results found in context",
                    Map.of("status", VerificationStatus.FALSE_POSITIVE)
            );
        }

        List<StageResult> previousResults = (List<StageResult>) raw;

        Map<String, Integer> stageScores = new LinkedHashMap<>();
        List<String> reasoning = new ArrayList<>();

        int totalScore = 0;
        boolean hasCriticalFailure = false;

        for (StageResult result : previousResults) {

            String key = "stage_" + stageScores.size();
            stageScores.put(key, result.score());

            if (result.reasoning() != null) {
                reasoning.add(result.reasoning());
            }

            totalScore += result.score();

            // ✅ CRITICAL FIX: Detect ANY explicit FALSE POSITIVE
            if (!result.passed() && result.reasoning() != null) {
                String reason = result.reasoning().toLowerCase();

                if (reason.contains("false positive")) {
                    hasCriticalFailure = true;
                }
            }
        }

        // ✅ HARD STOP: Any FALSE POSITIVE → score = 0
        if (hasCriticalFailure) {

            reasoning.add("CRITICAL FAILURE: Explicit FALSE POSITIVE detected");

            context.put("confidenceScore", new ConfidenceScore(0, stageScores, reasoning));
            context.put("verificationStatus", VerificationStatus.FALSE_POSITIVE);

            return StageResult.fail(
                    0,
                    "Final confidence: 0/100. Status: FALSE_POSITIVE",
                    Map.of(
                            "status", VerificationStatus.FALSE_POSITIVE,
                            "stageScores", stageScores
                    )
            );
        }

        // Normal scoring
        int normalizedScore = previousResults.isEmpty()
                ? 0
                : Math.min(100, totalScore / previousResults.size());

        // KEV boost
        Optional<ExploitabilityAssessor.ExploitabilityResult> exploitResult =
                context.get("exploitabilityResult");

        if (exploitResult.isPresent()
                && exploitResult.get().inKev()
                && normalizedScore < 90) {

            normalizedScore = Math.min(100, normalizedScore + 15);
            reasoning.add("BOOST: Known Exploited Vulnerability (KEV) detected");
        }

        // Final status
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

        return StageResult.pass(
                normalizedScore,
                "Final confidence: " + normalizedScore + "/100. Status: " + status,
                Map.of(
                        "status", status,
                        "stageScores", stageScores
                )
        );
    }
}