package com.aevum.core.domain.model;

import java.util.*;

/**
 * Confidence score with stage breakdown.
 */
public final class ConfidenceScore {
    private final int totalScore;
    private final Map<String, Integer> stageScores;
    private final List<String> reasoning;

    public ConfidenceScore(int totalScore, Map<String, Integer> stageScores, List<String> reasoning) {
        // Use Java 17-compatible clamp
        this.totalScore = Math.max(0, Math.min(totalScore, 100));
        this.stageScores = Map.copyOf(stageScores);
        this.reasoning = List.copyOf(reasoning);
    }

    public int getTotalScore() { return totalScore; }
    public Map<String, Integer> getStageScores() { return stageScores; }
    public List<String> getReasoning() { return reasoning; }

    public boolean isConfirmed() { return totalScore >= 90; }
    public boolean isFalsePositive() { return totalScore < 70; }
    public boolean isInconclusive() { return totalScore >= 70 && totalScore < 90; }

    @Override
    public String toString() {
        return "Confidence[" + totalScore + "/100]";
    }
}
