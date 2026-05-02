package com.aevum.core.pipeline;

import com.aevum.core.domain.model.*;
import java.util.*;

/**
 * Single stage in the 6-stage verification pipeline.
 */
public interface Stage {
    String getName();
    StageResult execute(VulnerabilitySignal signal, StageContext context);

    record StageResult(
        boolean passed,
        int score,
        String reasoning,
        Map<String, Object> metadata
    ) {
        public static StageResult pass(int score, String reasoning) {
            return new StageResult(true, score, reasoning, Collections.emptyMap());
        }
        public static StageResult pass(int score, String reasoning, Map<String, Object> metadata) {
            return new StageResult(true, score, reasoning, metadata);
        }
        public static StageResult fail(int score, String reasoning) {
            return new StageResult(false, score, reasoning, Collections.emptyMap());
        }
        public static StageResult fail(int score, String reasoning, Map<String, Object> metadata) {
            return new StageResult(false, score, reasoning, metadata);
        }
    }
}
