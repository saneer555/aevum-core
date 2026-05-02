package com.aevum.core.pipeline;

import com.aevum.core.domain.model.*;
import com.aevum.core.engine.ReachabilityAnalyzer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.util.*;

/**
 * Stage 4: Runtime Reachability Analysis.
 * Is the vulnerable code path actually called from application entry points?
 */
@Component
public class RuntimeReachabilityStage implements Stage {
    private static final Logger LOG = LoggerFactory.getLogger(RuntimeReachabilityStage.class);
    private final ReachabilityAnalyzer reachabilityAnalyzer;

    public RuntimeReachabilityStage(ReachabilityAnalyzer reachabilityAnalyzer) {
        this.reachabilityAnalyzer = reachabilityAnalyzer;
    }

    @Override
    public String getName() { return "STAGE_04_RUNTIME_REACHABILITY"; }

    @Override
    public StageResult execute(VulnerabilitySignal signal, StageContext context) {
        Artifact effective = context.<Artifact>get("effectiveArtifact")
            .orElseThrow(() -> new IllegalStateException("Effective artifact not set in context"));

        var result = reachabilityAnalyzer.analyzeReachability(
            effective, context.getBuildOutput(), context.getEntryPoints(), signal.getCveId(), context.isNetworkExposed());

        if (!result.reachable()) {
            String reason = "FALSE POSITIVE: Vulnerable code path NOT reachable from application entry points. " +
                           "The library is present but the vulnerable classes (" +
                           result.vulnerableClasses().size() + ") are not invoked.";
            LOG.info(reason);
            return StageResult.fail(40, reason,
                Map.of(
                    "vulnerableClasses", result.vulnerableClasses(),
                    "reachableClasses", result.reachableClasses()
                ));
        }

        LOG.debug("Vulnerable code path IS reachable");
        return StageResult.pass(85, "Vulnerable code path is reachable from application entry points",
            Map.of(
                "vulnerableClasses", result.vulnerableClasses(),
                "reachableClasses", result.reachableClasses()
            ));
    }
}
