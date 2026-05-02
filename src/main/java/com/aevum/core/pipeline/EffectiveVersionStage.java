package com.aevum.core.pipeline;

import com.aevum.core.domain.model.*;
import com.aevum.core.engine.BomResolver;
import com.aevum.core.engine.version.VersionRangeEvaluator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.util.*;

/**
 * Stage 2: Effective Version Check via BOM resolution.
 * 85% of false positives are eliminated here.
 */
@Component
public class EffectiveVersionStage implements Stage {
    private static final Logger LOG = LoggerFactory.getLogger(EffectiveVersionStage.class);
    private final BomResolver bomResolver;

    public EffectiveVersionStage(BomResolver bomResolver) {
        this.bomResolver = bomResolver;
    }

    @Override
    public String getName() { return "STAGE_02_EFFECTIVE_VERSION"; }

    @Override
    public StageResult execute(VulnerabilitySignal signal, StageContext context) {
        EffectivePom effectivePom = context.getEffectivePom();

        BomResolver.ResolutionResult result = bomResolver.resolveEffectiveVersion(
            signal.getGroupId(), signal.getArtifactId(), effectivePom);

        if (!result.isFound()) {
            String reason = "FALSE POSITIVE: Artifact not found in resolved dependency tree: " + signal.getShortCoordinate();
            LOG.info(reason);
            return StageResult.fail(0, reason,
                Map.of("resolution", "NOT_FOUND"));
        }

        Artifact effective = result.resolvedArtifact();
        String reportedVersion = signal.getReportedVersion();
        String effectiveVersion = effective.getVersion();
        String affectedRange = signal.getMetadata() != null ? signal.getMetadata().get("affectedRange") : null;

        LOG.debug("Reported version: {}, Effective version: {} (rule: {})",
                 reportedVersion, effectiveVersion, result.mediationRule());

        // Store for later stages
        context.put("effectiveArtifact", effective);
        context.put("resolutionResult", result);
        // If the scanner provided an affected range, ensure the resolved/effective
        // version falls inside that range. If it does not, this is a false positive.
        if (affectedRange != null && !affectedRange.isBlank()) {
            boolean inRange = VersionRangeEvaluator.isVersionInRange(effectiveVersion, affectedRange);
            if (!inRange) {
                String reason = String.format(
                    "FALSE POSITIVE: Effective version %s is NOT in vulnerable range %s (reported was %s)",
                    effectiveVersion, affectedRange, reportedVersion);
                LOG.info(reason);
                return StageResult.fail(0, reason,
                    Map.of(
                        "reportedVersion", reportedVersion,
                        "effectiveVersion", effectiveVersion,
                        "affectedRange", affectedRange,
                        "mediationRule", result.mediationRule(),
                        "resolutionTrace", result.trace()
                    ));
            }
        } else {
            // Fallback behavior: if no range was supplied, require reported==effective
            if (!reportedVersion.equals(effectiveVersion)) {
                String reason = String.format(
                    "FALSE POSITIVE: Scanner reported %s but Maven resolved %s via %s. " +
                    "The vulnerable version is NOT on the runtime classpath.",
                    reportedVersion, effectiveVersion, result.mediationRule());
                LOG.info(reason);
                return StageResult.fail(0, reason,
                    Map.of(
                        "reportedVersion", reportedVersion,
                        "effectiveVersion", effectiveVersion,
                        "mediationRule", result.mediationRule(),
                        "resolutionTrace", result.trace()
                    ));
            }
        }

        return StageResult.pass(95, "Effective version validated: " + effectiveVersion,
            Map.of(
                "effectiveVersion", effectiveVersion,
                "mediationRule", result.mediationRule(),
                "depth", result.depth(),
                "isDirect", result.isDirect()
            ));
    }
}
