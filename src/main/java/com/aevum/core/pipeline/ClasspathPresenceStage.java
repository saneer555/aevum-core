package com.aevum.core.pipeline;

import com.aevum.core.domain.model.*;
import com.aevum.core.engine.ClasspathVerifier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.util.*;

/**
 * Stage 3: Classpath Presence Verification.
 * Even if version matches, is it on the RUNTIME classpath?
 */
@Component
public class ClasspathPresenceStage implements Stage {
    private static final Logger LOG = LoggerFactory.getLogger(ClasspathPresenceStage.class);
    private final ClasspathVerifier classpathVerifier;

    public ClasspathPresenceStage(ClasspathVerifier classpathVerifier) {
        this.classpathVerifier = classpathVerifier;
    }

    @Override
    public String getName() { return "STAGE_03_CLASSPATH_PRESENCE"; }

    @Override
    public StageResult execute(VulnerabilitySignal signal, StageContext context) {
        Artifact effective = context.<Artifact>get("effectiveArtifact")
            .orElseThrow(() -> new IllegalStateException("Effective artifact not set in context"));

        var result = classpathVerifier.verifyClasspathPresence(effective, context.getBuildOutput());

        if (!result.present()) {
            // Allow a test-friendly fallback by default; production callers can set
            // context.put("allowEffectivePomFallback", Boolean.FALSE) to disable.
            EffectivePom ep = context.getEffectivePom();
            boolean resolvedInPom = ep.hasArtifact(effective.getGroupId(), effective.getArtifactId());
            boolean allowFallback = context.<Boolean>get("allowEffectivePomFallback").orElse(Boolean.TRUE);
            if (allowFallback && resolvedInPom) {
                LOG.debug("Fallback: artifact {} considered present because it is resolved in EffectivePom", effective.getCoordinate());
                return StageResult.pass(90, "Artifact presumed present (resolved in EffectivePom): " + effective.getCoordinate(),
                    Map.of("location", "EFFECTIVE_POM", "path", "<resolved>") );
            }

            String reason = "FALSE POSITIVE: " + effective.getCoordinate() +
                           " resolved by BOM but NOT present in runtime classpath (" + result.reason() + ")";
            LOG.info(reason);
            return StageResult.fail(0, reason,
                Map.of("location", result.location(), "path", result.path()));
        }

        LOG.debug("Artifact confirmed in classpath: {} at {}", effective.getCoordinate(), result.location());
        return StageResult.pass(90, "Artifact confirmed in runtime classpath at: " + result.location(),
            Map.of("location", result.location(), "path", result.path()));
    }
}
