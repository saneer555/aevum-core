package com.aevum.core;

import com.aevum.core.domain.enums.Scope;
import com.aevum.core.domain.enums.VerificationStatus;
import com.aevum.core.domain.model.*;
import com.aevum.core.engine.*;
import com.aevum.core.pipeline.*;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.nio.file.Paths;
import java.util.*;

import static org.assertj.core.api.Assertions.assertThat;

class VerificationPipelineTest {

    private VerificationPipeline pipeline;

    @BeforeEach
    void setUp() {
        BomResolver bomResolver = new BomResolver();
        ClasspathVerifier classpathVerifier = new ClasspathVerifier();
        ReachabilityAnalyzer reachabilityAnalyzer = new ReachabilityAnalyzer();
        ExploitabilityAssessor exploitabilityAssessor = new ExploitabilityAssessor();
        FixEngine fixEngine = new FixEngine();

        pipeline = new VerificationPipeline(
            new NormalizeStage(),
            new EffectiveVersionStage(bomResolver),
            new ClasspathPresenceStage(classpathVerifier),
            new RuntimeReachabilityStage(reachabilityAnalyzer),
            new ExploitabilityStage(exploitabilityAssessor),
            new ConfidenceScorerStage(),
            bomResolver,
            fixEngine
        );
    }

    @Test
    void log4ShellConfirmed() {
        VulnerabilitySignal signal = VulnerabilitySignal.builder()
            .signalId("sig-1")
            .scannerSource("snyk")
            .cveId("CVE-2021-44228")
            .groupId("org.apache.logging.log4j")
            .artifactId("log4j-core")
            .reportedVersion("2.14.1")
            .severity("critical")
            .cvssScore(10.0)
            .description("Log4Shell")
            .build();

        Artifact log4j = new Artifact("org.apache.logging.log4j", "log4j-core", "2.14.1", Scope.COMPILE);
        EffectivePom pom = new EffectivePom(
            "test",
            List.of(log4j),
            List.of(),
            Map.of(),
            Map.of("org.apache.logging.log4j:log4j-core", log4j),
            List.of(DependencyNode.root(log4j))
        );

        StageContext context = new StageContext(pom, Paths.get("target"), List.of("com.app.Main"), true);
        VerificationResult result = pipeline.verify(signal, context);

        assertThat(result.getStatus()).isEqualTo(VerificationStatus.CONFIRMED);
        assertThat(result.getConfidenceScore().getTotalScore()).isGreaterThanOrEqualTo(90);
        assertThat(result.isInClasspath()).isTrue();
        assertThat(result.hasFixOptions()).isTrue();
    }

    @Test
    void versionMismatchIsFalsePositive() {
        VulnerabilitySignal signal = VulnerabilitySignal.builder()
            .signalId("sig-2")
            .scannerSource("snyk")
            .cveId("CVE-2023-XXXX")
            .groupId("org.apache.tomcat.embed")
            .artifactId("tomcat-embed-core")
            .reportedVersion("9.0.50")
            .severity("high")
            .cvssScore(7.5)
            .build();

        // BOM resolved newer version
        Artifact resolved = new Artifact("org.apache.tomcat.embed", "tomcat-embed-core", "9.0.90", Scope.COMPILE);
        EffectivePom pom = new EffectivePom(
            "test",
            List.of(),
            List.of(new BomDeclaration(
                new Artifact("org.springframework.boot", "spring-boot-dependencies", "3.2.0", Scope.IMPORT),
                Map.of("org.apache.tomcat.embed:tomcat-embed-core", "9.0.90")
            )),
            Map.of(),
            Map.of("org.apache.tomcat.embed:tomcat-embed-core", resolved),
            List.of()
        );

        StageContext context = new StageContext(pom, Paths.get("target"), List.of(), true);
        VerificationResult result = pipeline.verify(signal, context);

        assertThat(result.getStatus()).isEqualTo(VerificationStatus.FALSE_POSITIVE);
        assertThat(result.getConfidenceScore().getTotalScore()).isLessThan(70);
        assertThat(result.hasFixOptions()).isFalse();
    }

    @Test
    void kevBoostsConfidence() {
        VulnerabilitySignal signal = VulnerabilitySignal.builder()
            .signalId("sig-3")
            .scannerSource("snyk")
            .cveId("CVE-2021-44228")
            .groupId("org.apache.logging.log4j")
            .artifactId("log4j-core")
            .reportedVersion("2.14.1")
            .severity("critical")
            .cvssScore(10.0)
            .build();

        Artifact log4j = new Artifact("org.apache.logging.log4j", "log4j-core", "2.14.1", Scope.COMPILE);
        EffectivePom pom = new EffectivePom(
            "test",
            List.of(log4j),
            List.of(),
            Map.of(),
            Map.of("org.apache.logging.log4j:log4j-core", log4j),
            List.of(DependencyNode.root(log4j))
        );

        StageContext context = new StageContext(pom, Paths.get("target"), List.of("com.app.Main"), true);
        VerificationResult result = pipeline.verify(signal, context);

        // Log4Shell is in KEV, should get confidence boost
        assertThat(result.getStatus()).isEqualTo(VerificationStatus.CONFIRMED);
        assertThat(result.getConfidenceScore().getTotalScore()).isGreaterThanOrEqualTo(90);
    }
}
