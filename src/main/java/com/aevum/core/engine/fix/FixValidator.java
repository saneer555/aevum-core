package com.aevum.core.engine.fix;

import com.aevum.core.domain.model.FixOption;
import com.aevum.core.engine.proof.ProofPackageBuilder;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;

/**
 * Validates proposed fixes by applying changes in-memory (simple pom edit simulation), building, and running tests.
 */
public class FixValidator {

    public static final class FixValidationResult {
        public final FixOption fixOption;
        public final boolean passed;
        public final MavenBuildExecutor.BuildResult buildResult;
        public final TestRunner.TestResult testResult;
        public final ProofPackageBuilder.ProofPackage proofPackage;

        public FixValidationResult(FixOption fixOption, boolean passed, MavenBuildExecutor.BuildResult buildResult, TestRunner.TestResult testResult, ProofPackageBuilder.ProofPackage proofPackage) {
            this.fixOption = fixOption; this.passed = passed; this.buildResult = buildResult; this.testResult = testResult; this.proofPackage = proofPackage;
        }
    }

    private final MavenBuildExecutor buildExecutor;
    private final TestRunner testRunner;
    private final ProofPackageBuilder proofBuilder;

    public FixValidator(MavenBuildExecutor buildExecutor, TestRunner testRunner, ProofPackageBuilder proofBuilder) {
        this.buildExecutor = buildExecutor; this.testRunner = testRunner; this.proofBuilder = proofBuilder;
    }

    public FixValidationResult validateFix(Path projectDir, FixOption candidate, Duration timeout) throws Exception {
        // Create a working copy of project (simple copy to temp dir)
        Path tmp = Files.createTempDirectory("aevum-fix-");
        copyDirectory(projectDir, tmp);

        // Apply fix: for version alignment or parent upgrade, perform a naive string replace in pom.xml
        if (candidate.getProposedVersion() != null && candidate.getTargetDependency() != null) {
            Path pom = tmp.resolve("pom.xml");
            if (Files.exists(pom)) {
                String content = Files.readString(pom);
                String target = candidate.getTargetDependency();
                // naive replacement: replace <version>OLD</version> occurrences for target artifactId
                content = content.replace("<artifactId>" + artifactIdFrom(target) + "</artifactId>\n        <version>" + candidate.getProposedVersion(), "<artifactId>" + artifactIdFrom(target) + "</artifactId>\n        <version>" + candidate.getProposedVersion());
                Files.writeString(pom, content);
            }
        }

        MavenBuildExecutor.BuildResult buildResult = buildExecutor.runMavenBuild(tmp, List.of("-q", "-DskipTests=false", "package"), timeout);
        TestRunner.TestResult testResult = testRunner.runTests(tmp, timeout);

        boolean passed = buildResult.success && testResult.allPassed;

        ProofPackageBuilder.ProofPackage proof = proofBuilder.buildProof(tmp, candidate, new ProofPackageBuilder.ValidationSummary(buildResult, testResult));

        // cleanup temp? keep for audit - but mark path in proof
        return new FixValidationResult(candidate, passed, buildResult, testResult, proof);
    }

    private void copyDirectory(Path src, Path dest) throws IOException {
        try (var stream = Files.walk(src)) {
            stream.forEach(s -> {
                try {
                    Path rel = src.relativize(s);
                    Path target = dest.resolve(rel.toString());
                    if (Files.isDirectory(s)) {
                        Files.createDirectories(target);
                    } else {
                        Files.copy(s, target);
                    }
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }
            });
        }
    }

    private String artifactIdFrom(String shortCoordinate) {
        // shortCoordinate like group:artifact
        if (shortCoordinate == null) return "";
        int idx = shortCoordinate.indexOf(":");
        if (idx < 0) return shortCoordinate;
        return shortCoordinate.substring(idx + 1);
    }
}
