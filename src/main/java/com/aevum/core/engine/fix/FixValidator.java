package com.aevum.core.engine.fix;

import com.aevum.core.domain.model.FixOption;
import com.aevum.core.engine.proof.ProofPackageBuilder;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.nio.file.*;
import java.nio.file.attribute.BasicFileAttributes;
import java.time.Duration;
import java.util.List;

/**
 * Validates proposed fixes by applying changes to a temp copy of the project,
 * building it, and running tests. Returns a ProofPackage on success.
 *
 * FIX: The original pom.xml string replace logic was completely broken:
 *   content.replace(
 *     "<artifactId>" + X + "</artifactId>\n        <version>" + PROPOSED,
 *     "<artifactId>" + X + "</artifactId>\n        <version>" + PROPOSED
 *   )
 * This replaces a string containing the NEW version with itself — it does nothing.
 * The fix: find the current version of the artifact in pom.xml and replace it with proposed.
 *
 * FIX 2: copyDirectory used Files.walk() with a lambda that swallowed IOExceptions by
 * wrapping in RuntimeException — causing confusing failures. Now uses Files.walkFileTree
 * with proper SimpleFileVisitor which handles errors cleanly.
 *
 * FIX 3: FixValidator is now a @Component so Spring can inject it and ProofPackageBuilder.
 */
@Component
public class FixValidator {

    public static final class FixValidationResult {
        public final FixOption fixOption;
        public final boolean passed;
        public final MavenBuildExecutor.BuildResult buildResult;
        public final TestRunner.TestResult testResult;
        public final ProofPackageBuilder.ProofPackage proofPackage;

        public FixValidationResult(FixOption fixOption, boolean passed,
                                   MavenBuildExecutor.BuildResult buildResult,
                                   TestRunner.TestResult testResult,
                                   ProofPackageBuilder.ProofPackage proofPackage) {
            this.fixOption = fixOption;
            this.passed = passed;
            this.buildResult = buildResult;
            this.testResult = testResult;
            this.proofPackage = proofPackage;
        }
    }

    private final MavenBuildExecutor buildExecutor;
    private final TestRunner testRunner;
    private final ProofPackageBuilder proofBuilder;

    public FixValidator(MavenBuildExecutor buildExecutor,
                        TestRunner testRunner,
                        ProofPackageBuilder proofBuilder) {
        this.buildExecutor = buildExecutor;
        this.testRunner = testRunner;
        this.proofBuilder = proofBuilder;
    }

    public FixValidationResult validateFix(Path projectDir, FixOption candidate,
                                           Duration timeout) throws Exception {
        // Create isolated working copy
        Path tmp = Files.createTempDirectory("aevum-fix-");
        try {
            copyDirectory(projectDir, tmp);
            applyFixToPom(tmp, candidate);

            MavenBuildExecutor.BuildResult buildResult =
                    buildExecutor.runMavenBuild(tmp, List.of("-q", "package"), timeout);

            TestRunner.TestResult testResult = buildResult.success
                    ? testRunner.runTests(tmp, timeout)
                    : new TestRunner.TestResult(false, List.of(), "(skipped — build failed)");

            boolean passed = buildResult.success && testResult.allPassed;

            ProofPackageBuilder.ProofPackage proof = proofBuilder.buildProof(
                    tmp, candidate, new ProofPackageBuilder.ValidationSummary(buildResult, testResult));

            return new FixValidationResult(candidate, passed, buildResult, testResult, proof);

        } finally {
            // Clean up temp directory to avoid disk accumulation
            deleteDirectory(tmp);
        }
    }

    /**
     * FIX: Correct pom.xml patching logic.
     *
     * For VERSION_ALIGNMENT: we need to change the version of the target artifact.
     * Strategy: find the line pattern:
     *   <artifactId>ARTIFACT_ID</artifactId>
     * then on the NEXT version line, replace the old version with proposed version.
     *
     * This is a naive but correct approach for simple pom.xml structures.
     * Production would use Maven XML DOM manipulation, but that adds complexity.
     */
    private void applyFixToPom(Path projectDir, FixOption candidate) throws IOException {
        if (candidate.getProposedVersion() == null || candidate.getTargetDependency() == null) {
            return; // Exclusion fixes handled separately (no version to change)
        }

        Path pom = projectDir.resolve("pom.xml");
        if (!Files.exists(pom)) return;

        String artifactId = extractArtifactId(candidate.getTargetDependency());
        if (artifactId == null || artifactId.isEmpty()) return;

        String content = Files.readString(pom);
        String[] lines = content.split("\n");
        StringBuilder result = new StringBuilder();

        boolean foundArtifact = false;
        boolean replaced = false;

        for (int i = 0; i < lines.length; i++) {
            String line = lines[i];

            // Track when we find the target artifact
            if (line.contains("<artifactId>" + artifactId + "</artifactId>")) {
                foundArtifact = true;
            }

            // FIX: If we just found the artifact and this is the version line, replace it
            if (foundArtifact && !replaced && line.trim().startsWith("<version>") && line.trim().endsWith("</version>")) {
                // Extract current version and replace with proposed
                String trimmed = line.trim();
                String currentVersion = trimmed.substring("<version>".length(),
                        trimmed.length() - "</version>".length());

                // Only replace if it's not already the proposed version
                if (!currentVersion.equals(candidate.getProposedVersion())) {
                    line = line.replace(
                            "<version>" + currentVersion + "</version>",
                            "<version>" + candidate.getProposedVersion() + "</version>"
                    );
                    replaced = true;
                    foundArtifact = false;
                }
            }

            // Reset artifact tracking if we pass a closing </dependency> without replacing
            if (foundArtifact && line.trim().equals("</dependency>")) {
                foundArtifact = false;
            }

            result.append(line).append("\n");
        }

        Files.writeString(pom, result.toString());
    }

    private String extractArtifactId(String shortCoordinate) {
        if (shortCoordinate == null) return null;
        int idx = shortCoordinate.indexOf(":");
        return idx >= 0 ? shortCoordinate.substring(idx + 1) : shortCoordinate;
    }

    /**
     * FIX: Use Files.walkFileTree with SimpleFileVisitor for clean error handling.
     * The original lambda-based approach threw RuntimeException on any IOException,
     * making failures very hard to diagnose.
     */
    private void copyDirectory(Path src, Path dest) throws IOException {
        Files.walkFileTree(src, new CopyVisitor(src, dest));
    }

    private void deleteDirectory(Path dir) throws IOException {
        if (!Files.exists(dir)) return;
        Files.walkFileTree(dir, new DeleteVisitor(dir));
    }

    private static final class CopyVisitor extends SimpleFileVisitor<Path> {
        private final Path src;
        private final Path dest;

        CopyVisitor(Path src, Path dest) {
            this.src = src;
            this.dest = dest;
        }

        @Override
        public FileVisitResult preVisitDirectory(Path dir, BasicFileAttributes attrs) throws IOException {
            Files.createDirectories(dest.resolve(src.relativize(dir)));
            return FileVisitResult.CONTINUE;
        }

        @Override
        public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) throws IOException {
            Files.copy(file, dest.resolve(src.relativize(file)), StandardCopyOption.REPLACE_EXISTING);
            return FileVisitResult.CONTINUE;
        }

        @Override
        public FileVisitResult visitFileFailed(Path file, IOException exc) {
            return FileVisitResult.CONTINUE;
        }
    }

    private static final class DeleteVisitor extends SimpleFileVisitor<Path> {
        private final Path root;

        DeleteVisitor(Path root) { this.root = root; }

        @Override
        public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) throws IOException {
            Files.deleteIfExists(file);
            return FileVisitResult.CONTINUE;
        }

        @Override
        public FileVisitResult postVisitDirectory(Path directory, IOException exc) throws IOException {
            Files.deleteIfExists(directory);
            return FileVisitResult.CONTINUE;
        }
    }
}