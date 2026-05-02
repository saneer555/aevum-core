package com.aevum.core.engine.proof;

import com.aevum.core.domain.model.FixOption;
import com.aevum.core.engine.fix.MavenBuildExecutor;
import com.aevum.core.engine.fix.TestRunner;
import org.springframework.stereotype.Component;

import java.io.BufferedOutputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.UUID;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

/**
 * Builds a proof package bundle (zip) containing patched pom, build logs, and test results.
 *
 * FIX: Original constructor called Files.createDirectories() which throws checked IOException.
 * When used inside FixEngine's constructor (via `new ProofPackageBuilder()`), this forced
 * a try/catch that would throw RuntimeException at Spring startup if target/ doesn't exist.
 *
 * Fix: Made the constructor zero-arg with no I/O. Directory creation is deferred to buildProof()
 * (lazy init), so Spring context startup never fails due to missing target directory.
 *
 * FIX 2: Now a proper @Component so Spring manages lifecycle. FixEngine injects it via constructor.
 */
@Component
public class ProofPackageBuilder {

    private static final Path OUTPUT_DIR = Path.of("target", "proof-packages");

    public static final class ValidationSummary {
        public final MavenBuildExecutor.BuildResult buildResult;
        public final TestRunner.TestResult testResult;

        public ValidationSummary(MavenBuildExecutor.BuildResult buildResult,
                                 TestRunner.TestResult testResult) {
            this.buildResult = buildResult;
            this.testResult = testResult;
        }
    }

    public static final class ProofPackage {
        private final String id;
        private final Path path;
        private final long createdAt;
        private final long sizeBytes;
        private final String sha256;

        public ProofPackage(String id, Path path, long createdAt, long sizeBytes, String sha256) {
            this.id = id;
            this.path = path;
            this.createdAt = createdAt;
            this.sizeBytes = sizeBytes;
            this.sha256 = sha256;
        }

        public String getId() { return id; }
        public Path getPath() { return path; }
        public long getCreatedAt() { return createdAt; }
        public long getSizeBytes() { return sizeBytes; }
        public String getSha256() { return sha256; }

        @Override
        public String toString() {
            return "ProofPackage[id=" + id + ", sha256=" + sha256.substring(0, 16) + "...]";
        }
    }

    /**
     * FIX: No-arg constructor — no I/O at construction time.
     * Spring will call this via component scan with no issues.
     */
    public ProofPackageBuilder() {
        // intentionally empty — directory created lazily in buildProof()
    }

    public ProofPackage buildProof(Path projectDir, FixOption fixOption,
                                   ValidationSummary summary) throws IOException {
        // Lazy directory creation — only when we actually need to write a proof
        Path outDir = Files.createDirectories(OUTPUT_DIR);
        String id = UUID.randomUUID().toString();
        Path out = outDir.resolve(id + ".zip");

        try (ZipOutputStream zos = new ZipOutputStream(
                new BufferedOutputStream(new FileOutputStream(out.toFile())))) {

            // Include patched pom if present
            Path pom = projectDir.resolve("pom.xml");
            if (Files.exists(pom)) {
                addZipEntry(zos, "patched-pom.xml", Files.readAllBytes(pom));
            }

            // Build log
            String buildLog = summary.buildResult != null ? summary.buildResult.stdout : "(no build log)";
            addZipEntry(zos, "build.log", buildLog.getBytes());

            // Test output
            String testLog = summary.testResult != null ? summary.testResult.rawOutput : "(no test log)";
            addZipEntry(zos, "test.log", testLog.getBytes());

            // Manifest
            boolean passed = summary.buildResult != null && summary.buildResult.success
                    && summary.testResult != null && summary.testResult.allPassed;
            String manifest = "id: " + id + "\n"
                    + "fix: " + (fixOption != null ? fixOption.getDescription() : "unknown") + "\n"
                    + "fixType: " + (fixOption != null ? fixOption.getFixType() : "unknown") + "\n"
                    + "targetDependency: " + (fixOption != null ? fixOption.getTargetDependency() : "unknown") + "\n"
                    + "proposedVersion: " + (fixOption != null && fixOption.getProposedVersion() != null
                    ? fixOption.getProposedVersion() : "N/A") + "\n"
                    + "passed: " + passed + "\n"
                    + "buildExitCode: " + (summary.buildResult != null ? summary.buildResult.exitCode : -1) + "\n"
                    + "buildDurationMs: " + (summary.buildResult != null ? summary.buildResult.durationMs : 0) + "\n"
                    + "timestamp: " + Instant.now() + "\n";
            addZipEntry(zos, "manifest.txt", manifest.getBytes());
        }

        long size = Files.size(out);
        String sha = computeSha256(out);

        // Write SHA alongside zip for external verification
        Files.writeString(outDir.resolve(id + ".sha256"), sha);

        return new ProofPackage(id, out, Instant.now().toEpochMilli(), size, sha);
    }

    private void addZipEntry(ZipOutputStream zos, String name, byte[] data) throws IOException {
        zos.putNextEntry(new ZipEntry(name));
        zos.write(data);
        zos.closeEntry();
    }

    private String computeSha256(Path p) throws IOException {
        try (var is = Files.newInputStream(p)) {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] buf = new byte[8192];
            int r;
            while ((r = is.read(buf)) > 0) md.update(buf, 0, r);
            byte[] digest = md.digest();
            StringBuilder sb = new StringBuilder();
            for (byte b : digest) sb.append(String.format("%02x", b));
            return sb.toString();
        } catch (Exception e) {
            throw new IOException("SHA-256 computation failed", e);
        }
    }
}