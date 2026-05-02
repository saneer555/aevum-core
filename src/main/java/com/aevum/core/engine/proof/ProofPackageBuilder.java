package com.aevum.core.engine.proof;

import com.aevum.core.domain.model.FixOption;
import com.aevum.core.engine.fix.MavenBuildExecutor;
import com.aevum.core.engine.fix.TestRunner;

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
 * Builds a proof package bundle (zip) containing before/after dependency trees, build logs and test results.
 */
public class ProofPackageBuilder {

    public static final class ValidationSummary {
        public final MavenBuildExecutor.BuildResult buildResult;
        public final TestRunner.TestResult testResult;
        public ValidationSummary(MavenBuildExecutor.BuildResult buildResult, TestRunner.TestResult testResult) {
            this.buildResult = buildResult; this.testResult = testResult;
        }
    }

    public static final class ProofPackage {
        public final String id;
        public final Path path;
        public final long createdAt;
        public final long sizeBytes;

        public ProofPackage(String id, Path path, long createdAt, long sizeBytes) {
            this.id = id; this.path = path; this.createdAt = createdAt; this.sizeBytes = sizeBytes;
        }

        public String getId() { return id; }
        public Path getPath() { return path; }
        public long getCreatedAt() { return createdAt; }
        public long getSizeBytes() { return sizeBytes; }
    }

    private final Path outputDir;

    public ProofPackageBuilder() throws IOException {
        this.outputDir = Files.createDirectories(Path.of("target", "proof-packages"));
    }

    public ProofPackage buildProof(Path projectDir, FixOption fixOption, ValidationSummary summary) throws IOException {
        String id = UUID.randomUUID().toString();
        Path out = outputDir.resolve(id + ".zip");
        try (ZipOutputStream zos = new ZipOutputStream(new BufferedOutputStream(new FileOutputStream(out.toFile())))) {
            // include patched pom if present
            Path pom = projectDir.resolve("pom.xml");
            if (Files.exists(pom)) {
                zos.putNextEntry(new ZipEntry("patched-pom.xml"));
                zos.write(Files.readAllBytes(pom));
                zos.closeEntry();
            }

            // include build log
            zos.putNextEntry(new ZipEntry("build.log"));
            zos.write(summary.buildResult.stdout.getBytes());
            zos.closeEntry();

            // include test output
            zos.putNextEntry(new ZipEntry("test.log"));
            zos.write(summary.testResult.rawOutput.getBytes());
            zos.closeEntry();

            // include manifest (simple)
            String manifest = "id: " + id + "\n" +
                "fix: " + fixOption.getDescription() + "\n" +
                "passed: " + (summary.buildResult.success && summary.testResult.allPassed) + "\n" +
                "timestamp: " + Instant.now().toString() + "\n";
            zos.putNextEntry(new ZipEntry("manifest.txt"));
            zos.write(manifest.getBytes());
            zos.closeEntry();
        }

        long size = Files.size(out);
        // compute simple sha256 of zip
        String sha = sha256(out);
        // write sha alongside
        Files.writeString(outputDir.resolve(id + ".sha256"), sha);
        return new ProofPackage(id, out, Instant.now().toEpochMilli(), size);
    }

    private static String sha256(Path p) throws IOException {
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
            throw new IOException("Failed sha256", e);
        }
    }
}
