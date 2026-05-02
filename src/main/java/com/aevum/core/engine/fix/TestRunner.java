package com.aevum.core.engine.fix;

import org.springframework.stereotype.Component;

import java.io.IOException;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

/**
 * Executes tests by invoking Maven test goal and parses basic surefire output (best-effort).
 */
@Component
public class TestRunner {

    public static final class TestFailure {
        public final String testName;
        public final String reason;
        public TestFailure(String testName, String reason) { this.testName = testName; this.reason = reason; }
    }

    public static final class TestResult {
        public final boolean allPassed;
        public final List<TestFailure> failures;
        public final String rawOutput;

        public TestResult(boolean allPassed, List<TestFailure> failures, String rawOutput) {
            this.allPassed = allPassed; this.failures = List.copyOf(failures); this.rawOutput = rawOutput;
        }
    }

    private final MavenBuildExecutor buildExecutor;

    public TestRunner(MavenBuildExecutor buildExecutor) {
        this.buildExecutor = buildExecutor;
    }

    public TestResult runTests(Path projectDir, Duration timeout) throws IOException, InterruptedException {
        MavenBuildExecutor.BuildResult br = buildExecutor.runMavenBuild(projectDir, List.of("-q", "test"), timeout);
        // Best-effort parse: if output contains "Failures:" or "Tests run:" lines, detect failures
        List<TestFailure> failures = new ArrayList<>();
        String out = br.stdout + "\n" + br.stderr;
        if (out.contains("FAILURE") || out.contains("Tests run:")) {
            // naive: if 'Failures:' or 'Tests run: X, Failures: Y' indicates failures
            String[] lines = out.split("\n");
            for (String l : lines) {
                if (l.contains("Failures:") || l.contains("Failed tests:")) {
                    failures.add(new TestFailure("unknown", l.trim()));
                }
            }
        }
        boolean allPassed = failures.isEmpty() && br.success;
        return new TestResult(allPassed, failures, out);
    }
}

