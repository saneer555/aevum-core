package com.aevum.core.engine.fix;

import org.springframework.stereotype.Component;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Executes Maven builds by shelling out to `mvn` available on PATH. Lightweight and has a timeout.
 */
@Component
public class MavenBuildExecutor {

    public static final class BuildResult {
        public final boolean success;
        public final int exitCode;
        public final String stdout;
        public final String stderr;
        public final long durationMs;

        public BuildResult(boolean success, int exitCode, String stdout, String stderr, long durationMs) {
            this.success = success; this.exitCode = exitCode; this.stdout = stdout; this.stderr = stderr; this.durationMs = durationMs;
        }
    }

    public BuildResult runMavenBuild(Path projectDir, List<String> goals, Duration timeout) throws IOException, InterruptedException {
        List<String> cmd = new ArrayList<>();
        cmd.add("mvn");
        cmd.addAll(goals);
        ProcessBuilder pb = new ProcessBuilder(cmd);
        pb.directory(projectDir.toFile());
        pb.redirectErrorStream(true);
        long start = System.currentTimeMillis();
        Process p = pb.start();
        StreamGobbler gobbler = new StreamGobbler(p);
        Thread t = new Thread(gobbler);
        t.start();
        boolean finished = p.waitFor(timeout.toMillis(), java.util.concurrent.TimeUnit.MILLISECONDS);
        if (!finished) {
            p.destroyForcibly();
            t.join(1000);
            long dur = System.currentTimeMillis() - start;
            return new BuildResult(false, -1, gobbler.getOutput(), "Timed out", dur);
        }
        int exit = p.exitValue();
        t.join(1000);
        long dur = System.currentTimeMillis() - start;
        String out = gobbler.getOutput();
        return new BuildResult(exit == 0, exit, out, "", dur);
    }

    private static final class StreamGobbler implements Runnable {
        private final Process process;
        private final StringBuilder out = new StringBuilder();
        StreamGobbler(Process process) { this.process = process; }
        public void run() {
            try (BufferedReader br = new BufferedReader(new InputStreamReader(process.getInputStream(), StandardCharsets.UTF_8))) {
                String line;
                while ((line = br.readLine()) != null) {
                    out.append(line).append('\n');
                }
            } catch (IOException ignored) {}
        }
        String getOutput() { return out.toString(); }
    }
}

