package com.aevum.core.engine;

import com.aevum.core.domain.model.Artifact;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.nio.file.*;
import java.util.*;
import java.util.jar.*;
import java.util.stream.*;

/**
 * Verifies if a vulnerable artifact is present in the runtime classpath.
 * Checks: WEB-INF/lib, fat-JAR manifest, module path.
 */
@Component
public class ClasspathVerifier {
    private static final Logger LOG = LoggerFactory.getLogger(ClasspathVerifier.class);

    public ClasspathCheckResult verifyClasspathPresence(Artifact artifact, Path buildOutput) {
        LOG.debug("Checking classpath presence for: {}", artifact.getCoordinate());

        if (!Files.exists(buildOutput)) {
            return ClasspathCheckResult.notPresent("Build output does not exist: " + buildOutput);
        }

        // Check 1: WEB-INF/lib for WAR files
        Path webInfLib = buildOutput.resolve("WEB-INF/lib");
        if (Files.exists(webInfLib)) {
            Optional<Path> match = findJarInDirectory(webInfLib, artifact);
            if (match.isPresent()) {
                return ClasspathCheckResult.present("WEB-INF/lib", match.get().toString());
            }
        }

        // Check 2: Fat JAR (BOOT-INF/lib for Spring Boot)
        Path bootInfLib = buildOutput.resolve("BOOT-INF/lib");
        if (Files.exists(bootInfLib)) {
            Optional<Path> match = findJarInDirectory(bootInfLib, artifact);
            if (match.isPresent()) {
                return ClasspathCheckResult.present("BOOT-INF/lib", match.get().toString());
            }
        }

        // Check 3: Direct JAR output
        if (buildOutput.toString().endsWith(".jar")) {
            boolean contains = checkJarContains(buildOutput, artifact);
            if (contains) {
                return ClasspathCheckResult.present("FAT_JAR", buildOutput.toString());
            }
        }

        // Check 4: Maven target/classes or module path
        Path classesDir = buildOutput.resolve("classes");
        if (Files.exists(classesDir)) {
            boolean found = checkClassesDirectory(classesDir, artifact);
            if (found) {
                return ClasspathCheckResult.present("CLASSES_DIR", classesDir.toString());
            }
        }

        return ClasspathCheckResult.notPresent("Artifact not found in any classpath location");
    }

    private Optional<Path> findJarInDirectory(Path dir, Artifact artifact) {
        String expectedPrefix = artifact.getArtifactId() + "-";
        try (Stream<Path> paths = Files.list(dir)) {
            return paths
                .filter(p -> p.getFileName().toString().startsWith(expectedPrefix))
                .filter(p -> p.getFileName().toString().contains(artifact.getVersion()))
                .findFirst();
        } catch (IOException e) {
            LOG.warn("Error scanning directory: {}", dir, e);
            return Optional.empty();
        }
    }

    private boolean checkJarContains(Path jarPath, Artifact artifact) {
        try (JarFile jarFile = new JarFile(jarPath.toFile())) {
            String expectedPath = "BOOT-INF/lib/" + artifact.getArtifactId() + "-" + artifact.getVersion() + ".jar";
            return jarFile.getJarEntry(expectedPath) != null;
        } catch (IOException e) {
            return false;
        }
    }

    private boolean checkClassesDirectory(Path classesDir, Artifact artifact) {
        String packagePath = artifact.getGroupId().replace('.', '/');
        Path packageDir = classesDir.resolve(packagePath);
        return Files.exists(packageDir);
    }

    public record ClasspathCheckResult(
        boolean present,
        String location,
        String path,
        String reason
    ) {
        public static ClasspathCheckResult present(String location, String path) {
            return new ClasspathCheckResult(true, location, path, "Artifact found in " + location);
        }
        public static ClasspathCheckResult notPresent(String reason) {
            return new ClasspathCheckResult(false, "NONE", "", reason);
        }
    }
}
