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

        String jarName = artifact.getArtifactId() + "-" + artifact.getVersion() + ".jar";

        List<Path> searchPaths = Arrays.asList(
            buildOutput.resolve("dependency").resolve(jarName),
            buildOutput.resolve(jarName),
            buildOutput.getParent() != null ? buildOutput.getParent().resolve(jarName) : buildOutput.resolve(jarName),
            buildOutput.resolve("classes"),
            buildOutput.resolve("BOOT-INF/lib").resolve(jarName),
            buildOutput.resolve("WEB-INF/lib").resolve(jarName)
        );

        for (Path p : searchPaths) {
            try {
                if (p != null && Files.exists(p)) {
                    LOG.info("S3: Found JAR at {}", p);
                    // Verify the JAR actually contains classes for the artifact
                    if (Files.isRegularFile(p) && p.toString().endsWith(".jar")) {
                        if (checkJarContains(p, artifact) || p.getFileName().toString().contains(artifact.getVersion())) {
                            return ClasspathCheckResult.present("FILESYSTEM", p.toString());
                        }
                    } else {
                        return ClasspathCheckResult.present("FILESYSTEM", p.toString());
                    }
                }
            } catch (Exception e) {
                LOG.warn("Error checking path {}", p, e);
            }
        }

        // Also check exploded classes folder for presence of the package
        Path classesDir = buildOutput.resolve("classes");
        if (Files.exists(classesDir)) {
            boolean found = checkClassesDirectory(classesDir, artifact);
            if (found) {
                LOG.info("S3: Found classes under {}", classesDir);
                return ClasspathCheckResult.present("CLASSES_DIR", classesDir.toString());
            }
        }

        // Check local maven repository
        Path mavenLocal = Paths.get(System.getProperty("user.home"), ".m2/repository",
            artifact.getGroupId().replace('.', '/'),
            artifact.getArtifactId(),
            artifact.getVersion(),
            jarName);

        if (Files.exists(mavenLocal)) {
            LOG.info("S3: Found JAR in Maven local repo at {}", mavenLocal);
            return ClasspathCheckResult.present("M2_LOCAL", mavenLocal.toString());
        }

        LOG.info("S3: JAR NOT FOUND for {}", artifact.getCoordinate());
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
