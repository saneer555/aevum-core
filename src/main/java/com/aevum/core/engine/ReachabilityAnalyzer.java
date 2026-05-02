package com.aevum.core.engine;

import com.aevum.core.domain.model.Artifact;
import org.objectweb.asm.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.*;
import java.util.*;
import java.util.jar.*;
import java.util.stream.*;

/**
 * Static call-graph analysis to determine if vulnerable code paths are reachable
 * from application entry points.
 */
@Component
public class ReachabilityAnalyzer {
    private static final Logger LOG = LoggerFactory.getLogger(ReachabilityAnalyzer.class);

    public ReachabilityResult analyzeReachability(Artifact artifact, Path buildOutput,
                                                   List<String> entryPointClasses) {
        LOG.debug("Analyzing reachability for: {}", artifact.getCoordinate());

        Set<String> vulnerableClasses = discoverVulnerableClasses(artifact, buildOutput);
        if (vulnerableClasses.isEmpty()) {
            return ReachabilityResult.notReachable("No vulnerable classes found in classpath");
        }

        Set<String> reachableClasses = new HashSet<>();
        for (String entryPoint : entryPointClasses) {
            Set<String> visited = new HashSet<>();
            traverseFromEntryPoint(entryPoint, vulnerableClasses, buildOutput, visited);
            reachableClasses.addAll(visited);
        }

        boolean isReachable = !reachableClasses.isEmpty();
        return new ReachabilityResult(
            isReachable,
            vulnerableClasses,
            reachableClasses,
            isReachable ? "Vulnerable code path reachable from entry points" : "No call path from entry points to vulnerable code"
        );
    }

    private Set<String> discoverVulnerableClasses(Artifact artifact, Path buildOutput) {
        Set<String> classes = new HashSet<>();
        String jarName = artifact.getArtifactId() + "-" + artifact.getVersion() + ".jar";

        // Search in BOOT-INF/lib or WEB-INF/lib
        Path[] libDirs = {
            buildOutput.resolve("BOOT-INF/lib"),
            buildOutput.resolve("WEB-INF/lib"),
            buildOutput.getParent() != null ? buildOutput.getParent().resolve("lib") : null
        };

        for (Path libDir : libDirs) {
            if (libDir == null || !Files.exists(libDir)) continue;
            try (Stream<Path> jars = Files.list(libDir)) {
                Optional<Path> targetJar = jars
                    .filter(p -> p.getFileName().toString().startsWith(artifact.getArtifactId()))
                    .filter(p -> p.getFileName().toString().contains(artifact.getVersion()))
                    .findFirst();

                if (targetJar.isPresent()) {
                    classes.addAll(extractClassNames(targetJar.get()));
                }
            } catch (IOException e) {
                LOG.warn("Error scanning lib dir: {}", libDir, e);
            }
        }
        return classes;
    }

    private Set<String> extractClassNames(Path jarPath) {
        Set<String> classes = new HashSet<>();
        try (JarFile jarFile = new JarFile(jarPath.toFile())) {
            Enumeration<JarEntry> entries = jarFile.entries();
            while (entries.hasMoreElements()) {
                JarEntry entry = entries.nextElement();
                if (entry.getName().endsWith(".class")) {
                    classes.add(entry.getName().replace('/', '.').replace(".class", ""));
                }
            }
        } catch (IOException e) {
            LOG.warn("Error reading JAR: {}", jarPath, e);
        }
        return classes;
    }

    private void traverseFromEntryPoint(String entryClass, Set<String> targetClasses,
                                         Path buildOutput, Set<String> visited) {
        Queue<String> queue = new LinkedList<>();
        queue.add(entryClass);
        visited.add(entryClass);

        while (!queue.isEmpty()) {
            String current = queue.poll();
            if (targetClasses.contains(current)) {
                return; // Found a path
            }

            Set<String> references = findClassReferences(current, buildOutput);
            for (String ref : references) {
                if (!visited.contains(ref)) {
                    visited.add(ref);
                    queue.add(ref);
                }
            }
        }
    }

    private Set<String> findClassReferences(String className, Path buildOutput) {
        Set<String> refs = new HashSet<>();
        String classPath = className.replace('.', '/') + ".class";

        // Check classes directory
        Path classFile = buildOutput.resolve("classes/" + classPath);
        if (!Files.exists(classFile)) {
            classFile = buildOutput.resolve(classPath);
        }

        if (Files.exists(classFile)) {
            try (InputStream is = Files.newInputStream(classFile)) {
                ClassReader reader = new ClassReader(is);
                ClassVisitor cv = new ClassVisitor(Opcodes.ASM9) {
                    @Override
                    public void visit(int version, int access, String name, String signature,
                                      String superName, String[] interfaces) {
                        if (superName != null) refs.add(superName.replace('/', '.'));
                        if (interfaces != null) {
                            for (String iface : interfaces) refs.add(iface.replace('/', '.'));
                        }
                    }

                    @Override
                    public MethodVisitor visitMethod(int access, String name, String descriptor,
                                                     String signature, String[] exceptions) {
                        return new MethodVisitor(Opcodes.ASM9) {
                            @Override
                            public void visitMethodInsn(int opcode, String owner, String name,
                                                        String descriptor, boolean isInterface) {
                                refs.add(owner.replace('/', '.'));
                            }
                            @Override
                            public void visitFieldInsn(int opcode, String owner, String name, String descriptor) {
                                refs.add(owner.replace('/', '.'));
                            }
                            @Override
                            public void visitTypeInsn(int opcode, String type) {
                                refs.add(type.replace('/', '.'));
                            }
                        };
                    }
                };
                reader.accept(cv, 0);
            } catch (IOException e) {
                LOG.debug("Could not read class: {}", classFile);
            }
        }
        return refs;
    }

    public record ReachabilityResult(
        boolean reachable,
        Set<String> vulnerableClasses,
        Set<String> reachableClasses,
        String reason
    ) {
        public static ReachabilityResult notReachable(String reason) {
            return new ReachabilityResult(false, Set.of(), Set.of(), reason);
        }
    }
}
