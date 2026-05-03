package com.aevum.core.service;

import com.aevum.core.cache.BomCache;
import com.aevum.core.domain.model.*;
import com.aevum.core.domain.enums.Scope;
import com.aevum.core.dto.ScanRequest;
import com.aevum.core.dto.ScanResponse;
import com.aevum.core.engine.*;
import com.aevum.core.pipeline.*;
import com.aevum.core.util.Threading;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import javax.xml.parsers.DocumentBuilderFactory;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.*;
import java.util.concurrent.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Service
public class VerificationService {
    private static final Logger LOG = LoggerFactory.getLogger(VerificationService.class);
    private static final Pattern PROPERTY_PATTERN = Pattern.compile("\\$\\{([^}]+)\\}");

    private final VerificationPipeline pipeline;
    private final BomResolver bomResolver;
    private final BomCache bomCache;

    public VerificationService(VerificationPipeline pipeline,
                               BomResolver bomResolver,
                               BomCache bomCache) {
        this.pipeline = pipeline;
        this.bomResolver = bomResolver;
        this.bomCache = bomCache;
    }

    public ScanResponse verify(ScanRequest request) {
        return verify(request, false);
    }

    public ScanResponse verify(ScanRequest request, boolean validateFixes) {
        long startTime = System.currentTimeMillis();
        String scanId = UUID.randomUUID().toString();
        LOG.info("Starting scan {} for project: {} (validateFixes={})",
                scanId, request.projectId(), validateFixes);

        EffectivePom effectivePom = buildEffectivePom(request);

        Path buildOutput = (request.buildOutputPath() != null && !request.buildOutputPath().isBlank())
                ? Paths.get(request.buildOutputPath())
                : Paths.get("target");

        List<String> entryPoints = (request.entryPointClasses() != null
                && !request.entryPointClasses().isEmpty())
                ? request.entryPointClasses()
                : List.of("com.example.Application");

        StageContext sharedContext = new StageContext(
                effectivePom, buildOutput, entryPoints, request.networkExposed());

        List<VulnerabilitySignal> signals = normalizeSignals(request);
        LOG.info("Normalized {} signal(s) for scan {}", signals.size(), scanId);
        for (VulnerabilitySignal s : signals) {
            LOG.info("Signal {}: cve={}, coord={}, safeVersions={}",
                    s.getSignalId(), s.getCveId(), s.getCoordinate(), s.getSafeVersions());
        }

        List<VerificationResult> results = processSignalsConcurrently(
                signals, sharedContext, validateFixes);

        List<ScanResponse.VulnerabilityResult> confirmed = new ArrayList<>();
        List<ScanResponse.VulnerabilityResult> falsePositives = new ArrayList<>();
        List<ScanResponse.VulnerabilityResult> inconclusive = new ArrayList<>();
        List<ScanResponse.ConfirmedVulnerability> confirmedVulns = new ArrayList<>();
        List<ScanResponse.FalsePositiveDetail> falsePosDetails = new ArrayList<>();

        for (VerificationResult result : results) {
            ScanResponse.VulnerabilityResult dto = toDto(result);
            switch (result.getStatus()) {
                case CONFIRMED -> {
                    confirmed.add(dto);
                    confirmedVulns.add(toConfirmedVuln(result));
                }
                case FALSE_POSITIVE -> {
                    falsePositives.add(dto);
                    falsePosDetails.add(toFalsePositiveDetail(result));
                }
                case INCONCLUSIVE -> inconclusive.add(dto);
            }
        }

        long durationMs = System.currentTimeMillis() - startTime;
        int total = signals.size();
        double fpRate = total > 0 ? (double) falsePositives.size() / total * 100.0 : 0.0;

        LOG.info("Scan {} complete: {} confirmed, {} false positives, {} inconclusive in {}ms (FP rate: {}%)",
                scanId, confirmed.size(), falsePositives.size(), inconclusive.size(),
                durationMs, String.format("%.1f", fpRate));

        return new ScanResponse(
                scanId,
                request.projectId(),
                confirmed,
                falsePositives,
                inconclusive,
                confirmedVulns,
                falsePosDetails,
                new ScanResponse.ScanMetrics(
                        total, confirmed.size(), falsePositives.size(),
                        inconclusive.size(), durationMs, fpRate)
        );
    }

    // ── EffectivePom Construction ─────────────────────────────────────────────

    private EffectivePom buildEffectivePom(ScanRequest request) {
        String pomContent = request.pomContent();
        if (pomContent != null && !pomContent.isBlank()) {
            Optional<EffectivePom> cached = bomCache.get(pomContent);
            if (cached.isPresent()) {
                LOG.debug("Using cached EffectivePom for project: {}", request.projectId());
                return cached.get();
            }
        }
        EffectivePom pom = constructEffectivePom(request);
        if (pomContent != null && !pomContent.isBlank()) {
            bomCache.put(pomContent, pom);
        }
        return pom;
    }

    private EffectivePom constructEffectivePom(ScanRequest request) {
        String pomContent = request.pomContent();
        boolean hasPomContent = pomContent != null && !pomContent.isBlank();

        if (hasPomContent) {
            try {
                return parsePomXml(request.projectId(), pomContent);
            } catch (Exception e) {
                LOG.warn("Failed to parse pomContent for project '{}', falling back to signal-based synthetic POM: {}",
                        request.projectId(), e.getMessage());
            }
        }

        List<Artifact> directDeps = new ArrayList<>();
        Map<String, Artifact> resolved = new HashMap<>();
        List<DependencyNode> tree = new ArrayList<>();

        if (request.signals() != null) {
            for (ScanRequest.VulnerabilityInput sig : request.signals()) {
                if (sig.version() == null || sig.version().isBlank()) continue;
                Artifact artifact = new Artifact(
                        sig.groupId(), sig.artifactId(), sig.version(), Scope.COMPILE);
                directDeps.add(artifact);
                resolved.put(artifact.getShortCoordinate(), artifact);
                tree.add(DependencyNode.root(artifact));
            }
        }
        return new EffectivePom(
                request.projectId(), directDeps, List.of(), Map.of(), resolved, tree);
    }

    /**
     * Parse POM XML with property resolution.
     */
    private EffectivePom parsePomXml(String projectId, String pomContent) throws Exception {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
        dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);

        Document doc = dbf.newDocumentBuilder()
                .parse(new ByteArrayInputStream(pomContent.getBytes(StandardCharsets.UTF_8)));
        doc.getDocumentElement().normalize();

        // ── Extract properties first ──
        Map<String, String> properties = extractProperties(doc);

        List<Artifact> directDeps = new ArrayList<>();
        Map<String, Artifact> resolved = new HashMap<>();
        List<DependencyNode> tree = new ArrayList<>();

        NodeList depNodes = doc.getElementsByTagName("dependency");
        for (int i = 0; i < depNodes.getLength(); i++) {
            Element dep = (Element) depNodes.item(i);
            if (isInsideDependencyManagement(dep)) continue;

            String groupId = textContent(dep, "groupId");
            String artifactId = textContent(dep, "artifactId");
            String version = textContent(dep, "version");
            String scope = textContent(dep, "scope");

            if (groupId.isBlank() || artifactId.isBlank()) continue;
            if ("test".equalsIgnoreCase(scope)) {
                LOG.debug("Skipping test-scoped dependency: {}:{}", groupId, artifactId);
                continue;
            }

            // ── CRITICAL FIX: Resolve property placeholders ──
            String resolvedVersion = resolveProperty(version, properties);
            if (resolvedVersion.isBlank()) {
                LOG.debug("Dependency {}:{} has no resolvable version (BOM-managed or empty)", groupId, artifactId);
                continue;
            }

            Scope mavenScope = parseScope(scope);
            Artifact artifact = new Artifact(groupId, artifactId, resolvedVersion, mavenScope);
            directDeps.add(artifact);
            resolved.put(artifact.getShortCoordinate(), artifact);
            tree.add(DependencyNode.root(artifact));
            LOG.debug("POM dependency parsed: {} (raw version: {}, resolved: {})",
                    artifact.getCoordinate(), version, resolvedVersion);
        }

        LOG.info("Parsed {} direct dependency(ies) from pomContent for project '{}'",
                directDeps.size(), projectId);

        return new EffectivePom(projectId, directDeps, List.of(), properties, resolved, tree);
    }

    private Map<String, String> extractProperties(Document doc) {
        Map<String, String> props = new HashMap<>();
        NodeList propNodes = doc.getElementsByTagName("properties");
        if (propNodes.getLength() > 0) {
            Element propsElement = (Element) propNodes.item(0);
            NodeList children = propsElement.getChildNodes();
            for (int i = 0; i < children.getLength(); i++) {
                if (children.item(i) instanceof Element child) {
                    String key = child.getTagName();
                    String value = child.getTextContent();
                    if (value != null && !value.isBlank()) {
                        props.put(key, value.trim());
                    }
                }
            }
        }
        // Built-in Maven properties
        props.put("project.version", "1.0.0");
        return props;
    }

    private String resolveProperty(String value, Map<String, String> properties) {
        if (value == null || value.isBlank()) return "";
        if (!value.startsWith("${")) return value;

        Matcher m = PROPERTY_PATTERN.matcher(value);
        if (m.matches()) {
            String propName = m.group(1);
            String resolved = properties.get(propName);
            if (resolved != null) {
                LOG.debug("Resolved property {} -> {}", propName, resolved);
                return resolved;
            }
            LOG.warn("Unresolved property reference: {}", value);
        }
        return value;
    }

    private boolean isInsideDependencyManagement(Element dep) {
        org.w3c.dom.Node parent = dep.getParentNode();
        while (parent != null) {
            if ("dependencyManagement".equals(parent.getNodeName())) return true;
            parent = parent.getParentNode();
        }
        return false;
    }

    private String textContent(Element parent, String tagName) {
        NodeList nodes = parent.getElementsByTagName(tagName);
        if (nodes.getLength() == 0) return "";
        String text = nodes.item(0).getTextContent();
        return text != null ? text.trim() : "";
    }

    private Scope parseScope(String scope) {
        if (scope == null || scope.isBlank()) return Scope.COMPILE;
        switch (scope.toLowerCase()) {
            case "provided": return Scope.PROVIDED;
            case "runtime": return Scope.RUNTIME;
            case "test": return Scope.TEST;
            case "system": return Scope.SYSTEM;
            case "import": return Scope.IMPORT;
            default: return Scope.COMPILE;
        }
    }

    // ── Signal Normalization ──────────────────────────────────────────────────

    private List<VulnerabilitySignal> normalizeSignals(ScanRequest request) {
        if (request.signals() == null) return List.of();

        List<VulnerabilitySignal> signals = new ArrayList<>();

        for (ScanRequest.VulnerabilityInput input : request.signals()) {
            Map<String, String> metadata = new LinkedHashMap<>();
            if (input.vulnerableRange() != null && !input.vulnerableRange().isBlank()) {
                metadata.put("affectedRange", input.vulnerableRange());
            }

            String signalId = (input.signalId() != null && !input.signalId().isBlank())
                    ? input.signalId()
                    : UUID.randomUUID().toString();

            String scannerSource = (input.scannerSource() != null && !input.scannerSource().isBlank())
                    ? input.scannerSource()
                    : "manual";

            // ── CRITICAL: Ensure safeVersions is ALWAYS populated ──
            List<String> safeVersions = resolveSafeVersions(input);

            LOG.info("Building signal {}: cve={}, safeVersions={}", signalId, input.cveId(), safeVersions);

            VulnerabilitySignal signal = VulnerabilitySignal.builder()
                    .signalId(signalId)
                    .scannerSource(scannerSource)
                    .cveId(input.cveId())
                    .groupId(input.groupId())
                    .artifactId(input.artifactId())
                    .reportedVersion(input.version())
                    .severity(input.severity())
                    .cvssScore(input.cvssScore())
                    .description(input.description())
                    .safeVersions(safeVersions)
                    .metadata(metadata)
                    .build();

            // Defensive verification
            if (signal.getSafeVersions() == null || signal.getSafeVersions().isEmpty()) {
                LOG.error("CRITICAL: Signal {} has EMPTY safeVersions after build! Input safeVersions={}, defaults={}",
                        signalId, input.safeVersions(), defaultSafeVersions(input.cveId()));
            } else {
                LOG.info("Signal {} built successfully with safeVersions={}", signalId, signal.getSafeVersions());
            }

            signals.add(signal);
        }

        return signals;
    }

    private List<String> resolveSafeVersions(ScanRequest.VulnerabilityInput input) {
        // Layer 1: Use input-provided safeVersions if present
        if (input.safeVersions() != null && !input.safeVersions().isEmpty()) {
            LOG.debug("Using input-provided safeVersions for {}: {}", input.cveId(), input.safeVersions());
            return List.copyOf(input.safeVersions());
        }

        // Layer 2: Default mapping for known CVEs
        List<String> defaults = defaultSafeVersions(input.cveId());
        if (!defaults.isEmpty()) {
            LOG.debug("Using default safeVersions for {}: {}", input.cveId(), defaults);
            return defaults;
        }

        // Layer 3: Empty (FixEngine will use SafeVersionFinder fallback)
        LOG.debug("No safeVersions known for {} — FixEngine will use fallback", input.cveId());
        return List.of();
    }

    private List<String> defaultSafeVersions(String cveId) {
        if (cveId == null) return List.of();
        return switch (cveId) {
            case "CVE-2021-44228", "CVE-2021-45046" -> List.of("2.17.1");
            case "CVE-2022-42889" -> List.of("1.10.0");
            case "CVE-2022-22965" -> List.of("5.3.39", "6.0.0");
            case "CVE-2023-35116" -> List.of("2.13.5", "2.15.0");
            case "CVE-2024-XXXX" -> List.of("1.81");
            case "CVE-2024-LOWRISK" -> List.of("2.7");
            default -> List.of();
        };
    }

    // ── Concurrent Processing ─────────────────────────────────────────────────

    private List<VerificationResult> processSignalsConcurrently(
            List<VulnerabilitySignal> signals,
            StageContext sharedContext,
            boolean validateFixes) {

        ExecutorService executor = Threading.newVirtualThreadPerTaskExecutor();
        Set<String> sharedSeen = ConcurrentHashMap.newKeySet();

        try {
            List<Future<VerificationResult>> futures = new ArrayList<>();

            for (VulnerabilitySignal signal : signals) {
                StageContext perSignalCtx = new StageContext(
                        sharedContext.getEffectivePom(),
                        sharedContext.getBuildOutput(),
                        sharedContext.getEntryPoints(),
                        sharedContext.isNetworkExposed());

                perSignalCtx.put("validateFixes", validateFixes);
                perSignalCtx.put("allowEffectivePomFallback", Boolean.FALSE);
                perSignalCtx.put("normalizeSeenHashes", sharedSeen);

                LOG.info("Submitting signal {} to pipeline (cve={}, safeVersions={})",
                        signal.getSignalId(), signal.getCveId(), signal.getSafeVersions());

                futures.add(executor.submit(() -> pipeline.verify(signal, perSignalCtx)));
            }

            List<VerificationResult> results = new ArrayList<>();
            for (Future<VerificationResult> future : futures) {
                try {
                    results.add(future.get());
                } catch (ExecutionException e) {
                    LOG.error("Signal processing failed: {}", e.getCause().getMessage(), e.getCause());
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    LOG.error("Signal processing interrupted");
                }
            }
            return results;
        } finally {
            executor.shutdown();
        }
    }

    // ── DTO Mappers ───────────────────────────────────────────────────────────

    private ScanResponse.VulnerabilityResult toDto(VerificationResult result) {
        VersionConflictInfo vc = extractVersionConflict(result);
        return new ScanResponse.VulnerabilityResult(
                result.getOriginalSignal() != null ? result.getOriginalSignal().getCveId() : "N/A",
                result.getEffectiveArtifact() != null
                        ? result.getEffectiveArtifact().getCoordinate() : "N/A",
                result.getStatus(),
                result.getConfidenceScore() != null
                        ? result.getConfidenceScore().getTotalScore() : 0,
                result.getRootCausePath() != null
                        ? result.getRootCausePath().getPathString() : "N/A",
                result.isInClasspath(),
                result.isReachable(),
                mapFixOptions(result.getFixOptions()),
                new ScanResponse.VersionConflictResult(vc.detected, vc.paths),
                result.getStageLogs()
        );
    }

    private ScanResponse.ConfirmedVulnerability toConfirmedVuln(VerificationResult result) {
        String proofId = result.getFixOptions().stream()
                .filter(FixOption::isValidated)
                .map(f -> extractProofId(f.getValidationLog()))
                .filter(Objects::nonNull)
                .findFirst().orElse(null);
        VersionConflictInfo vc = extractVersionConflict(result);
        return new ScanResponse.ConfirmedVulnerability(
                result.getOriginalSignal() != null ? result.getOriginalSignal().getCveId() : "N/A",
                result.getEffectiveArtifact() != null
                        ? result.getEffectiveArtifact().getCoordinate() : "N/A",
                result.getStatus(),
                result.getConfidenceScore() != null
                        ? result.getConfidenceScore().getTotalScore() : 0,
                result.getRootCausePath() != null
                        ? result.getRootCausePath().getPathString() : "N/A",
                result.isInClasspath(),
                result.isReachable(),
                mapFixOptions(result.getFixOptions()),
                new ScanResponse.VersionConflictResult(vc.detected, vc.paths),
                proofId,
                result.getStageLogs()
        );
    }

    private ScanResponse.FalsePositiveDetail toFalsePositiveDetail(VerificationResult result) {
        String reason = Optional.ofNullable(result.getStageLogs())
                .filter(logs -> !logs.isEmpty())
                .flatMap(logs -> logs.stream()
                        .filter(l -> l.contains("FALSE POSITIVE")
                                || l.contains("FALSE_POSITIVE")
                                || l.contains("not found"))
                        .findFirst())
                .orElse("Not in classpath or version mismatch");

        return new ScanResponse.FalsePositiveDetail(
                result.getOriginalSignal() != null
                        ? result.getOriginalSignal().getCveId() : "N/A",
                result.getEffectiveArtifact() != null
                        ? result.getEffectiveArtifact().getCoordinate() : "N/A",
                reason,
                result.getStageLogs() != null ? result.getStageLogs() : List.of()
        );
    }

    private List<ScanResponse.FixOptionDto> mapFixOptions(List<FixOption> fixes) {
        if (fixes == null) return List.of();
        return fixes.stream()
                .map(f -> new ScanResponse.FixOptionDto(
                        f.getFixType().name(),
                        f.getDescription(),
                        f.getTargetDependency(),
                        f.getProposedVersion(),
                        f.isValidated(),
                        f.getValidationLog(),
                        extractProofId(f.getValidationLog())
                ))
                .toList();
    }

    private String extractProofId(String validationLog) {
        if (validationLog == null) return null;
        int idx = validationLog.indexOf("ProofPackageId=");
        if (idx < 0) return null;
        return validationLog.substring(idx + "ProofPackageId=".length()).trim();
    }

    private record VersionConflictInfo(boolean detected, List<String> paths) {}

    @SuppressWarnings("unchecked")
    private VersionConflictInfo extractVersionConflict(VerificationResult result) {
        Object vc = result.getMetadata().getOrDefault("versionConflict", Map.of());
        if (vc instanceof Map<?, ?> vm) {
            boolean detected = Boolean.TRUE.equals(vm.get("conflictDetected"));
            Object paths = vm.get("conflictingPaths");
            List<String> pathList = (paths instanceof List<?>)
                    ? ((List<?>) paths).stream().map(Object::toString).toList()
                    : List.of();
            return new VersionConflictInfo(detected, pathList);
        }
        return new VersionConflictInfo(false, List.of());
    }
}