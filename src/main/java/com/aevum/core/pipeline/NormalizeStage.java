package com.aevum.core.pipeline;

import com.aevum.core.domain.model.VulnerabilitySignal;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Stage 1: Normalize input and deduplicate via SHA-256.
 *
 * Deduplication logic: two signals are duplicates if they refer to the SAME
 * vulnerability in the SAME artifact at the SAME version — regardless of which
 * scanner reported it.  A Snyk alert and a Trivy alert for the same CVE are
 * duplicates; they should not be processed twice.
 *
 * The hash is computed from: cveId|groupId|artifactId|reportedVersion
 * scannerSource is EXCLUDED — different scanners reporting the same vuln = duplicate.
 *
 * State is per-scan (via StageContext) and thread-safe (ConcurrentHashMap.newKeySet).
 */
@Component
public class NormalizeStage implements Stage {
    private static final Logger LOG = LoggerFactory.getLogger(NormalizeStage.class);

    private static final String SEEN_HASHES_KEY = "normalizeSeenHashes";

    @Override
    public String getName() { return "STAGE_01_NORMALIZE"; }

    @Override
    public StageResult execute(VulnerabilitySignal signal, StageContext context) {
        @SuppressWarnings("unchecked")
        Set<String> seenHashes = context.<Set<String>>get(SEEN_HASHES_KEY)
                .orElseGet(() -> {
                    Set<String> fresh = ConcurrentHashMap.newKeySet();
                    context.put(SEEN_HASHES_KEY, fresh);
                    return fresh;
                });

        String hash = computeSha256(signal);

        // Atomic add: returns false if hash already present (duplicate)
        if (!seenHashes.add(hash)) {
            LOG.debug("Duplicate signal eliminated: {} (hash={})", signal.getSignalId(), hash);
            return StageResult.fail(0,
                    "FALSE POSITIVE: Duplicate signal eliminated via SHA-256: " + hash,
                    Map.of("sha256", hash, "duplicate", true));
        }

        LOG.debug("Signal normalized. SHA-256: {}", hash);
        return StageResult.pass(100,
                "Signal normalized and deduplicated",
                Map.of("sha256", hash, "duplicate", false));
    }

    /**
     * Compute deduplication hash.
     *
     * scannerSource is EXCLUDED so that the same CVE reported by different
     * scanners (Snyk, Trivy, Black Duck) is treated as a single signal.
     */
    private String computeSha256(VulnerabilitySignal signal) {
        String payload = signal.getCveId() + "|" +
                signal.getGroupId() + "|" +
                signal.getArtifactId() + "|" +
                signal.getReportedVersion();
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(payload.getBytes(StandardCharsets.UTF_8));
            return bytesToHex(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 not available", e);
        }
    }

    private String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}