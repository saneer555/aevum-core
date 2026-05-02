package com.aevum.core.pipeline;

import com.aevum.core.domain.model.VulnerabilitySignal;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Stage 1: Normalize input and deduplicate via SHA-256.
 *
 * FIX 1: The original used a LinkedHashMap-backed Set as instance-level state.
 *   - LinkedHashMap is NOT thread-safe (concurrent scans would corrupt it).
 *   - Instance-level state means duplicates from Scan A bleed into Scan B (wrong dedup across unrelated scans).
 *
 * FIX 2: Deduplication state is now stored PER SCAN in StageContext (keyed by "normalizeSeenHashes").
 *   - Each scan has its own dedup set, isolated from other concurrent scans.
 *   - The set itself is a ConcurrentHashMap.newKeySet() for thread safety within a scan.
 *
 * FIX 3: clearCache() was the only way to reset state before — now unnecessary since state is per-context.
 */
@Component
public class NormalizeStage implements Stage {
    private static final Logger LOG = LoggerFactory.getLogger(NormalizeStage.class);

    private static final String SEEN_HASHES_KEY = "normalizeSeenHashes";

    @Override
    public String getName() { return "STAGE_01_NORMALIZE"; }

    @Override
    public StageResult execute(VulnerabilitySignal signal, StageContext context) {
        // Get or create the per-scan dedup set stored in context
        @SuppressWarnings("unchecked")
        Set<String> seenHashes = context.<Set<String>>get(SEEN_HASHES_KEY)
                .orElseGet(() -> {
                    Set<String> fresh = ConcurrentHashMap.newKeySet();
                    context.put(SEEN_HASHES_KEY, fresh);
                    return fresh;
                });

        String hash = computeSha256(signal);

        // add() returns false if already present — atomic on ConcurrentHashMap.KeySetView
        if (!seenHashes.add(hash)) {
            LOG.debug("Duplicate signal detected and eliminated: {} (hash={})", signal.getSignalId(), hash);
            return StageResult.fail(0,
                    "Duplicate signal eliminated via SHA-256: " + hash,
                    Map.of("sha256", hash, "duplicate", true));
        }

        LOG.debug("Signal normalized. SHA-256: {}", hash);
        return StageResult.pass(100,
                "Signal normalized and deduplicated",
                Map.of("sha256", hash, "duplicate", false));
    }

    private String computeSha256(VulnerabilitySignal signal) {
        String payload = signal.getScannerSource() + "|" +
                signal.getCveId() + "|" +
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