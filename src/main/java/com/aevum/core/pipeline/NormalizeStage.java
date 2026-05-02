package com.aevum.core.pipeline;

import com.aevum.core.domain.model.VulnerabilitySignal;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;

/**
 * Stage 1: Normalize input and deduplicate via SHA-256.
 */
@Component
public class NormalizeStage implements Stage {
    private static final Logger LOG = LoggerFactory.getLogger(NormalizeStage.class);
    private final Set<String> seenHashes = Collections.newSetFromMap(new LinkedHashMap<>());

    @Override
    public String getName() { return "STAGE_01_NORMALIZE"; }

    @Override
    public StageResult execute(VulnerabilitySignal signal, StageContext context) {
        String hash = computeSha256(signal);

        if (seenHashes.contains(hash)) {
            LOG.debug("Duplicate signal detected and eliminated: {}", signal.getSignalId());
            return StageResult.fail(0, "Duplicate signal eliminated via SHA-256: " + hash,
                Map.of("sha256", hash, "duplicate", true));
        }

        seenHashes.add(hash);
        LOG.debug("Signal normalized. SHA-256: {}", hash);
        return StageResult.pass(100, "Signal normalized and deduplicated",
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

    public void clearCache() {
        seenHashes.clear();
    }
}
