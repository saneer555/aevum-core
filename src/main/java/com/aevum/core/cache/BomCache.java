package com.aevum.core.cache;

import com.aevum.core.domain.model.Artifact;
import com.aevum.core.domain.model.EffectivePom;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.benmanes.caffeine.cache.Cache;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.util.Optional;

/**
 * L1 In-Memory Cache for BOM resolution results.
 * Cache key = SHA-256 of pom.xml content.
 */
@Component
public class BomCache {
    private static final Logger LOG = LoggerFactory.getLogger(BomCache.class);

    private final Cache<String, EffectivePom> l1Cache;

    public BomCache() {
        this.l1Cache = Caffeine.newBuilder()
            .maximumSize(1000)
            .expireAfterWrite(Duration.ofHours(24))
            .recordStats()
            .build();
    }

    public Optional<EffectivePom> get(String pomContent) {
        String key = sha256(pomContent);
        EffectivePom cached = l1Cache.getIfPresent(key);
        if (cached != null) {
            LOG.debug("L1 cache HIT for key: {}", key.substring(0, 16));
        }
        return Optional.ofNullable(cached);
    }

    public void put(String pomContent, EffectivePom effectivePom) {
        String key = sha256(pomContent);
        l1Cache.put(key, effectivePom);
        LOG.debug("L1 cache PUT for key: {}", key.substring(0, 16));
    }

    public void invalidate(String pomContent) {
        l1Cache.invalidate(sha256(pomContent));
    }

    public void invalidateAll() {
        l1Cache.invalidateAll();
    }

    public com.github.benmanes.caffeine.cache.stats.CacheStats stats() {
        return l1Cache.stats();
    }

    private String sha256(String input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(input.getBytes());
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
