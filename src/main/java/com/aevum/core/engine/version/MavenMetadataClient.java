package com.aevum.core.engine.version;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import org.w3c.dom.Document;
import org.w3c.dom.NodeList;

import javax.xml.parsers.DocumentBuilderFactory;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Fetches maven-metadata.xml from Maven Central to enumerate available versions.
 *
 * FIX: Was not a @Component — instantiated via `new` inside FixEngine's manual constructor.
 * Now a proper Spring @Component with singleton lifecycle (cache is shared across requests).
 *
 * Thread-safe: HttpClient is immutable, ConcurrentHashMap for cache.
 */
@Component
public class MavenMetadataClient {
    private static final Logger LOG = LoggerFactory.getLogger(MavenMetadataClient.class);
    private static final String MAVEN_CENTRAL_BASE = "https://repo1.maven.org/maven2/";
    private static final Duration HTTP_TIMEOUT = Duration.ofSeconds(10);

    private final HttpClient httpClient = HttpClient.newBuilder()
            .connectTimeout(HTTP_TIMEOUT)
            .build();

    private static final class CacheEntry {
        final List<String> versions;
        final long fetchedAt;
        CacheEntry(List<String> versions, long fetchedAt) {
            this.versions = versions;
            this.fetchedAt = fetchedAt;
        }
    }

    private final ConcurrentHashMap<String, CacheEntry> cache = new ConcurrentHashMap<>();
    private final long ttlMillis;

    public MavenMetadataClient() {
        this.ttlMillis = Duration.ofHours(12).toMillis();
    }

    // Visible for tests — allows overriding TTL or fetchAvailableVersions
    public MavenMetadataClient(long ttlMillis) {
        this.ttlMillis = ttlMillis;
    }

    public List<String> fetchAvailableVersions(String groupId, String artifactId) throws IOException {
        String key = groupId + ":" + artifactId;
        CacheEntry cached = cache.get(key);
        long now = System.currentTimeMillis();
        if (cached != null && (now - cached.fetchedAt) < ttlMillis) {
            LOG.debug("Cache hit for maven metadata: {}", key);
            return List.copyOf(cached.versions);
        }

        try {
            List<String> versions = fetchFromMaven(groupId, artifactId);
            cache.put(key, new CacheEntry(versions, now));
            LOG.debug("Fetched {} versions for {}", versions.size(), key);
            return versions;
        } catch (IOException e) {
            // Return stale cache if available rather than failing
            if (cached != null) {
                LOG.warn("Maven Central fetch failed for {} — using stale cache: {}", key, e.getMessage());
                return List.copyOf(cached.versions);
            }
            throw e;
        }
    }

    public Optional<String> fetchLatestRelease(String groupId, String artifactId) throws IOException {
        List<String> versions = fetchAvailableVersions(groupId, artifactId);
        if (versions.isEmpty()) return Optional.empty();
        return Optional.of(versions.get(versions.size() - 1));
    }

    private List<String> fetchFromMaven(String groupId, String artifactId) throws IOException {
        try {
            String path = groupId.replace('.', '/') + "/" + artifactId + "/maven-metadata.xml";
            URI uri = URI.create(MAVEN_CENTRAL_BASE + path);
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(uri)
                    .timeout(HTTP_TIMEOUT)
                    .GET()
                    .build();

            HttpResponse<InputStream> resp = httpClient.send(request,
                    HttpResponse.BodyHandlers.ofInputStream());
            if (resp.statusCode() != 200) {
                throw new IOException("Maven metadata fetch returned HTTP " + resp.statusCode()
                        + " for " + groupId + ":" + artifactId);
            }

            Document doc = DocumentBuilderFactory.newInstance()
                    .newDocumentBuilder()
                    .parse(resp.body());
            NodeList nodes = doc.getElementsByTagName("version");
            List<String> versions = new ArrayList<>();
            for (int i = 0; i < nodes.getLength(); i++) {
                String v = nodes.item(i).getTextContent().trim();
                if (!v.isEmpty()) versions.add(v);
            }
            return versions;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("Interrupted while fetching Maven metadata", e);
        } catch (IOException e) {
            throw e;
        } catch (Exception e) {
            throw new IOException("Error parsing Maven metadata for "
                    + groupId + ":" + artifactId, e);
        }
    }
}