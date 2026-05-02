package com.aevum.core.engine.version;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import javax.xml.parsers.DocumentBuilderFactory;

import org.w3c.dom.Document;
import org.w3c.dom.NodeList;

/**
 * Minimal Maven metadata client that fetches maven-metadata.xml from Maven Central.
 * Caches results in-memory for short TTL using a simple map with timestamps.
 */
public class MavenMetadataClient {
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

    private final ConcurrentMap<String, CacheEntry> cache = new ConcurrentHashMap<>();
    private final long ttlMillis;

    public MavenMetadataClient() {
        this.ttlMillis = Duration.ofHours(12).toMillis();
    }

    // Visible for tests
    public MavenMetadataClient(long ttlMillis) {
        this.ttlMillis = ttlMillis;
    }

    public List<String> fetchAvailableVersions(String groupId, String artifactId) throws IOException {
        String key = groupId + ":" + artifactId;
        CacheEntry cached = cache.get(key);
        long now = System.currentTimeMillis();
        if (cached != null && (now - cached.fetchedAt) < ttlMillis) {
            return List.copyOf(cached.versions);
        }

        try {
            List<String> versions = fetchFromMaven(groupId, artifactId);
            cache.put(key, new CacheEntry(versions, now));
            return versions;
        } catch (IOException e) {
            if (cached != null) return List.copyOf(cached.versions);
            throw e;
        }
    }

    public Optional<String> fetchLatestRelease(String groupId, String artifactId) throws IOException {
        List<String> versions = fetchAvailableVersions(groupId, artifactId);
        if (versions.isEmpty()) return Optional.empty();
        // naive: assume last is latest in metadata order
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

            HttpResponse<InputStream> resp = httpClient.send(request, HttpResponse.BodyHandlers.ofInputStream());
            if (resp.statusCode() != 200) {
                throw new IOException("Failed to fetch metadata: " + resp.statusCode());
            }

            Document doc = DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(resp.body());
            NodeList nodes = doc.getElementsByTagName("version");
            List<String> versions = new ArrayList<>();
            for (int i = 0; i < nodes.getLength(); i++) {
                versions.add(nodes.item(i).getTextContent().trim());
            }
            return versions;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("Interrupted fetching metadata", e);
        } catch (Exception e) {
            throw new IOException("Error parsing maven metadata", e);
        }
    }
}

