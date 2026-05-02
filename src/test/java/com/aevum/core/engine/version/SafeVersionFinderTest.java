package com.aevum.core.engine.version;

import org.junit.jupiter.api.Test;
import java.io.IOException;
import java.util.List;
import static org.assertj.core.api.Assertions.assertThat;

class SafeVersionFinderTest {

    @Test
    void findMinimumSafePicksFirstNonVulnerable() throws IOException {
        // Create a metadata client that returns a synthetic list
        MavenMetadataClient client = new MavenMetadataClient(60_000) {
            @Override
            public List<String> fetchAvailableVersions(String groupId, String artifactId) {
                return List.of("1.0.0", "1.2.0", "1.5.0", "1.81", "1.82");
            }
        };

        SafeVersionFinder finder = new SafeVersionFinder(client);
        SafeVersionFinder.SafeVersionResult res = finder.findMinimumSafe("org.example", "lib", "1.0", "[1.0,1.81)");
        assertThat(res.vulnerable).isTrue();
        assertThat(res.minimumSafeVersion).isEqualTo("1.81");
    }
}

