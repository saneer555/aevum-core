package com.aevum.core.engine.version;

import org.junit.jupiter.api.Test;
import static org.assertj.core.api.Assertions.assertThat;

public class VersionParserTest {

    @Test
    void parseSemverAndCompare() {
        VersionParser.Version v1 = VersionParser.parse("1.2.3");
        VersionParser.Version v2 = VersionParser.parse("1.2.4");
        VersionParser.Version v3 = VersionParser.parse("1.2.3-RC1");

        assertThat(v1.major).isEqualTo(1);
        assertThat(v1.minor).isEqualTo(2);
        assertThat(v1.patch).isEqualTo(3);

        assertThat(v1.compareTo(v2)).isLessThan(0);
        assertThat(v2.compareTo(v1)).isGreaterThan(0);
        // pre-release sorts before release
        assertThat(v3.compareTo(v1)).isLessThan(0);
    }
}

