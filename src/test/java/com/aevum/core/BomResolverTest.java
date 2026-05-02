package com.aevum.core;

import com.aevum.core.domain.enums.Scope;
import com.aevum.core.domain.model.*;
import com.aevum.core.engine.BomResolver;
import org.junit.jupiter.api.Test;

import java.util.*;

import static org.assertj.core.api.Assertions.assertThat;

class BomResolverTest {

    private final BomResolver resolver = new BomResolver();

    @Test
    void directDependencyOverridesBom() {
        Artifact direct = new Artifact("org.example", "lib", "2.0.0", Scope.COMPILE);
        Artifact bomManaged = new Artifact("org.example", "lib", "1.5.0", Scope.COMPILE);

        BomDeclaration bom = new BomDeclaration(
            new Artifact("org.example", "bom", "1.0.0", Scope.IMPORT),
            Map.of("org.example:lib", "1.5.0")
        );

        EffectivePom pom = new EffectivePom(
            "test",
            List.of(direct),
            List.of(bom),
            Map.of(),
            Map.of("org.example:lib", direct),
            List.of(DependencyNode.root(direct))
        );

        var result = resolver.resolveEffectiveVersion("org.example", "lib", pom);

        assertThat(result.isFound()).isTrue();
        assertThat(result.resolvedArtifact().getVersion()).isEqualTo("2.0.0");
        assertThat(result.mediationRule()).isEqualTo("DIRECT_DEPENDENCY_OVERRIDES_BOM");
    }

    @Test
    void bomManagedVersionUsedWhenNoDirect() {
        BomDeclaration bom = new BomDeclaration(
            new Artifact("org.springframework.boot", "spring-boot-dependencies", "3.2.0", Scope.IMPORT),
            Map.of("org.apache.logging.log4j:log4j-core", "2.21.1")
        );

        EffectivePom pom = new EffectivePom(
            "test",
            List.of(),
            List.of(bom),
            Map.of(),
            Map.of(),
            List.of()
        );

        var result = resolver.resolveEffectiveVersion("org.apache.logging.log4j", "log4j-core", pom);

        assertThat(result.isFound()).isTrue();
        assertThat(result.resolvedArtifact().getVersion()).isEqualTo("2.21.1");
        assertThat(result.mediationRule()).isEqualTo("MANAGED_VERSION_FROM_BOM");
    }

    @Test
    void nearestDefinitionWins() {
        Artifact root = new Artifact("com.app", "app", "1.0.0", Scope.COMPILE);
        Artifact springCloud = new Artifact("org.springframework.cloud", "spring-cloud-vault", "4.0.0", Scope.COMPILE);
        Artifact bcprov = new Artifact("org.bouncycastle", "bcprov-jdk18on", "1.80", Scope.COMPILE);

        DependencyNode cloudNode = DependencyNode.child(springCloud, DependencyNode.root(root), false);
        DependencyNode bcNode = DependencyNode.child(bcprov, cloudNode, false);
        DependencyNode tree = DependencyNode.root(root).withChildren(List.of(cloudNode.withChildren(List.of(bcNode))));

        EffectivePom pom = new EffectivePom(
            "test",
            List.of(root),
            List.of(),
            Map.of(),
            Map.of("org.bouncycastle:bcprov-jdk18on", bcprov),
            List.of(tree)
        );

        var result = resolver.resolveEffectiveVersion("org.bouncycastle", "bcprov-jdk18on", pom);

        assertThat(result.isFound()).isTrue();
        assertThat(result.resolvedArtifact().getVersion()).isEqualTo("1.80");
        assertThat(result.mediationRule()).isEqualTo("NEAREST_DEFINITION_WINS");
        assertThat(result.depth()).isEqualTo(2);
    }

    @Test
    void notFoundReturnsEmpty() {
        EffectivePom pom = new EffectivePom(
            "test", List.of(), List.of(), Map.of(), Map.of(), List.of()
        );

        var result = resolver.resolveEffectiveVersion("com.unknown", "lib", pom);

        assertThat(result.isFound()).isFalse();
        assertThat(result.mediationRule()).isEqualTo("NOT_FOUND");
    }
}
