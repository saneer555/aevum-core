package com.aevum.core.cli;

import com.aevum.core.dto.ScanRequest;
import com.aevum.core.dto.ScanResponse;
import com.aevum.core.service.VerificationService;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

import java.util.List;

/**
 * CLI runner for local testing and standalone execution.
 * Usage: java -jar aevum-core.jar --scan --file=signals.json
 */
@Component
@Profile("cli")
public class CliRunner implements CommandLineRunner {
    private final VerificationService verificationService;
    private final ObjectMapper mapper;

    public CliRunner(VerificationService verificationService) {
        this.verificationService = verificationService;
        this.mapper = new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT);
    }

    @Override
    public void run(String... args) throws Exception {
        System.out.println("╔══════════════════════════════════════════════════════════════╗");
        System.out.println("║  AEVUM CORE - Deterministic Vulnerability Engine v1.0       ║");
        System.out.println("║  Do not fix unless proven real. Do not add unless required.  ║");
        System.out.println("╚══════════════════════════════════════════════════════════════╝");
        System.out.println();

        // Demo scan with real CVE scenarios
        ScanRequest request = createDemoRequest();
        ScanResponse response = verificationService.verify(request);

        System.out.println(mapper.writeValueAsString(response));
        System.out.println();
        printSummary(response);
    }

    private ScanRequest createDemoRequest() {
        return new ScanRequest(
                "demo-project",
                null,
                "target",
                List.of("com.example.Application"),
                true,
                List.of(
                        // CONFIRMED: Log4Shell
                        new ScanRequest.VulnerabilityInput(
                                null,                           // signalId (auto-generated)
                                "snyk",
                                "CVE-2021-44228",
                                "org.apache.logging.log4j",
                                "log4j-core",
                                "2.14.1",
                                null,
                                List.of(),
                                "critical",
                                10.0,
                                "Log4Shell RCE vulnerability"
                        ),
                        // FALSE POSITIVE: Tomcat BOM mismatch
                        new ScanRequest.VulnerabilityInput(
                                null,
                                "snyk",
                                "CVE-2023-XXXX",
                                "org.apache.tomcat.embed",
                                "tomcat-embed-core",
                                "9.0.50",
                                null,
                                List.of(),
                                "high",
                                7.5,
                                "Tomcat vulnerability"
                        ),
                        // CONFIRMED: Bouncy Castle
                        new ScanRequest.VulnerabilityInput(
                                null,
                                "trivy",
                                "CVE-2024-XXXX",
                                "org.bouncycastle",
                                "bcprov-jdk18on",
                                "1.80",
                                null,
                                List.of(),
                                "high",
                                8.2,
                                "Bouncy Castle cryptographic vulnerability"
                        ),
                        // FALSE POSITIVE: Mockito test scope
                        new ScanRequest.VulnerabilityInput(
                                null,
                                "blackduck",
                                "CVE-2023-YYYY",
                                "org.mockito",
                                "mockito-core",
                                "4.0.0",
                                null,
                                List.of(),
                                "medium",
                                5.3,
                                "Mockito test dependency - not in production classpath"
                        )
                )
        );
    }

    private void printSummary(ScanResponse response) {
        ScanResponse.ScanMetrics m = response.metrics();
        System.out.println("═══ VERIFICATION SUMMARY ═══");
        System.out.printf("Total Signals:      %d%n", m.totalSignals());
        System.out.printf("CONFIRMED:          %d%n", m.confirmedCount());
        System.out.printf("FALSE POSITIVES:    %d%n", m.falsePositiveCount());
        System.out.printf("INCONCLUSIVE:       %d%n", m.inconclusiveCount());
        System.out.printf("False Positive Rate: %.1f%%%n", m.falsePositiveRate());
        System.out.printf("Duration:           %dms%n", m.durationMs());
        System.out.println();

        if (!response.confirmed().isEmpty()) {
            System.out.println("═══ CONFIRMED VULNERABILITIES ═══");
            for (ScanResponse.VulnerabilityResult v : response.confirmed()) {
                System.out.printf("  • %s (%s) - Confidence: %d%%%n", v.cveId(), v.coordinate(), v.confidenceScore());
                System.out.printf("    Root Cause: %s%n", v.rootCausePath());
                if (!v.fixOptions().isEmpty()) {
                    System.out.printf("    Fix: %s%n", v.fixOptions().get(0).description());
                }
            }
        }

        if (!response.falsePositives().isEmpty()) {
            System.out.println();
            System.out.println("═══ FALSE POSITIVES ELIMINATED ═══");
            for (ScanResponse.VulnerabilityResult v : response.falsePositives()) {
                System.out.printf("  ✗ %s (%s) - Confidence: %d%%%n", v.cveId(), v.coordinate(), v.confidenceScore());
                if (!v.stageLogs().isEmpty()) {
                    System.out.printf("    Reason: %s%n", v.stageLogs().get(v.stageLogs().size() - 1));
                }
            }
        }
    }
}
