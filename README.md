# AEVUM CORE v1.0

## Deterministic Vulnerability Verification & Remediation Engine

### Core Principle
> "Do not fix unless the vulnerability is proven real.
>  Do not add anything unless it is required.
>  Always fix at the root cause, not symptom."

### Architecture
- **Java 21** with Virtual Threads (50K concurrent verifications)
- **Spring Boot 3.x** - Microservice architecture
- **GraalVM Native Image** compatible
- **Domain-Driven Design** - Immutable models, no anemic domain

### 6-Stage Verification Pipeline

| Stage | Name | Purpose | Eliminates |
|-------|------|---------|------------|
| S1 | Normalize | Deduplicate via SHA-256 | Duplicate alerts |
| S2 | Effective Version | BOM resolution | ~85% false positives |
| S3 | Classpath Presence | Runtime check | Test-only deps |
| S4 | Reachability | Static call graph | Unused code paths |
| S5 | Exploitability | EPSS + KEV + exposure | Low-risk issues |
| S6 | Confidence | Final 0-100 score | Ambiguous cases |

### Maven BOM Resolution Rules
1. Direct dependency overrides BOM
2. Nearest definition wins
3. First declaration wins
4. Explicit version overrides managed version

### Running

```bash
# Build
./mvnw clean package

# Run with CLI profile (demo scan)
java -jar target/aevum-core-1.0.0.jar --spring.profiles.active=cli

# Run as REST API
java -jar target/aevum-core-1.0.0.jar

# Native image
./mvnw native:compile
```

### API
```bash
curl -X POST http://localhost:8080/api/v1/verify   -H "Content-Type: application/json"   -d '{
    "projectId": "my-app",
    "signals": [{
      "scannerSource": "snyk",
      "cveId": "CVE-2021-44228",
      "groupId": "org.apache.logging.log4j",
      "artifactId": "log4j-core",
      "version": "2.14.1",
      "severity": "critical",
      "cvssScore": 10.0
    }]
  }'
```

### Project Structure
```
com.aevum.core
├── domain
│   ├── enums (Scope, VerificationStatus, FixType)
│   └── model (Artifact, DependencyNode, BomDeclaration, EffectivePom,
│              VulnerabilitySignal, VerificationResult, ConfidenceScore,
│              RootCausePath, FixOption, ProofPackage)
├── engine
│   ├── BomResolver (Maven mediation rules)
│   ├── ClasspathVerifier (runtime presence)
│   ├── ReachabilityAnalyzer (static call graph)
│   ├── ExploitabilityAssessor (EPSS + KEV)
│   └── FixEngine (root-cause fixes)
├── pipeline
│   ├── Stage (interface)
│   ├── StageContext
│   ├── NormalizeStage
│   ├── EffectiveVersionStage
│   ├── ClasspathPresenceStage
│   ├── RuntimeReachabilityStage
│   ├── ExploitabilityStage
│   ├── ConfidenceScorerStage
│   └── VerificationPipeline (orchestrator)
├── cache
│   └── BomCache (Caffeine L1)
├── service
│   └── VerificationService (50K concurrent)
├── cli
│   ├── VerificationController (REST)
│   └── CliRunner (standalone)
├── config
│   └── AppConfig (virtual threads)
└── dto
    ├── ScanRequest
    └── ScanResponse
```
