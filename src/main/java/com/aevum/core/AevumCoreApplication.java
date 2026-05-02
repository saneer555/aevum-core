package com.aevum.core;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * AEVUM Core - Deterministic Vulnerability Verification & Remediation Engine.
 *
 * Core Principle:
 * "Do not fix unless the vulnerability is proven real.
 *  Do not add anything unless it is required.
 *  Always fix at the root cause, not symptom."
 */
@SpringBootApplication
public class AevumCoreApplication {
    public static void main(String[] args) {
        SpringApplication.run(AevumCoreApplication.class, args);
    }
}
