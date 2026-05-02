package com.aevum.core.cli;

import com.aevum.core.dto.ScanRequest;
import com.aevum.core.dto.ScanResponse;
import com.aevum.core.service.VerificationService;
import jakarta.validation.Valid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

/**
 * REST API for vulnerability verification.
 */
@RestController
@RequestMapping("/api/v1/verify")
@CrossOrigin(origins = "*")
public class VerificationController {
    private static final Logger LOG = LoggerFactory.getLogger(VerificationController.class);
    private final VerificationService verificationService;

    public VerificationController(VerificationService verificationService) {
        this.verificationService = verificationService;
    }

    @PostMapping
    public ResponseEntity<ScanResponse> verify(@Valid @RequestBody ScanRequest request,
                                               @RequestParam(defaultValue = "true") boolean validateFixes) {
        LOG.info("Received verification request for project: {} (validateFixes={})", request.projectId(), validateFixes);
        ScanResponse response = verificationService.verify(request, validateFixes);
        return ResponseEntity.ok(response);
    }

    @GetMapping("/health")
    public ResponseEntity<String> health() {
        return ResponseEntity.ok("AEVUM CORE - Deterministic Vulnerability Engine - OK");
    }
}
