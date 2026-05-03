# Task: Fix request/response payloads to match expected, debug mismatches

## Current Status
- [x] Analyzed POSTMAN_GUIDE, request04.json, corrupted resp04.json
- [ ] Create expected_resp04.json
- [ ] Regenerate clean resp04.json (run server + POST)
- [ ] Read pipeline source files (VerificationService, Stages)
- [ ] Fix RuntimeReachabilityStage (make Log4Shell/Text4Shell reachable=true)
- [ ] Fix ClasspathPresenceStage (Netty NOT_FOUND)
- [ ] Fix EffectiveVersionStage (BOM-MISMATCH S2 range fail, conf=0)
- [ ] Add fixOptions generation
- [ ] Adjust confidence scores
- [ ] Test API, verify matches expected
- [ ] Handle other requests (03,05,06) if needed

## Next Step
Create expected_resp04.json for diff reference.
