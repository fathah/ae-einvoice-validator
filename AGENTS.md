# Ziqx UAE e-invoice validator

This repository is a standalone, stateless HTTP service. Keep its builds, credentials and deployment independent of Tanseek or other client products.

Do not change frozen official resource bytes or historical hashes in place. Add a new specification directory and deliberate API/client compatibility changes for a specification update. Preserve original notices.

Validation must remain offline, authenticated, bounded and fail closed. Never log invoice XML, customer values, bearer tokens or detailed parser errors. A valid report requires the schema and both official Billing rule sets to complete.

Run `python3 -B tests/test_package.py`, `python3 -B .github/scripts/test_security_scan.py`, the actual Docker-backed `python3 test.py`, and `python3 test_compose.py` after changing runtime behavior. Keep the high/critical image gate before registry login or publication. API contract changes require tests against the running service.

No customer billing, public registration, production rollout or paid-service claims are authorized by this source extraction. Future commercial features should use a separate API gateway for per-customer keys, quotas and metering.
