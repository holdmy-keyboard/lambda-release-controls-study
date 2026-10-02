# Lambda release-control study

Research prototype for **From Signed Build to Approved Deployment: Comparing Provenance Verification and Enforced Code Signing for AWS Lambda Releases**.

This repository contains a harmless fixed-marker Python application, controlled release workflows, provenance/signing adapters and scoped Terraform configuration. It is being prepared under the researcher's G4 approval of 2 October 2026. Setup and live validation are in progress; **no experimental results have been collected or published**. Final data collection requires a separate G5 decision.

The four treatments are baseline (C0), provenance gate (C1), enforced Lambda code signing (C2), and both controls (C3). The committed runner configuration is disabled. The identity-only setup path prints a small allowlist of nonsecret OIDC claims and does not assume any AWS role.

Local checks:

```sh
python3 -m unittest discover -s tests
```

The tests use synthetic data. They do not prove actual cryptographic verification, IAM compatibility, cloud behavior or experimental outcomes. Some generic verifier failures remain operational errors rather than being credited as attack detections.

Credentials, private account bindings, raw evidence, Terraform state and local helper authentication files must not be committed. The operator must configure a dedicated sandbox, immutable approved identities, versioned inputs, resource/budget counters and independent readiness checks before enabling the runtime. The code is an unfinished research prototype, not a production release system.

Companion fixture source: [lambda-release-controls-fixtures](https://github.com/holdmy-keyboard/lambda-release-controls-fixtures).
