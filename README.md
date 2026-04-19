# crypto-lab-pq-rotation

Browser-based PQC migration planner for operational teams.

## What It Is

`crypto-lab-pq-rotation` is a browser-based interactive planner for post-quantum cryptography migration, focused on real deployment operations rather than algorithm theory. It models the end-to-end transition from cryptographic inventory through hybrid deployment to pure PQC in a five-phase program.

The demo includes:

- Hybrid X.509-style certificates with classical + PQ signatures (ECDSA-P256 + ML-DSA-65) and byte-size analysis.
- A timeline engine that aligns migration actions with major regulatory frameworks (CNSA 2.0, EU NIS, UK NCSC, Australia ASD, Germany BSI, Canada CCCS).
- A rolling key rotation simulator with canary deployment, monitoring windows, staged rollout, and automatic rollback.
- A dashboard interface that visualizes inventory risk, phase progress, and operational readiness.

It uses real cryptographic primitives:

- ECDSA-P256 from `@noble/curves`
- ML-DSA-65 from `@noble/post-quantum`

This makes the size and operational tradeoffs visible, including the substantial certificate size increase for hybrid deployments.

## When to Use It

Use this project when you need to:

- Plan an organization-wide PQC migration roadmap with concrete phases and dependencies.
- Explain why hybrid deployment is the practical transition model before pure PQC.
- Teach operational realities: root CA rotation, HSM/KMS readiness, rollback planning, and monitoring coverage.
- Compare regulatory timelines across jurisdictions.
- Prototype crypto-agile architecture decisions for new systems.

Do not use this as a production PKI or key-management platform. It is an educational planning tool, not a CA product.

## Live Demo

https://systemslibrarian.github.io/crypto-lab-pq-rotation/

## What Can Go Wrong

- **Timeline optimism.** Most enterprise migrations require multi-year sequencing. Delayed starts compress risk into hard regulatory deadlines.
- **Skipping crypto-agility.** Without abstraction layers and policy-driven crypto selection, migration costs explode and rollback is unsafe.
- **Partial inventory.** Teams often miss firmware signing, CA hierarchy elements, or application signing paths and discover blockers late.
- **Root CA drag.** Root trust anchors are long-lived and distributed across many trust stores; rotating them is a slow, high-coordination process.
- **Vendor asymmetry.** Some suppliers have clear PQ roadmaps; others do not. Migration is only as fast as the slowest dependency.
- **Capacity and size effects.** Hybrid and PQ artifacts are larger, affecting TLS handshake behavior, CT logging, and constrained network paths.
- **Weak observability.** If you cannot measure algorithm usage by traffic and endpoint class, governance reporting is unreliable.

## Real-World Usage

The migration framework represented here aligns with published guidance from:

- NSA CNSA 2.0 (September 2022 release, December 2024 update)
- NIST NCCoE Migration to PQC project materials
- EU NIS Cooperation Group PQC roadmap (June 2025)
- UK NCSC post-quantum migration guidance (2025)
- Germany BSI transition guidance (October 2024)
- Australia ASD Information Security Manual
- Canada CCCS PQC roadmap (June 2025)
- ETSI CYBER quantum-safe guidance

Hybrid certificate modeling follows the composite-signature transition direction described in IETF LAMPS work (including draft-ietf-lamps-pq-composite-sigs).

The implementation reflects real migration patterns used by large enterprises and public-sector organizations: inventory first, hybrid rollout, monitored phased rotation, rollback-safe operations, and eventual classical retirement under compliance timelines.