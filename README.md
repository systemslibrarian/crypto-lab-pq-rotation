# crypto-lab-pq-rotation

## What It Is

`crypto-lab-pq-rotation` is a browser-based interactive planner for post-quantum cryptography migration, focused on real deployment operations rather than algorithm theory. It models the end-to-end transition from cryptographic inventory through hybrid deployment to pure PQC in a five-phase program.

A **"Start here" stepper** at the top gives the newcomer a single causal spine — urgency justifies the hybrid fix, the fix has a size cost, deadlines sequence the work, and staged rotation ships it — and each of the four steps links to its section. Jargon (HNDL, composite signatures, canary) is glossed in one plain sentence on first use, in the same style as the Mosca card.

The demo includes:

- An interactive **Mosca's-inequality** model (X + Y > Z) with adjustable CRQC year and migration time, pairing the generic formula with a live worst-case worked example pulled from the loaded inventory, so you can see exactly when "harvest now, decrypt later" (HNDL) already puts your data past the line.
- Composite-style hybrid certificate models with classical + PQ signatures (ECDSA-P256 + ML-DSA-65) and **mandatory AND verification**. The signed body is JSON; the X.509 envelope size is modeled, while key and signature sizes are measured. This does not implement DER X.509 certificates, the IETF composite-signature wire format, or ITU-T Catalyst/MCA alternative-signature extensions. To-scale stacked bars show the envelope, public keys, and signatures.
- A **tamper lab** on the real certificate: forge the classical signature, the PQ signature, or the body and watch verification react live. A **certificate-structure diagram** (Body → SHA-256 hash → {classical sig, PQ sig} → overall trust) turns the affected block red and shows the actual flipped hex byte before/after — demonstrating why a hybrid verifier trusts a certificate only when *both* signatures hold.
- A timeline engine that aligns migration actions with major scoped policy/guidance/planning profiles (CNSA 2.0, EU NIS, UK NCSC, Australia ASD, Germany BSI, Canada CCCS). Each phase bar is a **self-explaining count** (how many inventory items are due by today) with one concrete example action and its planned date; the Doom Meter numbers are traced back to separately labeled guidance or model-choice planning dates.
- A rolling key rotation simulator with canary deployment, monitoring windows, staged rollout, and automatic rollback, visualized as a **fleet dot grid** that recolours classical → hybrid as stages roll out, highlights the single canary, and reverts to classical on an injected-failure rollback.
- An **in-browser verification suite** that runs the lab's own cryptographic self-tests so you can confirm none of the results are faked.
- An **"About this demo"** fold at the bottom with a greenfield PQ-aware architecture example, accessibility notes, and links to companion labs.

It uses real cryptographic primitives:

- ECDSA-P256 from `@noble/curves`
- ML-DSA-65 from `@noble/post-quantum`

Every byte size shown is measured from keys and signatures generated live in the browser. A classical ECDSA-P256 leaf certificate is ~1.2 KB; the hybrid equivalent is ~6.5 KB (≈5.4× larger), and the cryptographic material alone — public key plus signature — grows roughly 55× once ML-DSA-65's 1,952-byte key and 3,309-byte signature are added. This makes the size and operational tradeoffs of hybrid deployment concrete rather than asserted.

## When to Use It

Use this project when you need to:

- Plan an organization-wide PQC migration roadmap with concrete phases and dependencies.
- Explain why hybrid deployment is the practical transition model before pure PQC.
- Teach operational realities: root CA rotation, HSM/KMS readiness, rollback planning, and monitoring coverage.
- Compare guidance and planning timelines across jurisdictions.
- Prototype crypto-agile architecture decisions for new systems.
- Do NOT use this as a production PKI or key-management platform — it is an educational planning tool, not a CA product.

## Live Demo

**[systemslibrarian.github.io/crypto-lab-pq-rotation](https://systemslibrarian.github.io/crypto-lab-pq-rotation/)**

The planner walks a five-phase PQC migration program end to end: an interactive Mosca's-inequality model, a live hybrid X.509 certificate (ECDSA-P256 + ML-DSA-65) with a tamper lab that forges the classical signature, the PQ signature, or the body, a scoped guidance/planning timeline engine spanning CNSA 2.0 and other jurisdictions, a rolling key-rotation simulator with canary rollout and automatic rollback, an in-browser cryptographic self-test suite, and an inventory/readiness dashboard. Every byte size shown is measured from keys and signatures generated live in the browser.

## What Can Go Wrong

- **Compatibility downgrade.** Adding an alternative PQ signature does not protect a client that still accepts a traditional-only replacement after a classical CA key is compromised. [Strenzke, ePrint 2026/2297 (approved October 4, 2026)](https://eprint.iacr.org/2026/2297) analyzes ITU-T Catalyst/MCA extensions and demonstrates this behavior in wolfSSL. This is an attack-model-conditional preprint, not a break of this lab's AND verifier. Relying-party policy must require the intended PQ protection throughout the accepted path; ordinary RFC 5280 validation remains necessary.
- **Timeline optimism.** Most enterprise migrations require multi-year sequencing. Delayed starts compress risk into profile-specific planning targets.
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

## How to Run Locally

```bash
git clone https://github.com/systemslibrarian/crypto-lab-pq-rotation
cd crypto-lab-pq-rotation
npm install
npm run dev
```

## Related Demos
- [crypto-lab-harvest-timeline](https://systemslibrarian.github.io/crypto-lab-harvest-timeline/) — the Mosca inequality and cost-of-delay scenarios that justify migrating now.
- [crypto-lab-hybrid-sign](https://systemslibrarian.github.io/crypto-lab-hybrid-sign/) — Ed25519 + ML-DSA-65 composite signatures, the IETF LAMPS construction this planner deploys.
- [crypto-lab-pki-chain](https://systemslibrarian.github.io/crypto-lab-pki-chain/) — X.509 certificate chains and the trust hierarchy being rotated.
- [crypto-lab-pq-families](https://systemslibrarian.github.io/crypto-lab-pq-families/) — the five PQC families and the size tradeoffs that drive migration choices.
- [crypto-lab-pq-tls-handshake](https://systemslibrarian.github.io/crypto-lab-pq-tls-handshake/) — hybrid X25519MLKEM768 key exchange, the TLS side of the same migration.

---

*Part of the [Crypto Lab](https://crypto-lab.systemslibrarian.dev/) suite.*

*"So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31*

## Milestone provenance (12 October 2026)

The visible planner separates published source milestones from its derived phase dates and adjustable assumptions. [ASD guidance, reviewed 22 September 2025](https://www.cyber.gov.au/publication/planning-for-post-quantum-cryptography), recommends a refined plan by end 2026, transition commenced by end 2028, and completion by end 2030. [Canada ITSM.40.001, 23 June 2025](https://www.cyber.gc.ca/en/guidance/roadmap-migration-post-quantum-cryptography-government-canada-itsm40001), covers federal non-classified IT: April 2026 initial planning and annual reporting, end-2031 high-priority migration, end-2035 remaining migration. Its 2028 hybrid pilot is a planner assumption, not a published requirement. [UK NCSC, 20 March 2025](https://www.ncsc.gov.uk/guidance/pqc-migration-timelines), supplies 2028/2031/2035 indicative horizons; the added 2030 pilot remains a model choice.

Source dates retain their year/month precision; period-end normalization supports arithmetic without inventing official day-level deadlines. Editing model choices leaves the source milestone table unchanged. CNSA applies to National Security Systems, not all organisations; its category mapping, and unverified EU/BSI dates, are conservatively labeled planner assumptions. These educational phase counts and hybrid/50% checkpoints are not legal-compliance assessments.

## US federal non-NSS source profile

The live demo adds a separate scope/purpose check for [EO 14412](https://www.whitehouse.gov/presidential-actions/2026/06/securing-the-nation-against-advanced-cryptographic-attacks/) (22 June 2026) and [OMB M-26-15](https://www.whitehouse.gov/wp-content/uploads/2026/06/M-26-15-Execution-of-the-Migration-to-Post-Quantum-Cryptography.pdf) (24 June 2026). It separates the prioritized key-establishment and signature targets, retains the authoritative relative plan deadline alongside UTC calendar arithmetic, and excludes NSS/private-sector fixtures from those targets. The scope check does not convert the illustrative phase planner into a compliance engine.
