# crypto-lab-pq-rotation

## What It Is

`crypto-lab-pq-rotation` is a browser-based interactive planner for post-quantum cryptography migration, focused on real deployment operations rather than algorithm theory. It models the end-to-end transition from cryptographic inventory through hybrid deployment to pure PQC in a five-phase program.

A **"Start here" stepper** at the top gives the newcomer a single causal spine — urgency justifies the hybrid fix, the fix has a size cost, deadlines sequence the work, and staged rotation ships it — and each of the four steps links to its section. Jargon (HNDL, composite signatures, canary) is glossed in one plain sentence on first use, in the same style as the Mosca card.

The demo includes:

- An interactive **Mosca's-inequality** model (X + Y > Z) with adjustable CRQC year and migration time, pairing the generic formula with a live worst-case worked example pulled from the loaded inventory, so you can see exactly when "harvest now, decrypt later" (HNDL) already puts your data past the line.
- Hybrid X.509-style certificates with classical + PQ signatures (ECDSA-P256 + ML-DSA-65) and **measured** byte-size analysis (not estimates), shown as **to-scale stacked bars** (envelope, classical pubkey/sig, PQ pubkey/sig) so the ML-DSA signature's dominance of the size cost is visible at a glance.
- A **tamper lab** on the real certificate: forge the classical signature, the PQ signature, or the body and watch verification react live. A **certificate-structure diagram** (Body → SHA-256 hash → {classical sig, PQ sig} → overall trust) turns the affected block red and shows the actual flipped hex byte before/after — demonstrating why a hybrid verifier trusts a certificate only when *both* signatures hold.
- A timeline engine that aligns migration actions with major regulatory frameworks (CNSA 2.0, EU NIS, UK NCSC, Australia ASD, Germany BSI, Canada CCCS). Each phase bar is a **self-explaining count** (how many inventory items are due by today) with one concrete example action and its planned date; the Doom Meter numbers are traced back to the framework's own milestone dates.
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
- Compare regulatory timelines across jurisdictions.
- Prototype crypto-agile architecture decisions for new systems.
- Do NOT use this as a production PKI or key-management platform — it is an educational planning tool, not a CA product.

## Live Demo

**[systemslibrarian.github.io/crypto-lab-pq-rotation](https://systemslibrarian.github.io/crypto-lab-pq-rotation/)**

The planner walks a five-phase PQC migration program end to end: an interactive Mosca's-inequality model, a live hybrid X.509 certificate (ECDSA-P256 + ML-DSA-65) with a tamper lab that forges the classical signature, the PQ signature, or the body, a regulatory-timeline engine spanning CNSA 2.0 and other jurisdictions, a rolling key-rotation simulator with canary rollout and automatic rollback, an in-browser cryptographic self-test suite, and an inventory/readiness dashboard. Every byte size shown is measured from keys and signatures generated live in the browser.

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

*One of 120+ browser demos in the [Crypto Lab](https://crypto-lab.systemslibrarian.dev/) suite.*

*"So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31*
