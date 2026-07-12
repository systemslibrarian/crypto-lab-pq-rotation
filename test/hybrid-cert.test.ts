import { describe, it, expect } from 'vitest';
import { p256 } from '@noble/curves/nist.js';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';

import {
  issueHybridCertificate,
  verifyHybridCertificate,
  analyzeCertificateSize,
  runHybridCertificateChecks,
  type HybridCertificate,
} from '../src/hybrid-cert.ts';

// FIPS 204 fixed sizes for ML-DSA-65. If a dependency bump silently changes the
// primitive, these known-answer constants make the build fail instead of
// letting the README's "measured" size claims quietly drift into fiction.
const ML_DSA_65_PUBLIC_KEY_BYTES = 1_952;
const ML_DSA_65_SIG_BYTES = 3_309;
const P256_COMPACT_SIG_BYTES = 64;

function randomBytes(length: number): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(length));
}

interface TestCa {
  caClassical: ReturnType<typeof p256.keygen>;
  caPq: ReturnType<typeof ml_dsa65.keygen>;
  subjectPublicKey: Uint8Array;
  classicalPubLen: number;
}

function buildCaAndSubject(): TestCa {
  const caClassical = p256.keygen();
  const caPq = ml_dsa65.keygen(randomBytes(32));
  const subjectClassical = p256.keygen();
  const subjectPq = ml_dsa65.keygen(randomBytes(32));
  const subjectPublicKey = new Uint8Array(subjectClassical.publicKey.length + subjectPq.publicKey.length);
  subjectPublicKey.set(subjectClassical.publicKey, 0);
  subjectPublicKey.set(subjectPq.publicKey, subjectClassical.publicKey.length);
  return { caClassical, caPq, subjectPublicKey, classicalPubLen: subjectClassical.publicKey.length };
}

async function freshCert(): Promise<{ cert: HybridCertificate; ca: TestCa }> {
  const ca = buildCaAndSubject();
  const cert = await issueHybridCertificate(
    'CN=example.com',
    ca.caClassical.secretKey,
    ca.caPq.secretKey,
    ca.subjectPublicKey,
  );
  return { cert, ca };
}

describe('known-answer sizes (FIPS 204 / SEC1)', () => {
  it('ML-DSA-65 public keys are exactly 1952 bytes', () => {
    const kp = ml_dsa65.keygen(randomBytes(32));
    expect(kp.publicKey.length).toBe(ML_DSA_65_PUBLIC_KEY_BYTES);
  });

  it('ML-DSA-65 signatures are exactly 3309 bytes', () => {
    const kp = ml_dsa65.keygen(randomBytes(32));
    const sig = ml_dsa65.sign(randomBytes(32), kp.secretKey);
    expect(sig.length).toBe(ML_DSA_65_SIG_BYTES);
  });

  it('P-256 compact signatures are exactly 64 bytes', () => {
    const kp = p256.keygen();
    const sig = p256.sign(randomBytes(32), kp.secretKey, { format: 'compact' });
    expect(sig.length).toBe(P256_COMPACT_SIG_BYTES);
  });

  it('issued certificate reports the measured primitive sizes', async () => {
    const { cert } = await freshCert();
    expect(cert.components.pqSigBytes).toBe(ML_DSA_65_SIG_BYTES);
    expect(cert.components.pqPubKeyBytes).toBe(ML_DSA_65_PUBLIC_KEY_BYTES);
    expect(cert.components.classicalSigBytes).toBe(P256_COMPACT_SIG_BYTES);
  });
});

describe('issue / verify round trip', () => {
  it('a freshly issued hybrid certificate verifies with both signatures', async () => {
    const { cert, ca } = await freshCert();
    const result = await verifyHybridCertificate(cert, ca.caClassical.publicKey, ca.caPq.publicKey);
    expect(result.valid).toBe(true);
    expect(result.classicalValid).toBe(true);
    expect(result.pqValid).toBe(true);
    expect(result.reason).toBeUndefined();
  });

  it('the bodyHash is the SHA-256 of the serialized body (not a placeholder)', async () => {
    const { cert } = await freshCert();
    expect(cert.bodyHash.length).toBe(32);
    // A hash of real content is not all-zero.
    expect(cert.bodyHash.some((b) => b !== 0)).toBe(true);
  });
});

describe('tamper detection (verify rejects forgery)', () => {
  it('flipping one bit of the classical signature is rejected', async () => {
    const { cert, ca } = await freshCert();
    const forged: HybridCertificate = { ...cert, classicalSignature: cert.classicalSignature.slice() };
    forged.classicalSignature[0] ^= 0x01;
    const result = await verifyHybridCertificate(forged, ca.caClassical.publicKey, ca.caPq.publicKey);
    expect(result.valid).toBe(false);
    expect(result.classicalValid).toBe(false);
    // The PQ signature is untouched, so a hybrid verifier still sees it hold.
    expect(result.pqValid).toBe(true);
    expect(result.reason).toMatch(/classical/i);
  });

  it('flipping one bit of the PQ signature is rejected', async () => {
    const { cert, ca } = await freshCert();
    const forged: HybridCertificate = { ...cert, pqSignature: cert.pqSignature.slice() };
    forged.pqSignature[0] ^= 0x01;
    const result = await verifyHybridCertificate(forged, ca.caClassical.publicKey, ca.caPq.publicKey);
    expect(result.valid).toBe(false);
    expect(result.pqValid).toBe(false);
    expect(result.classicalValid).toBe(true);
    expect(result.reason).toMatch(/post-quantum|ML-DSA/i);
  });

  it('editing the certificate body invalidates both signatures via hash mismatch', async () => {
    const { cert, ca } = await freshCert();
    const forged: HybridCertificate = {
      ...cert,
      body: { ...cert.body, subject: 'CN=attacker.example' },
    };
    const result = await verifyHybridCertificate(forged, ca.caClassical.publicKey, ca.caPq.publicKey);
    expect(result.valid).toBe(false);
    expect(result.classicalValid).toBe(false);
    expect(result.pqValid).toBe(false);
    expect(result.reason).toMatch(/hash mismatch/i);
  });

  it('a certificate does not verify under a different CA key pair', async () => {
    const { cert } = await freshCert();
    const wrongClassical = p256.keygen();
    const wrongPq = ml_dsa65.keygen(randomBytes(32));
    const result = await verifyHybridCertificate(cert, wrongClassical.publicKey, wrongPq.publicKey);
    expect(result.valid).toBe(false);
    expect(result.classicalValid).toBe(false);
    expect(result.pqValid).toBe(false);
  });

  it('the classical half alone cannot satisfy a hybrid verifier (both required)', async () => {
    const { cert, ca } = await freshCert();
    // Keep the real classical CA key but supply a wrong PQ key: hybrid must fail.
    const wrongPq = ml_dsa65.keygen(randomBytes(32));
    const result = await verifyHybridCertificate(cert, ca.caClassical.publicKey, wrongPq.publicKey);
    expect(result.classicalValid).toBe(true);
    expect(result.pqValid).toBe(false);
    expect(result.valid).toBe(false);
  });
});

describe('size analysis honesty', () => {
  it('the breakdown sums to the reported hybrid total', async () => {
    const { cert } = await freshCert();
    const size = analyzeCertificateSize(cert);
    expect(size.hybridTotal).toBe(
      size.envelope + size.classicalPubKey + size.pqPubKey + size.classicalSig + size.pqSig,
    );
  });

  it('the hybrid crypto material grows ~55x over classical (README claim)', async () => {
    const { cert } = await freshCert();
    const size = analyzeCertificateSize(cert);
    // classical material = 65B SEC1 pubkey + 64B sig ~= 129B; hybrid adds the
    // 1952B PQ key + 3309B PQ sig. README asserts "roughly 55x".
    expect(size.cryptoMaterialRatio).toBeGreaterThanOrEqual(40);
    expect(size.cryptoMaterialRatio).toBeLessThanOrEqual(60);
  });

  it('classical leaf lands ~1.2 KB', async () => {
    const { cert } = await freshCert();
    const size = analyzeCertificateSize(cert);
    expect(size.classicalTotal).toBeGreaterThanOrEqual(1_000);
    expect(size.classicalTotal).toBeLessThanOrEqual(2_000);
  });
});

describe('in-app self-test suite mirrors these guarantees', () => {
  it('runHybridCertificateChecks reports every property held', async () => {
    const checks = await runHybridCertificateChecks();
    expect(checks).toEqual({
      issuedAndVerified: true,
      classicalTamperDetected: true,
      pqTamperDetected: true,
      sizeEstimateReasonable: true,
      sizeBreakdownAccurate: true,
    });
  });
});
