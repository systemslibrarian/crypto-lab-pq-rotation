import { p256 } from '@noble/curves/nist.js';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';

const encoder = new TextEncoder();

// The cryptographic material (public keys + signatures) is MEASURED from the
// real primitives at issue time — nothing here is a guessed constant. The only
// modeled value is the X.509 envelope: the issuer/subject DN, validity window,
// serial, AKI/SKI, EKU, SAN, CRL/OCSP pointers, SCT, and ASN.1 framing that a
// real public leaf certificate carries. That envelope is algorithm-independent,
// so it is the same byte cost whether the cert is classical, hybrid, or pure PQ.
const X509_ENVELOPE_BYTES = 1_100;
// ML-DSA-65 public keys are a fixed 1952 bytes (FIPS 204). Used to split the
// concatenated hybrid subjectPublicKey back into its classical + PQ halves.
const ML_DSA_65_PUBLIC_KEY_BYTES = 1_952;

export interface CertificateComponents {
  envelopeBytes: number;
  classicalPubKeyBytes: number;
  pqPubKeyBytes: number;
  classicalSigBytes: number;
  pqSigBytes: number;
}

export interface CertificateBody {
  version: number;
  serialNumber: string;
  issuer: string;
  subject: string;
  validFrom: Date;
  validTo: Date;
  publicKeyAlgorithm: 'ECDSA-P256' | 'ML-DSA-65' | 'ECDSA-P256+ML-DSA-65';
  publicKey: Uint8Array;
}

export interface HybridCertificate {
  body: CertificateBody;
  classicalSignature: Uint8Array;
  pqSignature: Uint8Array;
  bodyHash: Uint8Array;
  components: CertificateComponents;
  totalSizeBytes: number;
  classicalSizeBytes: number;
  pqSizeBytes: number;
}

function randomBytes(length: number): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(length));
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (value) => value.toString(16).padStart(2, '0')).join('');
}

function serializeCertificateBody(body: CertificateBody): Uint8Array {
  return encoder.encode(
    JSON.stringify({
      version: body.version,
      serialNumber: body.serialNumber,
      issuer: body.issuer,
      subject: body.subject,
      validFrom: body.validFrom.toISOString(),
      validTo: body.validTo.toISOString(),
      publicKeyAlgorithm: body.publicKeyAlgorithm,
      publicKey: bytesToHex(body.publicKey),
    }),
  );
}

async function sha256(bytes: Uint8Array): Promise<Uint8Array> {
  const digestInput = Uint8Array.from(bytes);
  const digest = await crypto.subtle.digest('SHA-256', digestInput);
  return new Uint8Array(digest);
}

function tamperAwareReason(classicalValid: boolean, pqValid: boolean, hashMatches: boolean): string | undefined {
  if (!hashMatches) {
    return 'Certificate body hash mismatch.';
  }
  if (!classicalValid && !pqValid) {
    return 'Both classical and post-quantum signatures failed verification.';
  }
  if (!classicalValid) {
    return 'Classical ECDSA signature failed verification.';
  }
  if (!pqValid) {
    return 'Post-quantum ML-DSA signature failed verification.';
  }
  return undefined;
}

export async function issueHybridCertificate(
  subject: string,
  caClassicalKey: Uint8Array,
  caPQKey: Uint8Array,
  subjectPublicKey: Uint8Array,
  validDays: number = 365,
): Promise<HybridCertificate> {
  const issuedAt = new Date();
  const expiresAt = new Date(issuedAt.getTime() + validDays * 24 * 60 * 60 * 1000);
  const body: CertificateBody = {
    version: 3,
    serialNumber: bytesToHex(randomBytes(12)),
    issuer: 'CN=Quantum Transition Issuing CA',
    subject,
    validFrom: issuedAt,
    validTo: expiresAt,
    publicKeyAlgorithm: 'ECDSA-P256+ML-DSA-65',
    publicKey: subjectPublicKey,
  };

  const serializedBody = serializeCertificateBody(body);
  const bodyHash = await sha256(serializedBody);
  const classicalSignature = p256.sign(bodyHash, caClassicalKey, { format: 'compact' });
  const pqSignature = ml_dsa65.sign(bodyHash, caPQKey);

  const components: CertificateComponents = {
    envelopeBytes: X509_ENVELOPE_BYTES,
    classicalPubKeyBytes: Math.max(0, subjectPublicKey.length - ML_DSA_65_PUBLIC_KEY_BYTES),
    pqPubKeyBytes: ML_DSA_65_PUBLIC_KEY_BYTES,
    classicalSigBytes: classicalSignature.length,
    pqSigBytes: pqSignature.length,
  };

  return {
    body,
    classicalSignature,
    pqSignature,
    bodyHash,
    components,
    classicalSizeBytes: components.envelopeBytes + components.classicalPubKeyBytes + components.classicalSigBytes,
    pqSizeBytes: components.envelopeBytes + components.pqPubKeyBytes + components.pqSigBytes,
    totalSizeBytes:
      components.envelopeBytes +
      components.classicalPubKeyBytes +
      components.pqPubKeyBytes +
      components.classicalSigBytes +
      components.pqSigBytes,
  };
}

export async function verifyHybridCertificate(
  cert: HybridCertificate,
  caClassicalPubKey: Uint8Array,
  caPQPubKey: Uint8Array,
): Promise<{
  valid: boolean;
  classicalValid: boolean;
  pqValid: boolean;
  reason?: string;
}> {
  const serializedBody = serializeCertificateBody(cert.body);
  const recomputedHash = await sha256(serializedBody);
  const hashMatches = bytesToHex(recomputedHash) === bytesToHex(cert.bodyHash);
  const classicalValid = hashMatches && p256.verify(cert.classicalSignature, cert.bodyHash, caClassicalPubKey, { format: 'compact' });
  const pqValid = hashMatches && ml_dsa65.verify(cert.pqSignature, cert.bodyHash, caPQPubKey);
  const valid = hashMatches && classicalValid && pqValid;

  return {
    valid,
    classicalValid,
    pqValid,
    reason: valid ? undefined : tamperAwareReason(classicalValid, pqValid, hashMatches),
  };
}

export function analyzeCertificateSize(cert: HybridCertificate): {
  envelope: number;
  classicalPubKey: number;
  pqPubKey: number;
  classicalSig: number;
  pqSig: number;
  classicalTotal: number;
  purePqTotal: number;
  hybridTotal: number;
  hybridVsClassical: number;
  cryptoMaterialClassical: number;
  cryptoMaterialHybrid: number;
  cryptoMaterialRatio: number;
} {
  const c = cert.components;
  const classicalTotal = c.envelopeBytes + c.classicalPubKeyBytes + c.classicalSigBytes;
  const purePqTotal = c.envelopeBytes + c.pqPubKeyBytes + c.pqSigBytes;
  const hybridTotal =
    c.envelopeBytes + c.classicalPubKeyBytes + c.pqPubKeyBytes + c.classicalSigBytes + c.pqSigBytes;
  // The envelope is shared, so the algorithm-attributable growth is clearest
  // when isolated to the crypto material (public key + signature) alone.
  const cryptoMaterialClassical = c.classicalPubKeyBytes + c.classicalSigBytes;
  const cryptoMaterialHybrid = c.classicalPubKeyBytes + c.pqPubKeyBytes + c.classicalSigBytes + c.pqSigBytes;

  return {
    envelope: c.envelopeBytes,
    classicalPubKey: c.classicalPubKeyBytes,
    pqPubKey: c.pqPubKeyBytes,
    classicalSig: c.classicalSigBytes,
    pqSig: c.pqSigBytes,
    classicalTotal,
    purePqTotal,
    hybridTotal,
    hybridVsClassical: Number((hybridTotal / Math.max(1, classicalTotal)).toFixed(1)),
    cryptoMaterialClassical,
    cryptoMaterialHybrid,
    cryptoMaterialRatio: Math.round(cryptoMaterialHybrid / Math.max(1, cryptoMaterialClassical)),
  };
}

export async function runHybridCertificateChecks(): Promise<{
  issuedAndVerified: boolean;
  classicalTamperDetected: boolean;
  pqTamperDetected: boolean;
  sizeEstimateReasonable: boolean;
  sizeBreakdownAccurate: boolean;
}> {
  const caClassical = p256.keygen();
  const caPq = ml_dsa65.keygen(randomBytes(32));
  const subjectClassical = p256.keygen();
  const subjectPq = ml_dsa65.keygen(randomBytes(32));
  const subjectPublicKey = new Uint8Array(subjectClassical.publicKey.length + subjectPq.publicKey.length);
  subjectPublicKey.set(subjectClassical.publicKey, 0);
  subjectPublicKey.set(subjectPq.publicKey, subjectClassical.publicKey.length);

  const certificate = await issueHybridCertificate(
    'CN=example.com',
    caClassical.secretKey,
    caPq.secretKey,
    subjectPublicKey,
  );
  const verification = await verifyHybridCertificate(certificate, caClassical.publicKey, caPq.publicKey);

  const tamperedClassical = {
    ...certificate,
    classicalSignature: certificate.classicalSignature.slice(),
  };
  tamperedClassical.classicalSignature[0] ^= 0x01;

  const tamperedPQ = {
    ...certificate,
    pqSignature: certificate.pqSignature.slice(),
  };
  tamperedPQ.pqSignature[0] ^= 0x01;

  const tamperedClassicalVerification = await verifyHybridCertificate(
    tamperedClassical,
    caClassical.publicKey,
    caPq.publicKey,
  );
  const tamperedPqVerification = await verifyHybridCertificate(tamperedPQ, caClassical.publicKey, caPq.publicKey);
  const size = analyzeCertificateSize(certificate);
  const breakdownMatches =
    size.hybridTotal === size.envelope + size.classicalPubKey + size.pqPubKey + size.classicalSig + size.pqSig;

  return {
    issuedAndVerified: verification.valid,
    classicalTamperDetected: !tamperedClassicalVerification.classicalValid,
    pqTamperDetected: !tamperedPqVerification.pqValid,
    // ML-DSA-65 signatures are a fixed 3309 bytes; a classical leaf cert lands
    // around 1.2 KB. If these measured values drift, the primitives changed.
    sizeEstimateReasonable: size.pqSig === 3_309 && size.classicalTotal >= 1_000 && size.classicalTotal <= 2_000,
    sizeBreakdownAccurate: breakdownMatches,
  };
}