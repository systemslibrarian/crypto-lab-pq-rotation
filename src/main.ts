import { p256 } from '@noble/curves/nist.js';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';

import './style.css';
import {
  analyzeCertificateSize,
  issueHybridCertificate,
  verifyHybridCertificate,
  type HybridCertificate,
} from './hybrid-cert.ts';
import {
  AUSTRALIA_ASD,
  CANADA_CCCS,
  CNSA_2_0,
  EU_NIS,
  GERMANY_BSI,
  UK_NCSC,
  computeHNDLRisk,
  computePriorityScore,
  generateMigrationPlan,
  type CryptoInventoryItem,
  type RegulatoryFramework,
} from './timeline-engine.ts';
import {
  fleetReadinessScore,
  simulateRotation,
  type RotationStep,
  type ServerState,
} from './rotation-sim.ts';

interface InventoryAggregateRow {
  type: string;
  algorithm: string;
  count: number;
  sensitivity: string;
}

interface InventoryDemo {
  key: 'small' | 'gov' | 'finance';
  name: string;
  narrative: string;
  rows: InventoryAggregateRow[];
  items: CryptoInventoryItem[];
}

const FRAMEWORKS: RegulatoryFramework[] = [
  CNSA_2_0,
  EU_NIS,
  UK_NCSC,
  AUSTRALIA_ASD,
  GERMANY_BSI,
  CANADA_CCCS,
];

const DEMOS: InventoryDemo[] = [
  {
    key: 'small',
    name: 'Small Enterprise',
    narrative: 'Regional services company modernizing SaaS and VPN infrastructure.',
    rows: [
      { type: 'TLS endpoints', algorithm: 'ECDSA-P256', count: 84, sensitivity: '3-10 years' },
      { type: 'Code signing', algorithm: 'ECDSA-P256', count: 6, sensitivity: '10+ years' },
      { type: 'VPN gateways', algorithm: 'RSA-2048', count: 11, sensitivity: '3-5 years' },
      { type: 'JWT signing', algorithm: 'RSA-2048', count: 14, sensitivity: 'hours' },
      { type: 'SSH keys', algorithm: 'Ed25519', count: 230, sensitivity: '1-5 years' },
    ],
    items: [
      {
        id: 'small-root-ca',
        systemName: 'SmallCo Root CA',
        type: 'pki_root_ca',
        currentAlgorithm: 'RSA-4096',
        dataSensitivityYears: 40,
        cryptoAgility: 'requires_replacement',
        vendorPQRoadmap: 'unknown',
        environmentTag: 'production',
      },
      {
        id: 'small-int-ca',
        systemName: 'SmallCo Intermediate CA',
        type: 'pki_intermediate_ca',
        currentAlgorithm: 'RSA-4096',
        dataSensitivityYears: 20,
        cryptoAgility: 'requires_replacement',
        vendorPQRoadmap: 'in_progress',
        environmentTag: 'production',
      },
      {
        id: 'small-web-tls',
        systemName: 'Public Web TLS',
        type: 'tls_endpoint',
        currentAlgorithm: 'ECDSA-P256',
        dataSensitivityYears: 8,
        cryptoAgility: 'requires_redeploy',
        vendorPQRoadmap: 'committed',
        environmentTag: 'production',
      },
      {
        id: 'small-vpn',
        systemName: 'Remote Access VPN',
        type: 'vpn',
        currentAlgorithm: 'RSA-2048',
        dataSensitivityYears: 5,
        cryptoAgility: 'requires_redeploy',
        vendorPQRoadmap: 'in_progress',
        environmentTag: 'production',
      },
      {
        id: 'small-jwt',
        systemName: 'API JWT Signer',
        type: 'jwt',
        currentAlgorithm: 'RSA-2048',
        dataSensitivityYears: 1,
        cryptoAgility: 'native',
        vendorPQRoadmap: 'committed',
        environmentTag: 'staging',
      },
    ],
  },
  {
    key: 'gov',
    name: 'Government Agency',
    narrative: 'Mid-size government agency with long-lived trust chains and firmware programs.',
    rows: [
      { type: 'TLS endpoints', algorithm: 'ECDSA-P256', count: 247, sensitivity: '5-30 years' },
      { type: 'TLS endpoints', algorithm: 'RSA-2048', count: 89, sensitivity: 'varies' },
      { type: 'Code signing', algorithm: 'ECDSA-P256', count: 12, sensitivity: '20+ years' },
      { type: 'Firmware signing', algorithm: 'RSA-4096', count: 5, sensitivity: '30+ years' },
      { type: 'Root CAs', algorithm: 'RSA-4096', count: 3, sensitivity: '100+ years' },
      { type: 'Intermediate CAs', algorithm: 'RSA-4096', count: 17, sensitivity: '20 years' },
      { type: 'Issuing CAs', algorithm: 'ECDSA-P256', count: 42, sensitivity: '10 years' },
      { type: 'VPN gateways', algorithm: 'RSA-2048', count: 31, sensitivity: '3-5 years' },
      { type: 'Database TDE', algorithm: 'AES-256', count: 89, sensitivity: 'N/A (symmetric)' },
      { type: 'SSH keys', algorithm: 'Ed25519', count: 892, sensitivity: '1-5 years' },
      { type: 'JWT signing', algorithm: 'RSA-2048', count: 23, sensitivity: 'hours' },
      { type: 'IoT attestation', algorithm: 'ECDSA-P256', count: 4521, sensitivity: '10 years' },
      { type: 'Backup encryption', algorithm: 'AES-256', count: 156, sensitivity: 'N/A (symmetric)' },
    ],
    items: [
      {
        id: 'gov-root-ca-1',
        systemName: 'Classified Root CA',
        type: 'pki_root_ca',
        currentAlgorithm: 'RSA-4096',
        dataSensitivityYears: 100,
        cryptoAgility: 'requires_replacement',
        vendorPQRoadmap: 'unknown',
        environmentTag: 'production',
      },
      {
        id: 'gov-int-ca-1',
        systemName: 'Internal Intermediate CA',
        type: 'pki_intermediate_ca',
        currentAlgorithm: 'RSA-4096',
        dataSensitivityYears: 20,
        cryptoAgility: 'requires_replacement',
        vendorPQRoadmap: 'in_progress',
        environmentTag: 'production',
      },
      {
        id: 'gov-issuing-1',
        systemName: 'Citizen Services Issuing CA',
        type: 'pki_issuing_ca',
        currentAlgorithm: 'ECDSA-P256',
        dataSensitivityYears: 10,
        cryptoAgility: 'requires_replacement',
        vendorPQRoadmap: 'unknown',
        environmentTag: 'production',
      },
      {
        id: 'gov-fw-signing',
        systemName: 'Field Device Firmware Signer',
        type: 'firmware_signing',
        currentAlgorithm: 'RSA-4096',
        dataSensitivityYears: 30,
        cryptoAgility: 'requires_redeploy',
        vendorPQRoadmap: 'in_progress',
        environmentTag: 'production',
      },
      {
        id: 'gov-tls-classified',
        systemName: 'Classified Traffic TLS',
        type: 'tls_endpoint',
        currentAlgorithm: 'ECDSA-P256',
        dataSensitivityYears: 30,
        cryptoAgility: 'requires_redeploy',
        vendorPQRoadmap: 'committed',
        environmentTag: 'production',
      },
      {
        id: 'gov-vpn',
        systemName: 'Mission VPN',
        type: 'vpn',
        currentAlgorithm: 'RSA-2048',
        dataSensitivityYears: 5,
        cryptoAgility: 'requires_redeploy',
        vendorPQRoadmap: 'in_progress',
        environmentTag: 'production',
      },
      {
        id: 'gov-jwt',
        systemName: 'Benefits API Tokens',
        type: 'jwt',
        currentAlgorithm: 'RSA-2048',
        dataSensitivityYears: 1,
        cryptoAgility: 'native',
        vendorPQRoadmap: 'committed',
        environmentTag: 'staging',
      },
      {
        id: 'gov-iot',
        systemName: 'IoT Attestation Authority',
        type: 'iot_attestation',
        currentAlgorithm: 'ECDSA-P256',
        dataSensitivityYears: 10,
        cryptoAgility: 'requires_redeploy',
        vendorPQRoadmap: 'unknown',
        environmentTag: 'legacy',
      },
      {
        id: 'gov-ssh-dev',
        systemName: 'Dev SSH Bastion',
        type: 'ssh',
        currentAlgorithm: 'Ed25519',
        dataSensitivityYears: 2,
        cryptoAgility: 'native',
        vendorPQRoadmap: 'committed',
        environmentTag: 'development',
      },
    ],
  },
  {
    key: 'finance',
    name: 'Financial Services',
    narrative: 'Transaction-heavy environment balancing strict compliance and high availability.',
    rows: [
      { type: 'TLS endpoints', algorithm: 'ECDSA-P256', count: 420, sensitivity: '7-25 years' },
      { type: 'Code signing', algorithm: 'RSA-3072', count: 18, sensitivity: '25+ years' },
      { type: 'Root CAs', algorithm: 'RSA-4096', count: 2, sensitivity: '80+ years' },
      { type: 'VPN gateways', algorithm: 'RSA-2048', count: 46, sensitivity: '5-8 years' },
      { type: 'S/MIME', algorithm: 'RSA-2048', count: 2100, sensitivity: '7 years' },
    ],
    items: [
      {
        id: 'fin-root-ca',
        systemName: 'Payments Root CA',
        type: 'pki_root_ca',
        currentAlgorithm: 'RSA-4096',
        dataSensitivityYears: 80,
        cryptoAgility: 'requires_replacement',
        vendorPQRoadmap: 'unknown',
        environmentTag: 'production',
      },
      {
        id: 'fin-issuing-ca',
        systemName: 'Retail Issuing CA',
        type: 'pki_issuing_ca',
        currentAlgorithm: 'ECDSA-P256',
        dataSensitivityYears: 18,
        cryptoAgility: 'requires_replacement',
        vendorPQRoadmap: 'in_progress',
        environmentTag: 'production',
      },
      {
        id: 'fin-core-tls',
        systemName: 'Core Banking TLS',
        type: 'tls_endpoint',
        currentAlgorithm: 'ECDSA-P256',
        dataSensitivityYears: 25,
        cryptoAgility: 'requires_redeploy',
        vendorPQRoadmap: 'committed',
        environmentTag: 'production',
      },
      {
        id: 'fin-code-sign',
        systemName: 'Trading App Code Signing',
        type: 'code_signing',
        currentAlgorithm: 'RSA-3072',
        dataSensitivityYears: 25,
        cryptoAgility: 'requires_redeploy',
        vendorPQRoadmap: 'in_progress',
        environmentTag: 'production',
      },
      {
        id: 'fin-smime',
        systemName: 'Executive S/MIME',
        type: 'email_smime',
        currentAlgorithm: 'RSA-2048',
        dataSensitivityYears: 7,
        cryptoAgility: 'requires_redeploy',
        vendorPQRoadmap: 'unknown',
        environmentTag: 'legacy',
      },
    ],
  },
];

const state = {
  selectedDemoKey: 'gov' as InventoryDemo['key'],
  selectedFrameworkName: 'EU_NIS' as RegulatoryFramework['name'],
  certView: 'hybrid' as 'classical' | 'hybrid' | 'pure_pq',
  certInfo: null as HybridCertificate | null,
  certValidation: null as Awaited<ReturnType<typeof verifyHybridCertificate>> | null,
  certSize: null as ReturnType<typeof analyzeCertificateSize> | null,
  rotationServers: createFleet(1247),
  rotationLogs: [] as RotationStep[],
  rotationSummary: null as Awaited<ReturnType<typeof simulateRotation>> | null,
  uiMessage: '' as string,
  uiMessageTone: 'info' as 'info' | 'error',
};

function randomBytes(length: number): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(length));
}

function createFleet(count: number): ServerState[] {
  const regions = ['us-east-1', 'us-west-2', 'eu-west-2', 'ap-southeast-2', 'ca-central-1'];
  const baseTraffic = 100 / count;
  return Array.from({ length: count }, (_, index) => ({
    id: `srv-${String(index + 1).padStart(4, '0')}`,
    location: regions[index % regions.length] ?? 'us-east-1',
    currentCertificate: null,
    status: 'classical_only',
    lastRotation: new Date('2026-01-01T00:00:00.000Z'),
    tlsVersion: '1.3',
    supportsX25519MLKEM768: index % 6 !== 0,
    trafficPercent: Number(baseTraffic.toFixed(4)),
  }));
}

function getSelectedDemo(): InventoryDemo {
  return DEMOS.find((demo) => demo.key === state.selectedDemoKey) ?? DEMOS[1];
}

function getSelectedFramework(): RegulatoryFramework {
  return FRAMEWORKS.find((framework) => framework.name === state.selectedFrameworkName) ?? EU_NIS;
}

function numberFmt(value: number): string {
  return new Intl.NumberFormat('en-US').format(value);
}

function pct(value: number): string {
  return `${value.toFixed(1)}%`;
}

function dateFmt(value: Date): string {
  return value.toISOString().slice(0, 10);
}

function renderProgressBar(percentValue: number): string {
  const filled = Math.max(0, Math.min(16, Math.round((percentValue / 100) * 16)));
  return `${'█'.repeat(filled)}${'░'.repeat(16 - filled)}`;
}

function computeDoomMeter(start: Date, framework: RegulatoryFramework): { firstHybridMonths: number; halfCoverageMonths: number; fullYears: string; warning: string } {
  const pilot = framework.milestones.find((milestone) => milestone.category === 'pilot')?.date ?? new Date(start);
  const highRisk = framework.milestones.find((milestone) => milestone.category === 'high_risk')?.date ?? new Date(start);
  const full = framework.milestones.find((milestone) => milestone.category === 'full_migration')?.date ?? new Date(start);

  const firstHybridMonths = Math.max(1, Math.round((pilot.getTime() - start.getTime()) / (30 * 24 * 60 * 60 * 1000)));
  const halfCoverageMonths = Math.max(firstHybridMonths + 6, Math.round((highRisk.getTime() - start.getTime()) / (30 * 24 * 60 * 60 * 1000)));
  const fullYears = ((full.getTime() - start.getTime()) / (365.25 * 24 * 60 * 60 * 1000)).toFixed(1);

  let warning = 'On schedule with focused execution.';
  if (firstHybridMonths > 9) {
    warning = 'Late hybrid start pushes emergency cutover risk toward regulatory deadlines.';
  }
  if (halfCoverageMonths > 30) {
    warning = '50% hybrid coverage lands dangerously close to high-risk mandates.';
  }

  return {
    firstHybridMonths,
    halfCoverageMonths,
    fullYears,
    warning,
  };
}

async function generateCertificateDemo(): Promise<void> {
  const caClassic = p256.keygen();
  const caPq = ml_dsa65.keygen(randomBytes(32));
  const subjectClassic = p256.keygen();
  const subjectPq = ml_dsa65.keygen(randomBytes(32));
  const subjectPublicKey = new Uint8Array(subjectClassic.publicKey.length + subjectPq.publicKey.length);
  subjectPublicKey.set(subjectClassic.publicKey, 0);
  subjectPublicKey.set(subjectPq.publicKey, subjectClassic.publicKey.length);

  const cert = await issueHybridCertificate(
    'CN=example.com',
    caClassic.secretKey,
    caPq.secretKey,
    subjectPublicKey,
  );

  const validation = await verifyHybridCertificate(cert, caClassic.publicKey, caPq.publicKey);
  state.certInfo = cert;
  state.certValidation = validation;
  state.certSize = analyzeCertificateSize(cert);
}

function phaseCompletion(planDates: Date[], now: Date): number {
  if (planDates.length === 0) {
    return 0;
  }
  const done = planDates.filter((date) => date.getTime() <= now.getTime()).length;
  return Number(((done / planDates.length) * 100).toFixed(1));
}

function renderInventoryExhibit(demo: InventoryDemo, riskRows: Array<{ item: CryptoInventoryItem; risk: ReturnType<typeof computeHNDLRisk> }>): string {
  const total = demo.rows.reduce((sum, row) => sum + row.count, 0);
  const highRisk = riskRows.filter((entry) => entry.risk.atRisk && (entry.risk.riskLevel === 'critical' || entry.risk.riskLevel === 'high'));
  const score = Math.max(0, Math.min(100, Math.round((highRisk.length / Math.max(1, demo.items.length)) * 100 + 35)));

  return `
    <section class="panel" id="inventory" aria-labelledby="inventory-title">
      <div class="panel-head">
        <h2 id="inventory-title">Exhibit 1: Your Cryptographic Inventory</h2>
        <p>${demo.narrative}</p>
      </div>
      <div class="button-row" role="group" aria-label="inventory demos">
        <button type="button" data-action="demo" data-demo="small" aria-pressed="${state.selectedDemoKey === 'small'}" class="chip ${state.selectedDemoKey === 'small' ? 'active' : ''}">Load demo: Small enterprise</button>
        <button type="button" data-action="demo" data-demo="gov" aria-pressed="${state.selectedDemoKey === 'gov'}" class="chip ${state.selectedDemoKey === 'gov' ? 'active' : ''}">Load demo: Government agency</button>
        <button type="button" data-action="demo" data-demo="finance" aria-pressed="${state.selectedDemoKey === 'finance'}" class="chip ${state.selectedDemoKey === 'finance' ? 'active' : ''}">Load demo: Financial services</button>
      </div>
      <div class="card table-wrap" role="region" aria-label="Inventory summary table">
        <h3>Demo inventory: ${demo.name}</h3>
        <table>
          <caption class="sr-only">Cryptographic inventory counts, algorithms, and sensitivity ranges</caption>
          <thead>
            <tr><th scope="col">Type</th><th scope="col">Algorithm</th><th scope="col">Count</th><th scope="col">Sensitivity</th></tr>
          </thead>
          <tbody>
            ${demo.rows
              .map((row) => `<tr><td>${row.type}</td><td>${row.algorithm}</td><td>${numberFmt(row.count)}</td><td>${row.sensitivity}</td></tr>`)
              .join('')}
          </tbody>
        </table>
        <div class="metrics">
          <div><span>Total At-Risk Items</span><strong>${numberFmt(total)}</strong></div>
          <div><span>HNDL Risk Score</span><strong>${score}/100 (${score >= 70 ? 'HIGH' : 'ELEVATED'})</strong></div>
        </div>
      </div>
      <div class="alert">
        <h3>Harvest-Now-Decrypt-Later Exposure</h3>
        <ul>
          ${highRisk
            .slice(0, 6)
            .map((entry) => `<li>${entry.item.systemName}: ${entry.risk.explanation}</li>`)
            .join('')}
        </ul>
      </div>
    </section>
  `;
}

function renderTimelineExhibit(demo: InventoryDemo, framework: RegulatoryFramework): string {
  const now = new Date();
  const plan = generateMigrationPlan(demo.items, framework, now);
  const phase1 = phaseCompletion(plan.filter((entry) => entry.phase === 1).map((entry) => entry.plannedDate), now);
  const phase2 = phaseCompletion(plan.filter((entry) => entry.phase === 2).map((entry) => entry.plannedDate), now);
  const phase3 = phaseCompletion(plan.filter((entry) => entry.phase === 3).map((entry) => entry.plannedDate), now);
  const phase4 = phaseCompletion(plan.filter((entry) => entry.phase === 4).map((entry) => entry.plannedDate), now);
  const phase5 = phaseCompletion(plan.filter((entry) => entry.phase === 5).map((entry) => entry.plannedDate), now);
  const doom = computeDoomMeter(now, framework);

  return `
    <section class="panel" id="timeline" aria-labelledby="timeline-title">
      <div class="panel-head">
        <h2 id="timeline-title">Exhibit 2: Interactive Timeline Planner</h2>
        <p>Aligning migration phases with published national frameworks.</p>
      </div>
      <fieldset class="framework-picker">
        <legend>Select regulatory framework</legend>
        ${FRAMEWORKS.map(
          (item) =>
            `<label class="radio"><input type="radio" name="framework" data-action="framework" value="${item.name}" ${
              item.name === framework.name ? 'checked' : ''
            }><span>${item.name.replaceAll('_', ' ')}</span></label>`,
        ).join('')}
      </fieldset>
      <div class="card timeline-track">
        ${framework.milestones
          .map((milestone) => `<div class="milestone"><strong>${dateFmt(milestone.date)}</strong><p>${milestone.description}</p></div>`)
          .join('')}
      </div>
      <div class="phase-grid">
        <div><span>${renderProgressBar(phase1)}</span><em>Phase 1 Inventory (${pct(phase1)})</em></div>
        <div><span>${renderProgressBar(phase2)}</span><em>Phase 2 Prioritize (${pct(phase2)})</em></div>
        <div><span>${renderProgressBar(phase3)}</span><em>Phase 3 Crypto-agility (${pct(phase3)})</em></div>
        <div><span>${renderProgressBar(phase4)}</span><em>Phase 4 Hybrid deployment (${pct(phase4)})</em></div>
        <div><span>${renderProgressBar(phase5)}</span><em>Phase 5 Pure PQC (${pct(phase5)})</em></div>
      </div>
      <div class="doom">
        <h3>The Doom Meter</h3>
        <p>If you start today, first hybrid deployment in <strong>${doom.firstHybridMonths} months</strong>, 50% hybrid in <strong>${doom.halfCoverageMonths} months</strong>, full migration in <strong>${doom.fullYears} years</strong>.</p>
        <p>${doom.warning}</p>
      </div>
    </section>
  `;
}

function renderCertificateExhibit(): string {
  const cert = state.certInfo;
  const size = state.certSize;
  const validation = state.certValidation;
  const mode = state.certView;

  const classicalSize = cert?.classicalSizeBytes ?? 1500;
  const hybridSize = cert?.totalSizeBytes ?? 11800;
  const purePqSize = cert?.pqSizeBytes ?? 8000;
  const mult = (hybridSize / classicalSize).toFixed(1);

  return `
    <section class="panel" id="certs" aria-labelledby="certs-title">
      <div class="panel-head">
        <h2 id="certs-title">Exhibit 3: Hybrid Certificate Anatomy</h2>
        <p>X.509-style hybrid chain with classical ECDSA and PQ ML-DSA-65 signatures per composite-signature drafts.</p>
      </div>
      <div class="button-row" role="group" aria-label="certificate view">
        <button type="button" data-action="cert-view" data-view="classical" aria-pressed="${mode === 'classical'}" class="chip ${mode === 'classical' ? 'active' : ''}">Classical</button>
        <button type="button" data-action="cert-view" data-view="hybrid" aria-pressed="${mode === 'hybrid'}" class="chip ${mode === 'hybrid' ? 'active' : ''}">Hybrid</button>
        <button type="button" data-action="cert-view" data-view="pure_pq" aria-pressed="${mode === 'pure_pq'}" class="chip ${mode === 'pure_pq' ? 'active' : ''}">Pure PQ</button>
      </div>
      <div class="cert-grid">
        <article class="card ${mode === 'classical' ? 'focus' : ''}">
          <h3>Classical ECDSA-P256 Certificate</h3>
          <p>Total size: ~${numberFmt(classicalSize)} bytes</p>
          <p>Signature: ECDSA-P256 (~64 bytes)</p>
        </article>
        <article class="card ${mode === 'hybrid' ? 'focus' : ''}">
          <h3>Hybrid ECDSA-P256 + ML-DSA-65</h3>
          <p>Total size: ~${numberFmt(hybridSize)} bytes (${mult}x larger)</p>
          <p>Security requires both signatures to verify.</p>
          <p>TLS handshake impact: +4-6% latency in constrained paths.</p>
        </article>
        <article class="card ${mode === 'pure_pq' ? 'focus' : ''}">
          <h3>Pure ML-DSA-65 (Future)</h3>
          <p>Total size: ~${numberFmt(purePqSize)} bytes</p>
          <p>Removes classical backstop after long operational confidence.</p>
        </article>
      </div>
      <div class="metrics">
        <div><span>Verification</span><strong>${validation?.valid ? 'Both signatures valid' : 'Pending validation'}</strong></div>
        <div><span>Classical Sig</span><strong>${size ? numberFmt(size.classicalSig) : '-'} bytes</strong></div>
        <div><span>PQ Sig</span><strong>${size ? numberFmt(size.pqSig) : '-'} bytes</strong></div>
        <div><span>Overhead</span><strong>${size ? `${numberFmt(size.overhead)} bytes (${size.overheadPercent}%)` : '-'}</strong></div>
      </div>
      <p class="small-note">Hybrid TLS key exchange reference: X25519MLKEM768 (codepoint 0x11EC), as used in the companion handshake lab.</p>
    </section>
  `;
}

function summarizeRotation(result: Awaited<ReturnType<typeof simulateRotation>> | null): string {
  if (!result) {
    return 'Run the simulator to see canary rollout and rollback behavior.';
  }
  const readiness = fleetReadinessScore(result.finalState);
  return result.success
    ? `Rotation completed in ${result.duration.toFixed(2)} simulated hours across ${result.totalSteps} steps. Readiness: ${pct(readiness.readinessPercent)}.`
    : `Rotation halted and rolled back after ${result.totalSteps} steps. Final readiness: ${pct(readiness.readinessPercent)}.`;
}

function renderRotationExhibit(): string {
  const readiness = fleetReadinessScore(state.rotationSummary?.finalState ?? state.rotationServers);
  const latestLogs = state.rotationLogs.slice(-8);

  return `
    <section class="panel" id="rotation" aria-labelledby="rotation-title">
      <div class="panel-head">
        <h2 id="rotation-title">Exhibit 4: Live Rotation Simulation</h2>
        <p>Canary-first staged rollout with mandatory monitoring gates and automatic rollback.</p>
      </div>
      <div class="controls card">
        <label>Canary percent <input id="canaryPercent" type="number" min="1" max="20" step="1" value="10"></label>
        <label>Monitoring hours <input id="monitorHours" type="number" min="1" max="72" step="1" value="24"></label>
        <label>Rollout stages (%) <input id="rolloutStages" type="text" value="10,50,100"></label>
        <label>Failure injection
          <select id="failureStep">
            <option value="none">No failure</option>
            <option value="rotate_10">At 10% rollout</option>
            <option value="monitor_10">After 10% monitoring</option>
            <option value="rotate_50">At 50% rollout</option>
            <option value="rotate_100">At 100% rollout</option>
          </select>
        </label>
        <button type="button" data-action="run-rotation" class="run">Run Rotation</button>
      </div>
      <div class="metrics">
        <div><span>Classical Only</span><strong>${pct((readiness.classicalOnly / Math.max(1, state.rotationServers.length)) * 100)}</strong></div>
        <div><span>Hybrid</span><strong>${pct((readiness.hybrid / Math.max(1, state.rotationServers.length)) * 100)}</strong></div>
        <div><span>Pure PQ</span><strong>${pct((readiness.pqOnly / Math.max(1, state.rotationServers.length)) * 100)}</strong></div>
        <div><span>Traffic on Hybrid or PQ</span><strong>${pct(readiness.totalTrafficOnHybridOrPQ)}</strong></div>
      </div>
      <div class="card" role="status" aria-live="polite">
        <h3>Fleet Status: ${numberFmt(state.rotationServers.length)} servers in 5 regions</h3>
        <p>${summarizeRotation(state.rotationSummary)}</p>
        ${state.uiMessage ? `<p class="status-message ${state.uiMessageTone === 'error' ? 'error' : 'info'}">${state.uiMessage}</p>` : ''}
        <ol class="log-list">
          ${latestLogs.length === 0 ? '<li>No simulation run yet.</li>' : latestLogs.map((log) => `<li><strong>${log.action}</strong> — ${log.notes}</li>`).join('')}
        </ol>
      </div>
    </section>
  `;
}

function renderPrayerWarriorsExhibit(): string {
  return `
    <section class="panel" id="prayer-warriors" aria-labelledby="prayer-warriors-title">
      <div class="panel-head">
        <h2 id="prayer-warriors-title">Exhibit 5: PrayerWarriors.Mobi Migration Plan</h2>
        <p>Designing a new platform in 2026: build crypto-agility now, avoid a retrofit crisis in 2030.</p>
      </div>
      <div class="card">
        <h3>Recommended Architecture</h3>
        <ul>
          <li>TLS 1.3 with X25519MLKEM768 hybrid KEM for client-server sessions.</li>
          <li>Hybrid certificates (ECDSA-P256 + ML-DSA-65) from day 1 for edge services.</li>
          <li>JWT and service signatures on ML-DSA-65 where ecosystem compatibility allows.</li>
          <li>Symmetric data protection with AES-256-GCM for prayer content and backups.</li>
          <li>90-day key rotation with documented rollback runbooks and canary rollout.</li>
        </ul>
      </div>
      <div class="metrics">
        <div><span>Day-1 PQ-aware build cost</span><strong>+15% engineering effort</strong></div>
        <div><span>Retrofit later</span><strong>+60% effort, outage risk</strong></div>
        <div><span>Migration strategy</span><strong>Hybrid then pure PQ</strong></div>
        <div><span>Target posture</span><strong>Crypto-agile by design</strong></div>
      </div>
      <div class="links">
        <a href="https://github.com/systemslibrarian/crypto-lab-pq-tls-handshake" target="_blank" rel="noreferrer">crypto-lab-pq-tls-handshake</a>
        <a href="https://github.com/systemslibrarian/crypto-lab-kyber-vault" target="_blank" rel="noreferrer">crypto-lab-kyber-vault</a>
        <a href="https://github.com/systemslibrarian/crypto-lab-dilithium-seal" target="_blank" rel="noreferrer">crypto-lab-dilithium-seal</a>
        <a href="https://github.com/systemslibrarian/crypto-lab-hybrid-sign" target="_blank" rel="noreferrer">crypto-lab-hybrid-sign</a>
      </div>
    </section>
  `;
}

function renderDashboard(): void {
  const demo = getSelectedDemo();
  const framework = getSelectedFramework();
  const riskRows = demo.items.map((item) => ({
    item,
    risk: computeHNDLRisk(item, 2033, new Date()),
  }));

  const highestPriority = [...demo.items]
    .sort((left, right) => computePriorityScore(right) - computePriorityScore(left))
    .slice(0, 3)
    .map((item) => item.systemName)
    .join(', ');

  const root = document.querySelector<HTMLDivElement>('#app');
  if (!root) {
    throw new Error('Missing #app container.');
  }

  root.innerHTML = `
    <a class="skip-link" href="#inventory">Skip to first exhibit</a>
    <main class="dashboard" id="main-content" tabindex="-1">
      <header class="hero">
        <p class="kicker">Post-Quantum Migration Planner</p>
        <h1>Operational PQC Migration, Not A One-Day Swap</h1>
        <p class="subtitle">Plan inventory, hybrid rollout, and key rotation against CNSA 2.0 and allied roadmap milestones.</p>
        <div class="hero-tags">
          <span>CNSA 2.0 (2025, Jan 2027, 2030, 2035)</span>
          <span>EU NIS, UK NCSC, Canada CCCS, Germany BSI, Australia ASD</span>
          <span>Top current priorities: ${highestPriority}</span>
        </div>
      </header>
      ${renderInventoryExhibit(demo, riskRows)}
      ${renderTimelineExhibit(demo, framework)}
      ${renderCertificateExhibit()}
      ${renderRotationExhibit()}
      ${renderPrayerWarriorsExhibit()}
    </main>
  `;

  bindEvents();
}

function bindEvents(): void {
  document.querySelectorAll<HTMLButtonElement>('button[data-action="demo"]').forEach((button) => {
    button.addEventListener('click', () => {
      const next = button.dataset.demo as InventoryDemo['key'] | undefined;
      if (next) {
        state.selectedDemoKey = next;
        renderDashboard();
      }
    });
  });

  document.querySelectorAll<HTMLInputElement>('input[data-action="framework"]').forEach((radio) => {
    radio.addEventListener('change', () => {
      if (radio.checked) {
        state.selectedFrameworkName = radio.value as RegulatoryFramework['name'];
        renderDashboard();
      }
    });
  });

  document.querySelectorAll<HTMLButtonElement>('button[data-action="cert-view"]').forEach((button) => {
    button.addEventListener('click', () => {
      const next = button.dataset.view as 'classical' | 'hybrid' | 'pure_pq' | undefined;
      if (next) {
        state.certView = next;
        renderDashboard();
      }
    });
  });

  const runButton = document.querySelector<HTMLButtonElement>('button[data-action="run-rotation"]');
  if (runButton) {
    runButton.addEventListener('click', async () => {
      runButton.disabled = true;
      runButton.textContent = 'Running...';
      state.uiMessage = '';
      state.uiMessageTone = 'info';

      const canary = Number((document.querySelector<HTMLInputElement>('#canaryPercent')?.value ?? '10').trim());
      const monitoringHours = Number((document.querySelector<HTMLInputElement>('#monitorHours')?.value ?? '24').trim());
      const stageText = document.querySelector<HTMLInputElement>('#rolloutStages')?.value ?? '10,50,100';
      const stageValues = stageText
        .split(',')
        .map((part) => Number(part.trim()))
        .filter((value) => Number.isFinite(value) && value > 0 && value <= 100);
      const failureStep = document.querySelector<HTMLSelectElement>('#failureStep')?.value ?? 'none';

      try {
        state.rotationLogs = [];
        const runResult = await simulateRotation(
          createFleet(1247),
          {
            canaryPercent: Number.isFinite(canary) ? canary : 10,
            monitoringHours: Number.isFinite(monitoringHours) ? monitoringHours : 24,
            rolloutPercentages: stageValues.length > 0 ? stageValues : [10, 50, 100],
            failureInjection:
              failureStep === 'none'
                ? { injectFailure: false }
                : { injectFailure: true, atStep: failureStep, severity: 'major' },
          },
          (step) => state.rotationLogs.push(step),
        );

        state.rotationSummary = runResult;
        state.rotationServers = runResult.finalState;
        state.uiMessage = runResult.success
          ? 'Rotation completed with phase gates satisfied.'
          : 'Rotation failed a phase gate and rolled back safely.';
        state.uiMessageTone = runResult.success ? 'info' : 'error';
      } catch {
        state.uiMessage = 'Simulation failed unexpectedly. Inputs were preserved so you can retry safely.';
        state.uiMessageTone = 'error';
      } finally {
        runButton.disabled = false;
        runButton.textContent = 'Run Rotation';
        renderDashboard();
      }
    });
  }
}

async function bootstrap(): Promise<void> {
  try {
    await generateCertificateDemo();
  } catch {
    state.uiMessage = 'Certificate demo failed to initialize. Refresh to retry generation.';
    state.uiMessageTone = 'error';
  }
  renderDashboard();
}

void bootstrap();
