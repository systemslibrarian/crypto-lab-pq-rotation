import { describe, it, expect } from 'vitest';

import {
  evaluateMosca,
  computePriorityScore,
  computeHNDLRisk,
  generateMigrationPlan,
  runTimelineEngineChecks,
  CNSA_2_0,
  EU_NIS,
  UK_NCSC,
  AUSTRALIA_ASD,
  GERMANY_BSI,
  CANADA_CCCS,
  type CryptoInventoryItem,
} from '../src/timeline-engine.ts';

const rootCa: CryptoInventoryItem = {
  id: 'root-1',
  systemName: 'Agency Root CA',
  type: 'pki_root_ca',
  currentAlgorithm: 'RSA-4096',
  dataSensitivityYears: 100,
  cryptoAgility: 'requires_replacement',
  vendorPQRoadmap: 'unknown',
  environmentTag: 'production',
};

const devSandbox: CryptoInventoryItem = {
  id: 'dev-1',
  systemName: 'Developer Sandbox',
  type: 'tls_endpoint',
  currentAlgorithm: 'AES-256', // symmetric, not the asymmetric PQ driver
  dataSensitivityYears: 1,
  cryptoAgility: 'native',
  vendorPQRoadmap: 'committed',
  environmentTag: 'development',
};

const today = new Date(Date.UTC(2026, 0, 1));

describe("Mosca's inequality (X + Y > Z)", () => {
  it('flags long-lived quantum-vulnerable data as exposed', () => {
    const result = evaluateMosca(rootCa, 2033, 5, today);
    // X=100, Y=5, Z=7 -> margin 98 > 0 -> exposed.
    expect(result.vulnerable).toBe(true);
    expect(result.yearsToCrqc).toBe(7);
    expect(result.marginYears).toBe(98);
    expect(result.exposed).toBe(true);
  });

  it('does not flag short-lived data when CRQC is far off', () => {
    const shortLived: CryptoInventoryItem = { ...rootCa, dataSensitivityYears: 1 };
    // X=1, Y=1, Z=14 -> margin -12 -> safe buffer.
    const result = evaluateMosca(shortLived, 2040, 1, today);
    expect(result.exposed).toBe(false);
    expect(result.marginYears).toBeLessThan(0);
  });

  it('never marks symmetric-only crypto as quantum-vulnerable', () => {
    const result = evaluateMosca(devSandbox, 2030, 2, today);
    expect(result.vulnerable).toBe(false);
    expect(result.exposed).toBe(false);
  });
});

describe('priority scoring', () => {
  it('ranks a quantum-vulnerable production root CA above a symmetric dev sandbox', () => {
    expect(computePriorityScore(rootCa)).toBeGreaterThan(computePriorityScore(devSandbox));
  });

  it('penalizes non-vulnerable algorithms relative to vulnerable ones', () => {
    const vulnerable: CryptoInventoryItem = { ...devSandbox, currentAlgorithm: 'ECDSA-P256' };
    expect(computePriorityScore(vulnerable)).toBeGreaterThan(computePriorityScore(devSandbox));
  });
});

describe('HNDL risk', () => {
  it('marks a long-retention root CA as critical', () => {
    const risk = computeHNDLRisk(rootCa, 2033, today);
    expect(risk.atRisk).toBe(true);
    expect(risk.riskLevel).toBe('critical');
    expect(risk.yearsOfExposure).toBeGreaterThan(0);
  });

  it('does not flag symmetric crypto', () => {
    const risk = computeHNDLRisk(devSandbox, 2033, today);
    expect(risk.atRisk).toBe(false);
    expect(risk.riskLevel).toBe('low');
  });
});

describe('migration plan generation', () => {
  const inventory: CryptoInventoryItem[] = [
    rootCa,
    {
      id: 'issuing-1',
      systemName: 'Issuing CA',
      type: 'pki_issuing_ca',
      currentAlgorithm: 'ECDSA-P256',
      dataSensitivityYears: 10,
      cryptoAgility: 'requires_replacement',
      vendorPQRoadmap: 'unknown',
      environmentTag: 'production',
    },
    devSandbox,
  ];

  it('covers every inventory item across five phases', () => {
    const plan = generateMigrationPlan(inventory, CNSA_2_0, today);
    expect(new Set(plan.map((a) => a.itemId)).size).toBe(inventory.length);
    for (const item of inventory) {
      const phases = plan.filter((a) => a.itemId === item.id).map((a) => a.phase);
      expect(phases.sort()).toEqual([1, 2, 3, 4, 5]);
    }
  });

  it('makes the issuing CA depend on the root CA', () => {
    const plan = generateMigrationPlan(inventory, CNSA_2_0, today);
    const issuing = plan.filter((a) => a.itemId === 'issuing-1');
    expect(issuing.length).toBeGreaterThan(0);
    expect(issuing.every((a) => a.dependencies.includes('root-1'))).toBe(true);
  });

  it('throws if a framework is missing a required milestone category', () => {
    const broken = { name: 'CNSA_2.0' as const, milestones: CNSA_2_0.milestones.slice(0, 2) };
    expect(() => generateMigrationPlan(inventory, broken, today)).toThrow(/milestone/i);
  });
});

describe('regulatory frameworks', () => {
  it('all six frameworks carry the four milestone categories', () => {
    const frameworks = [CNSA_2_0, EU_NIS, UK_NCSC, AUSTRALIA_ASD, GERMANY_BSI, CANADA_CCCS];
    for (const framework of frameworks) {
      const categories = new Set(framework.milestones.map((m) => m.category));
      expect(categories.has('planning')).toBe(true);
      expect(categories.has('pilot')).toBe(true);
      expect(categories.has('high_risk')).toBe(true);
      expect(categories.has('full_migration')).toBe(true);
    }
  });
});

describe('in-app timeline self-test suite', () => {
  it('runTimelineEngineChecks reports every property held', async () => {
    const checks = await runTimelineEngineChecks();
    expect(checks).toEqual({
      priorityOrderingCorrect: true,
      planCoversAllInventory: true,
      dependenciesRespected: true,
      hndlFlagsLongLivedData: true,
      allFrameworksPresent: true,
    });
  });
});
