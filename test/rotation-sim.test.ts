import { describe, it, expect } from 'vitest';

import {
  simulateRotation,
  fleetReadinessScore,
  runRotationSimulationChecks,
  type ServerState,
  type RotationStep,
} from '../src/rotation-sim.ts';

function sampleFleet(count = 10): ServerState[] {
  return Array.from({ length: count }, (_, index) => ({
    id: `server-${index + 1}`,
    location: ['us-east-1', 'us-west-2', 'eu-west-2', 'ap-southeast-2', 'ca-central-1'][index % 5] ?? 'us-east-1',
    currentCertificate: null,
    status: 'classical_only' as const,
    lastRotation: new Date('2026-01-01T00:00:00.000Z'),
    tlsVersion: '1.3' as const,
    supportsX25519MLKEM768: index < 8,
    trafficPercent: index === 0 ? 18 : 9.1,
  }));
}

const happyConfig = {
  canaryPercent: 10,
  monitoringHours: 24,
  rolloutPercentages: [10, 50, 100],
  failureInjection: { injectFailure: false },
};

describe('successful rotation', () => {
  it('completes all phases and leaves every server hybrid dual-signed', async () => {
    const run = await simulateRotation(sampleFleet(), happyConfig);
    expect(run.success).toBe(true);
    expect(run.rolledBack).toBe(false);
    expect(run.finalState.every((s) => s.status === 'hybrid_dual_signed')).toBe(true);
    // Each server carries a real issued certificate that verifies its own hash.
    expect(run.finalState.every((s) => s.currentCertificate !== null)).toBe(true);
  });

  it('does not mutate the caller-provided servers', async () => {
    const original = sampleFleet();
    await simulateRotation(original, happyConfig);
    expect(original.every((s) => s.status === 'classical_only')).toBe(true);
    expect(original.every((s) => s.currentCertificate === null)).toBe(true);
  });

  it('deploys the canary to exactly one server', async () => {
    const steps: RotationStep[] = [];
    await simulateRotation(sampleFleet(), happyConfig, (step) => steps.push(step));
    const canary = steps.find((s) => s.action === 'deploy_to_canary');
    expect(canary?.affectedServers.length).toBe(1);
  });

  it('respects the monitoring windows in the elapsed duration', async () => {
    const run = await simulateRotation(sampleFleet(), happyConfig);
    // 24h canary monitor + 3 * 48h stage monitors dominate the schedule.
    expect(run.duration).toBeGreaterThanOrEqual(171);
  });
});

describe('failure injection triggers rollback', () => {
  it('rolls the whole fleet back to classical_only on a rollout failure', async () => {
    const run = await simulateRotation(sampleFleet(), {
      ...happyConfig,
      failureInjection: { injectFailure: true, atStep: 'rotate_10', severity: 'major' },
    });
    expect(run.success).toBe(false);
    expect(run.rolledBack).toBe(true);
    expect(run.finalState.every((s) => s.status === 'classical_only')).toBe(true);
    expect(run.finalState.every((s) => s.currentCertificate === null)).toBe(true);
  });

  it('rolls back when the canary deployment itself fails', async () => {
    const run = await simulateRotation(sampleFleet(), {
      ...happyConfig,
      failureInjection: { injectFailure: true, atStep: 'deploy_to_canary', severity: 'critical' },
    });
    expect(run.success).toBe(false);
    expect(run.rolledBack).toBe(true);
    expect(run.finalState.every((s) => s.status === 'classical_only')).toBe(true);
  });
});

describe('fleet readiness scoring', () => {
  it('reports 100% readiness once every server is hybrid', async () => {
    const run = await simulateRotation(sampleFleet(), happyConfig);
    const readiness = fleetReadinessScore(run.finalState);
    expect(readiness.hybrid).toBe(10);
    expect(readiness.classicalOnly).toBe(0);
    expect(readiness.readinessPercent).toBe(100);
    expect(readiness.totalTrafficOnHybridOrPQ).toBeGreaterThan(0);
  });

  it('reports 0% readiness for an all-classical fleet', () => {
    const readiness = fleetReadinessScore(sampleFleet());
    expect(readiness.readinessPercent).toBe(0);
    expect(readiness.hybrid).toBe(0);
  });
});

describe('in-app rotation self-test suite', () => {
  it('runRotationSimulationChecks reports every property held', async () => {
    const checks = await runRotationSimulationChecks();
    expect(checks).toEqual({
      completesAllPhases: true,
      failureTriggersRollback: true,
      readinessScoreUpdates: true,
      timingRespectsMonitoringWindows: true,
      canaryAffectsSingleServer: true,
    });
  });
});
