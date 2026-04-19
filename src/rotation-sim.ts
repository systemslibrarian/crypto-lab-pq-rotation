import { p256 } from '@noble/curves/nist.js';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';

import { issueHybridCertificate, type HybridCertificate } from './hybrid-cert.ts';

export interface ServerState {
  id: string;
  location: string;
  currentCertificate: HybridCertificate | null;
  status: 'classical_only' | 'hybrid_dual_signed' | 'pq_only' | 'rotating';
  lastRotation: Date;
  tlsVersion: '1.2' | '1.3';
  supportsX25519MLKEM768: boolean;
  trafficPercent: number;
}

export interface RotationStep {
  timestamp: Date;
  action: 'issue_new_cert' | 'deploy_to_canary' | 'promote_canary' | 'rotate_fleet' | 'retire_old_cert' | 'monitor' | 'rollback';
  affectedServers: string[];
  success: boolean;
  notes: string;
}

interface RotationConfig {
  canaryPercent: number;
  monitoringHours: number;
  rolloutPercentages: number[];
  failureInjection: {
    injectFailure: boolean;
    atStep?: string;
    severity?: 'minor' | 'major' | 'critical';
  };
}

function randomBytes(length: number): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(length));
}

function cloneCertificate(cert: HybridCertificate | null): HybridCertificate | null {
  if (!cert) {
    return null;
  }

  return {
    ...cert,
    body: {
      ...cert.body,
      validFrom: new Date(cert.body.validFrom),
      validTo: new Date(cert.body.validTo),
      publicKey: cert.body.publicKey.slice(),
    },
    classicalSignature: cert.classicalSignature.slice(),
    pqSignature: cert.pqSignature.slice(),
    bodyHash: cert.bodyHash.slice(),
  };
}

function cloneServers(servers: ServerState[]): ServerState[] {
  return servers.map((server) => ({
    ...server,
    currentCertificate: cloneCertificate(server.currentCertificate),
    lastRotation: new Date(server.lastRotation),
  }));
}

function shouldFail(config: RotationConfig, stepKey: string): boolean {
  return config.failureInjection.injectFailure && config.failureInjection.atStep === stepKey;
}

function chooseTargetServers(servers: ServerState[], percent: number): ServerState[] {
  const targetCount = Math.max(1, Math.ceil((servers.length * percent) / 100));
  return [...servers]
    .sort((left, right) => right.trafficPercent - left.trafficPercent || left.id.localeCompare(right.id))
    .slice(0, targetCount);
}

async function createHybridCertificateForServer(server: ServerState, caClassicalKey: Uint8Array, caPQKey: Uint8Array): Promise<HybridCertificate> {
  const classicalKeys = p256.keygen();
  const pqKeys = ml_dsa65.keygen(randomBytes(32));
  const subjectPublicKey = new Uint8Array(classicalKeys.publicKey.length + pqKeys.publicKey.length);
  subjectPublicKey.set(classicalKeys.publicKey, 0);
  subjectPublicKey.set(pqKeys.publicKey, classicalKeys.publicKey.length);

  return issueHybridCertificate(
    `CN=${server.id}.${server.location}.pqc.example`,
    caClassicalKey,
    caPQKey,
    subjectPublicKey,
  );
}

function emitStep(step: RotationStep, onStep?: (step: RotationStep) => void): RotationStep {
  onStep?.(step);
  return step;
}

function rollbackFleet(servers: ServerState[], originalServers: ServerState[]): void {
  const originalMap = new Map(originalServers.map((server) => [server.id, server]));
  for (const server of servers) {
    const original = originalMap.get(server.id);
    if (!original) {
      continue;
    }
    server.currentCertificate = cloneCertificate(original.currentCertificate);
    server.status = original.status;
    server.lastRotation = new Date(original.lastRotation);
  }
}

export async function simulateRotation(
  servers: ServerState[],
  config: RotationConfig,
  onStep?: (step: RotationStep) => void,
): Promise<{
  success: boolean;
  totalSteps: number;
  duration: number;
  rolledBack: boolean;
  finalState: ServerState[];
}> {
  const workingSet = cloneServers(servers);
  const originalSet = cloneServers(servers);
  const baseTime = new Date();
  const steps: RotationStep[] = [];
  let elapsedHours = 0;
  let rolledBack = false;
  let success = true;

  const caClassical = p256.keygen();
  const caPQ = ml_dsa65.keygen(randomBytes(32));
  const issuedCertificates = new Map<string, HybridCertificate>();

  for (const server of workingSet) {
    issuedCertificates.set(server.id, await createHybridCertificateForServer(server, caClassical.secretKey, caPQ.secretKey));
  }

  steps.push(
    emitStep(
      {
        timestamp: new Date(baseTime.getTime() + elapsedHours * 60 * 60 * 1000),
        action: 'issue_new_cert',
        affectedServers: workingSet.map((server) => server.id),
        success: true,
        notes: `Issued ${workingSet.length} new hybrid certificates for staged rollout.`,
      },
      onStep,
    ),
  );
  elapsedHours += 1;

  const canaryCandidates = chooseTargetServers(workingSet, Math.max(config.canaryPercent, 1));
  const canary = canaryCandidates.slice(0, 1);
  for (const server of canary) {
    server.status = 'hybrid_dual_signed';
    server.currentCertificate = cloneCertificate(issuedCertificates.get(server.id) ?? null);
    server.lastRotation = new Date(baseTime.getTime() + elapsedHours * 60 * 60 * 1000);
  }

  steps.push(
    emitStep(
      {
        timestamp: new Date(baseTime.getTime() + elapsedHours * 60 * 60 * 1000),
        action: 'deploy_to_canary',
        affectedServers: canary.map((server) => server.id),
        success: !shouldFail(config, 'deploy_to_canary'),
        notes: `Deployed hybrid certificate to exactly ${canary.length} canary server.`,
      },
      onStep,
    ),
  );
  elapsedHours += 1;

  if (shouldFail(config, 'deploy_to_canary')) {
    success = false;
  }

  if (success) {
    steps.push(
      emitStep(
        {
          timestamp: new Date(baseTime.getTime() + elapsedHours * 60 * 60 * 1000),
          action: 'monitor',
          affectedServers: canary.map((server) => server.id),
          success: !shouldFail(config, 'monitor_canary'),
          notes: `Observed the canary for ${config.monitoringHours} simulated hour(s) before promotion.`,
        },
        onStep,
      ),
    );
    elapsedHours += config.monitoringHours;
    if (shouldFail(config, 'monitor_canary')) {
      success = false;
    }
  }

  if (success) {
    steps.push(
      emitStep(
        {
          timestamp: new Date(baseTime.getTime() + elapsedHours * 60 * 60 * 1000),
          action: 'promote_canary',
          affectedServers: canary.map((server) => server.id),
          success: true,
          notes: 'Promoted canary evidence and opened the phased fleet rollout.',
        },
        onStep,
      ),
    );
    elapsedHours += 0.25;
  }

  for (const percent of config.rolloutPercentages) {
    if (!success) {
      break;
    }

    const stageKey = `rotate_${percent}`;
    const targetServers = chooseTargetServers(workingSet, percent);
    for (const server of targetServers) {
      server.status = 'hybrid_dual_signed';
      server.currentCertificate = cloneCertificate(issuedCertificates.get(server.id) ?? null);
      server.lastRotation = new Date(baseTime.getTime() + elapsedHours * 60 * 60 * 1000);
    }

    const rolloutFailed = shouldFail(config, stageKey);
    steps.push(
      emitStep(
        {
          timestamp: new Date(baseTime.getTime() + elapsedHours * 60 * 60 * 1000),
          action: 'rotate_fleet',
          affectedServers: targetServers.map((server) => server.id),
          success: !rolloutFailed,
          notes: rolloutFailed
            ? `Injected ${config.failureInjection.severity ?? 'major'} failure during ${percent}% rollout.`
            : `Rolled hybrid certificates to the ${percent}% fleet stage.`,
        },
        onStep,
      ),
    );
    elapsedHours += 1;

    if (rolloutFailed) {
      success = false;
      break;
    }

    const monitorFailed = shouldFail(config, `monitor_${percent}`);
    const monitorHours = config.monitoringHours * 2;
    steps.push(
      emitStep(
        {
          timestamp: new Date(baseTime.getTime() + elapsedHours * 60 * 60 * 1000),
          action: 'monitor',
          affectedServers: targetServers.map((server) => server.id),
          success: !monitorFailed,
          notes: `Observed ${percent}% rollout for ${monitorHours} simulated hour(s).`,
        },
        onStep,
      ),
    );
    elapsedHours += monitorHours;

    if (monitorFailed) {
      success = false;
      break;
    }
  }

  if (success) {
    steps.push(
      emitStep(
        {
          timestamp: new Date(baseTime.getTime() + elapsedHours * 60 * 60 * 1000),
          action: 'retire_old_cert',
          affectedServers: workingSet.map((server) => server.id),
          success: !shouldFail(config, 'retire_old_cert'),
          notes: 'Retired the classical-only certificate pool after the hybrid grace period.',
        },
        onStep,
      ),
    );
    elapsedHours += 1;
    if (shouldFail(config, 'retire_old_cert')) {
      success = false;
    }
  }

  if (!success) {
    rollbackFleet(workingSet, originalSet);
    rolledBack = true;
    steps.push(
      emitStep(
        {
          timestamp: new Date(baseTime.getTime() + elapsedHours * 60 * 60 * 1000),
          action: 'rollback',
          affectedServers: workingSet.map((server) => server.id),
          success: true,
          notes: 'Rollback completed automatically after the failed phase gate.',
        },
        onStep,
      ),
    );
    elapsedHours += config.failureInjection.severity === 'critical' ? 0.25 : 0.1;
  }

  return {
    success,
    totalSteps: steps.length,
    duration: Number(elapsedHours.toFixed(2)),
    rolledBack,
    finalState: workingSet,
  };
}

export function fleetReadinessScore(servers: ServerState[]): {
  classicalOnly: number;
  hybrid: number;
  pqOnly: number;
  totalTrafficOnHybridOrPQ: number;
  readinessPercent: number;
} {
  const totalServers = Math.max(servers.length, 1);
  const classicalOnly = servers.filter((server) => server.status === 'classical_only').length;
  const hybrid = servers.filter((server) => server.status === 'hybrid_dual_signed').length;
  const pqOnly = servers.filter((server) => server.status === 'pq_only').length;
  const totalTrafficOnHybridOrPQ = Number(
    servers
      .filter((server) => server.status === 'hybrid_dual_signed' || server.status === 'pq_only')
      .reduce((sum, server) => sum + server.trafficPercent, 0)
      .toFixed(1),
  );

  return {
    classicalOnly,
    hybrid,
    pqOnly,
    totalTrafficOnHybridOrPQ,
    readinessPercent: Number((((hybrid + pqOnly) / totalServers) * 100).toFixed(1)),
  };
}

export async function runRotationSimulationChecks(): Promise<{
  completesAllPhases: boolean;
  failureTriggersRollback: boolean;
  readinessScoreUpdates: boolean;
  timingRespectsMonitoringWindows: boolean;
  canaryAffectsSingleServer: boolean;
}> {
  const sampleServers: ServerState[] = Array.from({ length: 10 }, (_, index) => ({
    id: `server-${index + 1}`,
    location: ['us-east-1', 'us-west-2', 'eu-west-2', 'ap-southeast-2', 'ca-central-1'][index % 5] ?? 'us-east-1',
    currentCertificate: null,
    status: 'classical_only',
    lastRotation: new Date('2026-01-01T00:00:00.000Z'),
    tlsVersion: '1.3',
    supportsX25519MLKEM768: index < 8,
    trafficPercent: index === 0 ? 18 : 9.1,
  }));

  const observedSteps: RotationStep[] = [];
  const successRun = await simulateRotation(
    sampleServers,
    {
      canaryPercent: 10,
      monitoringHours: 24,
      rolloutPercentages: [10, 50, 100],
      failureInjection: {
        injectFailure: false,
      },
    },
    (step) => observedSteps.push(step),
  );

  const failureRun = await simulateRotation(sampleServers, {
    canaryPercent: 10,
    monitoringHours: 24,
    rolloutPercentages: [10, 50, 100],
    failureInjection: {
      injectFailure: true,
      atStep: 'rotate_10',
      severity: 'major',
    },
  });

  const readiness = fleetReadinessScore(successRun.finalState);
  const canaryStep = observedSteps.find((step) => step.action === 'deploy_to_canary');

  return {
    completesAllPhases: successRun.success && !successRun.rolledBack && successRun.finalState.every((server) => server.status === 'hybrid_dual_signed'),
    failureTriggersRollback: !failureRun.success && failureRun.rolledBack && failureRun.finalState.every((server) => server.status === 'classical_only'),
    readinessScoreUpdates: readiness.hybrid === sampleServers.length && readiness.totalTrafficOnHybridOrPQ > 0,
    timingRespectsMonitoringWindows: successRun.duration >= 171,
    canaryAffectsSingleServer: (canaryStep?.affectedServers.length ?? 0) === 1,
  };
}