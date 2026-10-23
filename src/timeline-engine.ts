/**
 * Migration timeline calculator for any organization.
 * Takes inventory and priorities, produces a phased roadmap
 * using scoped policy/guidance profiles and explicit planner assumptions.
 */

export interface CryptoInventoryItem {
  id: string;
  systemName: string;
  type:
    | 'tls_endpoint'
    | 'code_signing'
    | 'firmware_signing'
    | 'pki_root_ca'
    | 'pki_intermediate_ca'
    | 'pki_issuing_ca'
    | 'vpn'
    | 'database_tde'
    | 'jwt'
    | 'email_smime'
    | 'iot_attestation'
    | 'backup'
    | 'ssh';
  currentAlgorithm: string;
  /** Explicit key-establishment or public-key encryption protecting stored/recorded ciphertext.
   * A signature or authentication algorithm alone does not establish HNDL exposure. */
  confidentialityAlgorithm?: string;
  dataSensitivityYears: number;
  cryptoAgility: 'native' | 'requires_redeploy' | 'requires_replacement';
  vendorPQRoadmap: 'committed' | 'in_progress' | 'unknown' | 'none';
  environmentTag: 'production' | 'staging' | 'development' | 'legacy';
}

export interface RegulatoryFramework {
  name: 'CNSA_2.0' | 'EU_NIS' | 'UK_NCSC' | 'Australia_ASD' | 'Germany_BSI' | 'Canada_CCCS';
  scope?: string;
  officialMilestones?: readonly { date: string; normalizedDate: string; wording: string; sourceUrl: string; sourceVersion: string; audience: string; status: 'guidance' | 'policy'; precision: 'year' | 'month' | 'day' }[];
  milestones: Array<{
    date: Date;
    description: string;
    category: 'planning' | 'pilot' | 'high_risk' | 'full_migration';
    provenance?: 'guidance' | 'policy' | 'model_choice';
    sourceUrl?: string;
    sourceVersion?: string;
    audience?: string;
    datePrecision?: 'year' | 'month' | 'day';
    sourceWording?: string;
  }>;
}

export interface MigrationAction {
  itemId: string;
  phase: 1 | 2 | 3 | 4 | 5;
  phaseName: string;
  plannedDate: Date;
  dependencies: string[];
  estimatedEffort: 'low' | 'medium' | 'high' | 'very_high';
  risk: 'low' | 'medium' | 'high';
  notes: string;
}

type RiskLevel = 'low' | 'medium' | 'high' | 'critical';

const PHASE_NAMES: Record<MigrationAction['phase'], string> = {
  1: 'Inventory',
  2: 'Risk Assessment',
  3: 'Crypto-Agility',
  4: 'Hybrid Deployment',
  5: 'Pure PQC & Compliance',
};

const TYPE_PRIORITY: Record<CryptoInventoryItem['type'], number> = {
  pki_root_ca: 100,
  firmware_signing: 96,
  pki_intermediate_ca: 90,
  pki_issuing_ca: 84,
  code_signing: 78,
  tls_endpoint: 74,
  vpn: 68,
  email_smime: 62,
  iot_attestation: 61,
  jwt: 55,
  ssh: 42,
  backup: 36,
  database_tde: 18,
};

const ENVIRONMENT_PRIORITY: Record<CryptoInventoryItem['environmentTag'], number> = {
  production: 18,
  legacy: 14,
  staging: 6,
  development: 0,
};

const AGILITY_PRIORITY: Record<CryptoInventoryItem['cryptoAgility'], number> = {
  native: 0,
  requires_redeploy: 9,
  requires_replacement: 18,
};

const VENDOR_PRIORITY: Record<CryptoInventoryItem['vendorPQRoadmap'], number> = {
  committed: 0,
  in_progress: 4,
  unknown: 8,
  none: 14,
};

function utcDate(year: number, month: number, day: number): Date {
  return new Date(Date.UTC(year, month - 1, day));
}

function clamp(value: number, min: number, max: number): number {
  return Math.min(max, Math.max(min, value));
}

function midpoint(start: Date, end: Date, ratio: number): Date {
  const clamped = clamp(ratio, 0, 1);
  return new Date(start.getTime() + (end.getTime() - start.getTime()) * clamped);
}

function algorithmIsQuantumVulnerable(algorithm: string): boolean {
  const normalized = algorithm.toLowerCase();
  return ['rsa', 'ecdsa', 'ecdh', 'ed25519', 'x25519', 'dsa', 'dh'].some((value) => normalized.includes(value));
}

function milestoneFor(framework: RegulatoryFramework, category: RegulatoryFramework['milestones'][number]['category']): Date {
  const milestone = framework.milestones.find((item) => item.category === category);
  if (!milestone) {
    throw new Error(`Missing ${category} milestone for ${framework.name}`);
  }
  return milestone.date;
}

function inferEstimatedEffort(item: CryptoInventoryItem): MigrationAction['estimatedEffort'] {
  if (item.type === 'pki_root_ca' || item.cryptoAgility === 'requires_replacement') {
    return 'very_high';
  }
  if (item.type === 'pki_intermediate_ca' || item.type === 'firmware_signing') {
    return 'high';
  }
  if (item.cryptoAgility === 'requires_redeploy' || item.environmentTag === 'production') {
    return 'medium';
  }
  return 'low';
}

function inferDependencies(item: CryptoInventoryItem, inventory: CryptoInventoryItem[]): string[] {
  if (item.type === 'pki_intermediate_ca') {
    return inventory.filter((candidate) => candidate.type === 'pki_root_ca').map((candidate) => candidate.id);
  }
  if (item.type === 'pki_issuing_ca') {
    return inventory
      .filter((candidate) => candidate.type === 'pki_root_ca' || candidate.type === 'pki_intermediate_ca')
      .map((candidate) => candidate.id);
  }
  return [];
}

function phaseNotes(item: CryptoInventoryItem, phase: MigrationAction['phase'], framework: RegulatoryFramework): string {
  const frameworkLabel = framework.name.replaceAll('_', ' ');
  const notes: Record<MigrationAction['phase'], string> = {
    1: `Catalog ${item.systemName}, record ${item.currentAlgorithm}, and document key custody before ${frameworkLabel} planning checkpoints.`,
    2: `Prioritize ${item.systemName} based on data lifetime, quantum exposure, and operational blast radius.`,
    3: `Add crypto-agile controls for ${item.systemName}, including abstraction layers, vendor readiness, and rollback playbooks.`,
    4: `Deploy hybrid classical+PQC support for ${item.systemName} and monitor interoperability before broad rollout.`,
    5: `Retire classical-only dependencies for ${item.systemName} and retain crypto-agility for the next algorithm refresh.`,
  };
  return notes[phase];
}

export const CNSA_2_0: RegulatoryFramework = {
  name: 'CNSA_2.0',
  milestones: [
    {
      date: utcDate(2025, 1, 1),
      description: 'NSS software/firmware signing, web servers and cloud services support and prefer CNSA 2.0.',
      category: 'planning',
    },
    {
      date: utcDate(2030, 1, 1),
      description: 'Software and firmware signing for NSS must use CNSA 2.0 exclusively.',
      category: 'pilot',
    },
    {
      date: utcDate(2033, 1, 1),
      description: 'Web browsers, servers and cloud services handling NSS data must use CNSA 2.0 exclusively.',
      category: 'high_risk',
    },
    {
      date: utcDate(2035, 12, 31),
      description: 'All legacy NSS asymmetric cryptography should be migrated.',
      category: 'full_migration',
    },
  ],
};

export const EU_NIS: RegulatoryFramework = {
  name: 'EU_NIS',
  milestones: [
    {
      date: utcDate(2026, 12, 31),
      description: 'Member states and critical entities should have initial PQ transition roadmaps.',
      category: 'planning',
    },
    {
      date: utcDate(2028, 12, 31),
      description: 'Pilot hybrid deployments for critical services and trust services.',
      category: 'pilot',
    },
    {
      date: utcDate(2030, 12, 31),
      description: 'High-risk and long-lifetime use cases should be migrated.',
      category: 'high_risk',
    },
    {
      date: utcDate(2035, 12, 31),
      description: 'Full transition target for critical sectors and public administration.',
      category: 'full_migration',
    },
  ],
};

export const UK_NCSC: RegulatoryFramework = {
  name: 'UK_NCSC',
  milestones: [
    {
      date: utcDate(2028, 12, 31),
      description: 'Complete discovery and dependency mapping for quantum-vulnerable cryptography.',
      category: 'planning',
    },
    {
      date: utcDate(2030, 6, 30),
      description: 'Run prioritized hybrid pilots for critical services and supporting suppliers.',
      category: 'pilot',
    },
    {
      date: utcDate(2031, 12, 31),
      description: 'Finish prioritized migration for the highest-risk services.',
      category: 'high_risk',
    },
    {
      date: utcDate(2035, 12, 31),
      description: 'Reach broad adoption across the remaining estate.',
      category: 'full_migration',
    },
  ],
};

export const AUSTRALIA_ASD: RegulatoryFramework = {
  name: 'Australia_ASD',
  milestones: [
    {
      date: utcDate(2026, 12, 31),
      description: 'ASD recommends a refined PQC transition plan by the end of 2026.',
      category: 'planning',
    },
    {
      date: utcDate(2028, 12, 31),
      description: 'ASD recommends transition has commenced by the end of 2028, starting with critical systems and data.',
      category: 'pilot',
    },
    {
      date: utcDate(2030, 12, 31),
      description: 'Illustrative high-risk sequencing checkpoint, aligned with ASD’s end-2030 completion recommendation.',
      category: 'high_risk',
    },
    {
      date: utcDate(2030, 12, 31),
      description: 'ASD recommends completion of PQC transition by the end of 2030.',
      category: 'full_migration',
    },
  ],
};

export const GERMANY_BSI: RegulatoryFramework = {
  name: 'Germany_BSI',
  milestones: [
    {
      date: utcDate(2024, 10, 15),
      description: 'BSI urges immediate inventory, crypto-agility planning, and transition preparation.',
      category: 'planning',
    },
    {
      date: utcDate(2027, 12, 31),
      description: 'Pilot hybrid certificate and key-establishment deployments in high-value environments.',
      category: 'pilot',
    },
    {
      date: utcDate(2030, 12, 31),
      description: 'Move high-protection and long-retention use cases onto quantum-safe controls.',
      category: 'high_risk',
    },
    {
      date: utcDate(2035, 12, 31),
      description: 'Complete broad transition in line with European quantum-safe planning horizons.',
      category: 'full_migration',
    },
  ],
};

export const CANADA_CCCS: RegulatoryFramework = {
  name: 'Canada_CCCS',
  milestones: [
    {
      date: utcDate(2026, 4, 30),
      description: 'Departments should produce initial migration plans and identify critical dependencies.',
      category: 'planning',
    },
    {
      date: utcDate(2028, 12, 31),
      description: 'Pilot hybrid deployments for departments handling sensitive or mission-critical data.',
      category: 'pilot',
    },
    {
      date: utcDate(2031, 12, 31),
      description: 'High-risk systems should complete migration.',
      category: 'high_risk',
    },
    {
      date: utcDate(2035, 12, 31),
      description: 'Complete migration target across the remaining estate.',
      category: 'full_migration',
    },
  ],
};

/** Source milestones use immutable date strings; editable planning dates are copies. */
const profiles = [CNSA_2_0, EU_NIS, UK_NCSC, AUSTRALIA_ASD, GERMANY_BSI, CANADA_CCCS];
const profileScope: Record<RegulatoryFramework['name'], string> = {
  'CNSA_2.0': 'US National Security Systems (NSS); not a general private-sector or non-NSS deadline. Dates below are this planner’s category mapping; verify product-specific CNSA requirements separately.',
  EU_NIS: 'EU / critical-service planning context. These dates are illustrative model choices; no legal-compliance finding is made.',
  UK_NCSC: 'UK NCSC guidance, primarily large organisations, critical infrastructure and bespoke IT; indicative migration horizons.',
  Australia_ASD: 'ASD recommended milestones for organisations applying the Australian ISM; guidance rather than a blanket private-sector law.',
  Germany_BSI: 'German / European planning context. These dates are illustrative model choices, not asserted BSI deadlines.',
  Canada_CCCS: 'Government of Canada federal departments and agencies, non-classified IT; not a blanket private-sector requirement.',
};
for (const profile of profiles) {
  profile.scope = profileScope[profile.name];
  for (const milestone of profile.milestones) {
    milestone.provenance = 'model_choice';
    milestone.audience = profile.scope;
    milestone.datePrecision = 'day';
  }
}
function attachGuidance(profile: RegulatoryFramework, url: string, version: string,
  entries: { category?: RegulatoryFramework['milestones'][number]['category']; date: string; normalizedDate: string; wording: string; precision: 'year' | 'month' }[]): void {
  profile.officialMilestones = Object.freeze(entries.map(entry => Object.freeze({
    ...entry, sourceUrl: url, sourceVersion: version, audience: profile.scope!, status: 'guidance' as const,
  })));
  for (const entry of entries) {
    if (!entry.category) continue;
    const milestone = profile.milestones.find(m => m.category === entry.category)!;
    Object.assign(milestone, { date: new Date(entry.normalizedDate + 'T00:00:00Z'),
      description: entry.wording, provenance: 'guidance', sourceUrl: url, sourceVersion: version,
      audience: profile.scope, datePrecision: entry.precision, sourceWording: entry.wording });
  }
}
attachGuidance(AUSTRALIA_ASD, 'https://www.cyber.gov.au/publication/planning-for-post-quantum-cryptography', 'Reviewed 22 September 2025', [
  { category: 'planning', date: 'By end of 2026', normalizedDate: '2026-12-31', wording: 'Refined plan for the transition to PQC.', precision: 'year' },
  { category: 'pilot', date: 'By end of 2028', normalizedDate: '2028-12-31', wording: 'Transition commenced, starting with critical systems and data (not a mandated hybrid pilot).', precision: 'year' },
  { category: 'full_migration', date: 'By end of 2030', normalizedDate: '2030-12-31', wording: 'PQC transition completed.', precision: 'year' },
]);
attachGuidance(CANADA_CCCS, 'https://www.cyber.gc.ca/en/guidance/roadmap-migration-post-quantum-cryptography-government-canada-itsm40001', 'ITSM.40.001, 23 June 2025', [
  { category: 'planning', date: 'April 2026', normalizedDate: '2026-04-30', wording: 'Initial departmental PQC migration plan.', precision: 'month' },
  { date: 'Beginning April 2026 and annually after', normalizedDate: '2026-04-30', wording: 'Report migration progress annually; not modeled as a one-time rollout phase.', precision: 'month' },
  { category: 'high_risk', date: 'End of 2031', normalizedDate: '2031-12-31', wording: 'Migration of high-priority systems complete.', precision: 'year' },
  { category: 'full_migration', date: 'End of 2035', normalizedDate: '2035-12-31', wording: 'Migration of remaining systems complete.', precision: 'year' },
]);
attachGuidance(UK_NCSC, 'https://www.ncsc.gov.uk/guidance/pqc-migration-timelines', '20 March 2025', [
  { category: 'planning', date: 'By 2028', normalizedDate: '2028-12-31', wording: 'Define goals, discover the estate and build an initial migration plan.', precision: 'year' },
  { category: 'high_risk', date: 'By 2031', normalizedDate: '2031-12-31', wording: 'Perform early highest-priority migration and refine the roadmap.', precision: 'year' },
  { category: 'full_migration', date: 'By 2035', normalizedDate: '2035-12-31', wording: 'Complete migration of systems, services and products.', precision: 'year' },
]);

/** Edit a planner assumption without changing source milestones. */
export function setModelMilestone(profile: RegulatoryFramework, category: RegulatoryFramework['milestones'][number]['category'], date: string): void {
  const milestone = profile.milestones.find(m => m.category === category);
  if (!milestone || milestone.provenance !== 'model_choice') throw new Error('Only model-choice milestones are editable');
  const value = new Date(date + 'T00:00:00Z');
  if (!Number.isFinite(value.getTime())) throw new Error('Invalid planner date');
  milestone.date = value;
}

export interface MoscaEvaluation {
  vulnerable: boolean; // the inventoried confidentiality algorithm is quantum-vulnerable
  shelfLifeYears: number; // X — how long the data must stay confidential
  migrationYears: number; // Y — how long migrating this system takes
  yearsToCrqc: number; // Z — years until a cryptographically relevant quantum computer
  exposed: boolean; // X + Y > Z -> migration planning threshold crossed for confidentiality
  marginYears: number; // (X + Y) - Z; positive means too late, negative means buffer
}

/**
 * Mosca's inequality. If the data's shelf life (X) plus the time to migrate (Y)
 * is greater than the time until a quantum computer can break the explicitly
 * inventoried key establishment/encryption (Z), the confidentiality migration
 * planning threshold has been crossed. This does not infer HNDL from a CA,
 * firmware signing, or authentication key, even if that key uses RSA/ECDSA.
 */
export function evaluateMosca(
  item: CryptoInventoryItem,
  crqcArrivalYear: number,
  migrationYears: number,
  today: Date = new Date(),
): MoscaEvaluation {
  const vulnerable = item.confidentialityAlgorithm !== undefined
    && algorithmIsQuantumVulnerable(item.confidentialityAlgorithm);
  const shelfLifeYears = item.dataSensitivityYears;
  const yearsToCrqc = Math.max(0, crqcArrivalYear - today.getUTCFullYear());
  const marginYears = shelfLifeYears + migrationYears - yearsToCrqc;

  return {
    vulnerable,
    shelfLifeYears,
    migrationYears,
    yearsToCrqc,
    exposed: vulnerable && marginYears > 0,
    marginYears,
  };
}

export function computePriorityScore(item: CryptoInventoryItem): number {
  const algorithmPenalty = algorithmIsQuantumVulnerable(item.currentAlgorithm) ? 12 : -10;
  const sensitivityWeight = Math.min(item.dataSensitivityYears, 30) * 1.4;

  return Number(
    (
      TYPE_PRIORITY[item.type] +
      ENVIRONMENT_PRIORITY[item.environmentTag] +
      AGILITY_PRIORITY[item.cryptoAgility] +
      VENDOR_PRIORITY[item.vendorPQRoadmap] +
      sensitivityWeight +
      algorithmPenalty
    ).toFixed(1),
  );
}

export function generateMigrationPlan(
  inventory: CryptoInventoryItem[],
  framework: RegulatoryFramework,
  startDate: Date = new Date(),
): MigrationAction[] {
  const ranked = [...inventory]
    .map((item) => ({ item, score: computePriorityScore(item) }))
    .sort((left, right) => right.score - left.score || left.item.id.localeCompare(right.item.id));

  const planning = milestoneFor(framework, 'planning');
  const pilot = milestoneFor(framework, 'pilot');
  const highRisk = milestoneFor(framework, 'high_risk');
  const fullMigration = milestoneFor(framework, 'full_migration');
  const total = Math.max(ranked.length - 1, 1);

  return ranked.flatMap(({ item }, index) => {
    const ratio = index / total;
    const dependencies = inferDependencies(item, inventory);
    const hndlRisk = computeHNDLRisk(item, 2033, startDate);
    const risk: MigrationAction['risk'] = hndlRisk.riskLevel === 'critical' ? 'high' : hndlRisk.riskLevel;
    const effort = inferEstimatedEffort(item);

    return [1, 2, 3, 4, 5].map((phaseNumber) => {
      const phase = phaseNumber as MigrationAction['phase'];
      const plannedDateByPhase: Record<MigrationAction['phase'], Date> = {
        1: midpoint(startDate, planning, ratio * 0.85),
        2: midpoint(planning, pilot, ratio * 0.75),
        3: midpoint(planning, highRisk, ratio),
        4: midpoint(pilot, highRisk, ratio),
        5: midpoint(highRisk, fullMigration, ratio),
      };

      return {
        itemId: item.id,
        phase,
        phaseName: PHASE_NAMES[phase],
        plannedDate: plannedDateByPhase[phase],
        dependencies,
        estimatedEffort: effort,
        risk,
        notes: phaseNotes(item, phase, framework),
      } satisfies MigrationAction;
    });
  });
}

export function computeHNDLRisk(
  item: CryptoInventoryItem,
  crqcArrivalYear: number = 2033,
  today: Date = new Date(),
): {
  atRisk: boolean;
  yearsOfExposure: number;
  riskLevel: RiskLevel;
  explanation: string;
} {
  if (!item.confidentialityAlgorithm) {
    return {
      atRisk: false,
      yearsOfExposure: 0,
      riskLevel: 'low',
      explanation: `${item.systemName} lists ${item.currentAlgorithm}, but no key-establishment or public-key encryption algorithm. Do not infer harvest-now exposure from a signing/authentication key; inventory confidentiality separately.`,
    };
  }
  if (!algorithmIsQuantumVulnerable(item.confidentialityAlgorithm)) {
    return {
      atRisk: false,
      yearsOfExposure: 0,
      riskLevel: 'low',
      explanation: `${item.systemName}'s inventoried confidentiality algorithm ${item.confidentialityAlgorithm} is not the immediate asymmetric HNDL migration driver here.`,
    };
  }

  const yearsUntilCrqc = Math.max(0, crqcArrivalYear - today.getUTCFullYear());
  const yearsOfExposure = Math.max(0, item.dataSensitivityYears - yearsUntilCrqc);
  const atRisk = yearsOfExposure > 0;

  let riskLevel: RiskLevel = 'low';
  if (yearsOfExposure >= 15) {
    riskLevel = 'critical';
  } else if (yearsOfExposure >= 8 || (atRisk && item.environmentTag === 'production')) {
    riskLevel = 'high';
  } else if (yearsOfExposure >= 3) {
    riskLevel = 'medium';
  }

  return {
    atRisk,
    yearsOfExposure,
    riskLevel,
    explanation: atRisk
      ? `${item.systemName} uses ${item.confidentialityAlgorithm} for confidentiality and its ${item.dataSensitivityYears}-year sensitivity window extends ${yearsOfExposure} year(s) past a ${crqcArrivalYear} CRQC scenario.`
      : `${item.systemName} uses ${item.confidentialityAlgorithm} for confidentiality, but its confidentiality window closes before a ${crqcArrivalYear} CRQC estimate.`,
  };
}

export async function runTimelineEngineChecks(): Promise<{
  priorityOrderingCorrect: boolean;
  planCoversAllInventory: boolean;
  dependenciesRespected: boolean;
  hndlFlagsLongLivedData: boolean;
  allFrameworksPresent: boolean;
}> {
  const inventory: CryptoInventoryItem[] = [
    {
      id: 'root-1',
      systemName: 'Agency Root CA',
      type: 'pki_root_ca',
      currentAlgorithm: 'RSA-4096',
      dataSensitivityYears: 100,
      cryptoAgility: 'requires_replacement',
      vendorPQRoadmap: 'unknown',
      environmentTag: 'production',
    },
    {
      id: 'fw-1',
      systemName: 'Field Device Firmware Signing',
      type: 'firmware_signing',
      currentAlgorithm: 'RSA-4096',
      dataSensitivityYears: 30,
      cryptoAgility: 'requires_redeploy',
      vendorPQRoadmap: 'in_progress',
      environmentTag: 'production',
    },
    {
      id: 'tls-1',
      systemName: 'Citizen Services TLS',
      type: 'tls_endpoint',
      currentAlgorithm: 'ECDSA-P256',
      confidentialityAlgorithm: 'X25519',
      dataSensitivityYears: 15,
      cryptoAgility: 'requires_redeploy',
      vendorPQRoadmap: 'committed',
      environmentTag: 'production',
    },
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
    {
      id: 'dev-1',
      systemName: 'Developer Sandbox',
      type: 'tls_endpoint',
      currentAlgorithm: 'ECDSA-P256',
      dataSensitivityYears: 1,
      cryptoAgility: 'native',
      vendorPQRoadmap: 'committed',
      environmentTag: 'development',
    },
  ];

  const frameworkSet = [CNSA_2_0, EU_NIS, UK_NCSC, AUSTRALIA_ASD, GERMANY_BSI, CANADA_CCCS];
  const priorityOrderingCorrect =
    computePriorityScore(inventory[1]) > computePriorityScore(inventory[2]) &&
    computePriorityScore(inventory[2]) > computePriorityScore(inventory[4]);
  const plan = generateMigrationPlan(inventory, CNSA_2_0, utcDate(2026, 1, 1));
  const planCoversAllInventory = new Set(plan.map((action) => action.itemId)).size === inventory.length;
  const issuingActions = plan.filter((action) => action.itemId === 'issuing-1');
  const dependenciesRespected = issuingActions.every((action) => action.dependencies.includes('root-1'));
  const rootSigning = computeHNDLRisk(inventory[0], 2033, utcDate(2026, 1, 1));
  const hndl = computeHNDLRisk(inventory[2], 2033, utcDate(2026, 1, 1));
  const hndlFlagsLongLivedData = !rootSigning.atRisk && hndl.atRisk && (hndl.riskLevel === 'critical' || hndl.riskLevel === 'high');
  const allFrameworksPresent = frameworkSet.every((framework) => framework.milestones.length >= 4);

  return {
    priorityOrderingCorrect,
    planCoversAllInventory,
    dependenciesRespected,
    hndlFlagsLongLivedData,
    allFrameworksPresent,
  };
}
