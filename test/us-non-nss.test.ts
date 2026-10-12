import { describe, it, expect } from 'vitest';
import { federalPolicyTarget, planSubmissionDate, US_FEDERAL_SOURCES } from '../src/us-non-nss';
describe('scoped US federal non-NSS policy', () => {
 it('separates key establishment and digital signature targets', () => {
  expect(federalPolicyTarget('prioritized_non_nss','key_establishment').deadline).toBe('2030-12-31');
  expect(federalPolicyTarget('prioritized_non_nss','digital_signature').deadline).toBe('2031-12-31');
 });
 it('does not assign prioritized non-NSS deadlines to NSS, private or unspecified remaining systems', () => {
  for (const scope of ['nss','outside_federal','other_non_nss'] as const) {
   for (const use of ['key_establishment','digital_signature'] as const) expect(federalPolicyTarget(scope,use).deadline).toBeNull();
  }
  expect(federalPolicyTarget('nss','key_establishment').note).toContain('CNSA');
  expect(federalPolicyTarget('outside_federal','key_establishment').note).toContain('proposed FAR');
 });
 it('calculates the relative plan date and preserves source status distinctions', () => {
  expect(planSubmissionDate()).toBe('2026-10-22');
  expect(US_FEDERAL_SOURCES.eoStatus).toBe('issued-executive-order');
  expect(US_FEDERAL_SOURCES.ir8547Status).toBe('initial-public-draft');
  expect(US_FEDERAL_SOURCES.farStatus).toBe('direction-to-publish-proposed-rules');
 });
});
