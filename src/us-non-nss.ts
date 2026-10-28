/** Source-policy classification, separate from this lab's illustrative phase planner. */
export type FederalScope = 'prioritized_non_nss' | 'other_non_nss' | 'nss' | 'outside_federal';
export type CryptoUse = 'key_establishment' | 'digital_signature';
export const US_FEDERAL_SOURCES = Object.freeze({
  eo: 'https://www.whitehouse.gov/presidential-actions/2026/06/securing-the-nation-against-advanced-cryptographic-attacks/',
  omb: 'https://www.whitehouse.gov/wp-content/uploads/2026/06/M-26-15-Execution-of-the-Migration-to-Post-Quantum-Cryptography.pdf',
  eoStatus: 'issued-executive-order', memorandumStatus: 'issued-memorandum',
  farStatus: 'direction-to-publish-proposed-rules', ir8547Status: 'final-report',
});
export function planSubmissionDate(): string {
  const date = new Date('2026-06-24T00:00:00Z');
  date.setUTCDate(date.getUTCDate() + 120);
  return date.toISOString().slice(0, 10);
}
export function federalPolicyTarget(scope: FederalScope, use: CryptoUse): { deadline: string | null; note: string } {
  if (use !== 'key_establishment' && use !== 'digital_signature') throw new Error('Unknown cryptographic use.');
  switch (scope) {
    case 'prioritized_non_nss': return { deadline: use === 'key_establishment' ? '2030-12-31' : '2031-12-31', note: 'US federal non-NSS HVA/high-impact and other OMB-prioritized systems. Key establishment and signature migration have different targets.' };
    case 'other_non_nss': return { deadline: null, note: 'OMB phases remaining non-NSS systems toward 2035, subject to risk and available offerings. That horizon is not automatically the HVA/high-impact deadline for this unspecified asset.' };
    case 'nss': return { deadline: null, note: 'OMB M-26-15 excludes National Security Systems. Use the product-specific CNSA/NSS requirements, not these OMB targets.' };
    case 'outside_federal': return { deadline: null, note: 'This federal profile does not establish a deadline for an ordinary private organization. EO procurement provisions direct proposed FAR rules; they are not an already-effective blanket contractor mandate.' };
    default: throw new Error('Unknown policy scope.');
  }
}
let selectedScope: FederalScope = 'outside_federal';
let selectedUse: CryptoUse = 'key_establishment';
export function renderUSFederalProfile(): string {
  const target = federalPolicyTarget(selectedScope, selectedUse);
  return `<section class="panel" id="us-non-nss-profile" aria-labelledby="us-federal-title">
    <div class="panel-head"><h2 id="us-federal-title">Source policy profile: US federal non-NSS</h2>
    <p>This scope check is separate from the illustrative phase planner above. A government-looking example is not enough to establish US federal applicability.</p></div>
    <div class="controls">
      <label>System scope <select id="us-federal-scope">
        ${([['outside_federal','Outside US federal scope'],['prioritized_non_nss','US federal non-NSS prioritized system'],['other_non_nss','Other US federal non-NSS system'],['nss','US National Security System']] as const).map(([v,l]) => `<option value="${v}" ${v===selectedScope?'selected':''}>${l}</option>`).join('')}
      </select></label>
      <label>Cryptographic purpose <select id="us-federal-use"><option value="key_establishment" ${selectedUse==='key_establishment'?'selected':''}>Key establishment / confidentiality</option><option value="digital_signature" ${selectedUse==='digital_signature'?'selected':''}>Digital signatures / authenticity</option></select></label>
    </div>
    <p id="us-federal-target" role="status">${target.deadline ? `Source target: ${target.deadline}. ` : 'No deadline assigned by this scope check. '}${target.note}</p>
    <p><a href="${US_FEDERAL_SOURCES.eo}" target="_blank" rel="noopener noreferrer">EO 14412, issued 22 June 2026, §4(b)</a>: prioritized non-NSS key establishment by 31 December 2030; digital signatures by 31 December 2031.</p>
    <p><a href="${US_FEDERAL_SOURCES.omb}" target="_blank" rel="noopener noreferrer">OMB M-26-15, issued 24 June 2026, §§3B/3D</a>: agency plans within <strong>120 days from the memorandum</strong>. Calendar-day calculation: 24 June + 120 days = <strong>${planSubmissionDate()}</strong>. Phases run through 2035. Priorities include HVAs, high-impact and other specified highly sensitive/vulnerable systems; NSS is excluded.</p>
    <p><a href="https://csrc.nist.gov/pubs/ir/8547/final" target="_blank" rel="noopener noreferrer">NIST IR 8547 is a final report (27 October 2026)</a>. Its §4 schedule deprecates quantum-vulnerable public-key algorithms after 2030 and disallows them under NIST standards and guidelines after 2035. It preserves the earlier migration targets for prioritized federal systems above; it does not establish a universal private-sector deadline.
    <a href="https://csrc.nist.gov/pubs/cswp/39/upd1/considerations-for-achieving-crypto-agility/final" target="_blank" rel="noopener noreferrer">CSWP 39upd1 is a final crypto-agility white paper (updated 29 June 2026)</a>. These final guidance publications are distinct from the issued EO/memorandum. Descriptive policy education; no compliance determination. IR 8547 status reviewed 28 October 2026.</p>
  </section>`;
}
export function bindUSFederalProfile(): void {
  const scope = document.getElementById('us-federal-scope') as HTMLSelectElement;
  const use = document.getElementById('us-federal-use') as HTMLSelectElement;
  const update = () => {
    selectedScope = scope.value as FederalScope; selectedUse = use.value as CryptoUse;
    const target = federalPolicyTarget(selectedScope, selectedUse);
    document.getElementById('us-federal-target')!.textContent = (target.deadline ? `Source target: ${target.deadline}. ` : 'No deadline assigned by this scope check. ') + target.note;
  };
  scope.addEventListener('change', update); use.addEventListener('change', update);
}
