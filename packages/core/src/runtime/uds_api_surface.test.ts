import { describe, expect, it } from 'vitest';
import * as core from '../index.js';

describe('UDS public API surface invariants', () => {
  it('exports only the approved runtime governance and admission values', () => {
    expect(Object.keys(core).sort()).toEqual([
      'SqliteGovernanceLedger',
      'UdsRuntimePipeline',
      'canonicalizeConsentRevocation',
    ].sort());
  });

  it('does not expose standalone scoring or legacy replay through the root', () => {
    expect('calculateWorth' in core).toBe(false);
    expect('SqliteReplayLedger' in core).toBe(false);
    expect('SovereignKeyRegistry' in core).toBe(false);
    expect('AtomicReplayLedger' in core).toBe(false);
  });
});
