/**
 * Synthsara Core public API.
 *
 * WORTH admission receipts are issued only through
 * UdsRuntimePipeline after durable governance acceptance.
 *
 * Internal scoring and replay utilities are intentionally
 * excluded from this public entry point.
 */
export {
  UdsRuntimePipeline,
  type AdmittedWorthReceipt
} from './runtime/uds_runtime_pipeline.js';

export {
  SqliteGovernanceLedger,
  canonicalizeConsentRevocation
} from './governance/uds_sqlite_authority.js';

export type {
  WorthContribution,
  WorthConfig
} from './governance/uds_worth_engine.js';

export type {
  ConsentAuthority
} from './governance/uds_registry_replay.js';
