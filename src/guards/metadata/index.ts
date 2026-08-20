/**
 * Public surface of the metadata guard (Dev 2 · `prompt-guard`).
 *
 * Week 1 ships the pinning engine only: canonicalization, the pin store, and drift detection.
 * There are deliberately **no** regex or keyword detectors here. Per `docs/THREAT-MODEL.md` §3
 * they are the lowest tier of defence and the loudest failure mode; Week 2 composes
 * `agent-threat-rules` (MIT, 85 tool-poisoning rules) rather than hand-rolling a phrase list.
 *
 * Protocol types (`Guard`, `Verdict`, `Finding`, `GuardContext`, `ProtocolEra`) are Dev 1's and
 * live in `src/types/protocol.ts`; import them from there, not from here.
 */
export {
  CANONICALIZATION_VERSION,
  CanonicalizationError,
  canonicalHash,
  canonicalize,
  canonicalizeAndHash,
  normalizeText,
  sha256Hex,
} from "./canonicalize.js";
export type { CanonicalizationErrorCode, CanonicalizeOptions } from "./canonicalize.js";

export {
  classifyChange,
  containsInvisible,
  diffValues,
  escapeInvisible,
  renderDriftAlert,
  renderFieldDiffs,
} from "./diff.js";
export type {
  ChangeImpact,
  DiffKind,
  DiffOptions,
  DriftAlertOptions,
  FieldDiff,
  RenderOptions,
} from "./diff.js";

/**
 * Invisible-character / ANSI rejection (RESEARCH-BRIEF §4.4: "narrow but real — near-zero FP").
 * Measured at 0.0% false positives across 90 benign metadata cases; see `test/unit/unicode-fp.test.ts`.
 * It **rejects** and never strips: a stripped description is one an attacker edited and we
 * laundered.
 */
export {
  DEFAULT_HAZARD_POLICY,
  HAZARD_CLASS_LABEL,
  UNICODE_GUARD_RESPONSE_METHODS,
  UnicodeHygieneGuard,
  codePointLabel,
  decodeTagBlock,
  hasHazard,
  hazardFinding,
  rankedClasses,
  renderSurfaceHazards,
  renderVisible,
  scanSurface,
  scanText,
} from "./unicode.js";
export type {
  Hazard,
  HazardClass,
  HazardDisposition,
  ScanOptions,
  SurfaceHazard,
  SurfaceScanOptions,
  TextScanResult,
  UnicodeHygieneGuardOptions,
} from "./unicode.js";

/**
 * Composed `agent-threat-rules` detector. **Advisory by default and not constructed unless an
 * operator opts in** — measured at 6.5% FP / 62.5% catch on the `alert` lane; see the header of
 * `./rules.ts` for the full table and why `enforce` (0% FP, 0% catch) is not the default.
 */
export {
  ATR_GUARD_RESPONSE_METHODS,
  AtrAdvisoryGuard,
  AtrScanner,
  METADATA_RULE_CATEGORIES,
  atrEngineConfig,
  metadataUnits,
} from "./rules.js";
export type {
  AtrAdvisoryGuardOptions,
  AtrLane,
  AtrMode,
  AtrScannerOptions,
  MetadataUnit,
} from "./rules.js";

export {
  SERVER_INSTRUCTIONS_SUBJECT,
  ToolSurfaceError,
  UNPINNED_TOOL_FIELDS,
  extractServerSurface,
  extractToolSurface,
  readCallToolName,
  readToolList,
} from "./surface.js";
export type { ExtractOptions, PinKind, ToolSurface } from "./surface.js";

export { MetadataPinGuard } from "./drift.js";
export type {
  DriftReport,
  MetadataPinGuardOptions,
  PinAssessmentOptions,
  PinEvent,
  PinEventKind,
} from "./drift.js";

/**
 * Pin-time risk assessment — the evidence a human gets at the moment they are asked to trust a
 * server. Composed from signals that already exist; it computes **no score** and returns **no
 * verdict**, and `PIN_ASSESSMENT_CAVEAT` is printed inside every report it renders. Measured at
 * 0.0% false positives across 11 captured real servers and 2.9% (1 of 35) on the deliberately
 * adversarial benign metadata corpus; see `test/unit/assess-fp.test.ts`.
 */
export {
  FLOOD_DUPLICATE_NAMES,
  MAX_EXAMPLES_PER_SIGNAL,
  MAX_SCANNED_SENTENCES,
  MAX_SUBJECTS_PER_SIGNAL,
  PIN_ASSESSMENT_CAVEAT,
  SIGNAL_READING_ORDER,
  assessPinCandidate,
  assessmentFinding,
  renderPinAssessment,
} from "./assess.js";
export type {
  AssessOptions,
  AssessmentLane,
  Measurement,
  NotChecked,
  PinCandidate,
  PinRiskAssessment,
  RiskSignal,
  SignalExample,
  Truncation,
} from "./assess.js";
