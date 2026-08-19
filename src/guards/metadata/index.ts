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

export { containsInvisible, diffValues, escapeInvisible, renderFieldDiffs } from "./diff.js";
export type { DiffKind, DiffOptions, FieldDiff, RenderOptions } from "./diff.js";

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
  PinEvent,
  PinEventKind,
} from "./drift.js";
