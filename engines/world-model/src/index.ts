/**
 * Conformance entry. The runner imports `WorldModel`, `entityIdFromName`,
 * `normalizeName`, and `decide` from this file.
 */

export { decide, entityIdFromName, normalizeName } from "./ids.js";
export { LOG_SCHEMA_VERSION, MESSAGE_KINDS, WorldModel } from "./model.js";
export type { ApplyResult, EdgeRecord, IngestReport, LogEntry, MessageKind } from "./model.js";
