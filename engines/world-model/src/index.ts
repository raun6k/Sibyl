/**
 * Conformance entry. The runner imports `WorldModel`, `entityIdFromName`,
 * `normalizeName`, and `decide` from this file.
 */

export { decide, entityIdFromName, normalizeName } from "./ids.js";
export { MESSAGE_KINDS, WorldModel } from "./model.js";
export type { ApplyResult, IngestReport, MessageKind } from "./model.js";
