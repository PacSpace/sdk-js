/**
 * The entity-id forms only PacSpace writes ("Cryptography and proof", the reserved forms): acknowledgment
 * records, trail index records, reader link records, the key registry and the policy record. A tenant's key
 * or the dashboard never writes or shares a record in one of these forms. Intake refuses them by the entity
 * id it receives; the SDK refuses them by the record's name before it blinds the name into a wire id, which
 * intake cannot read.
 */
export const RESERVED_RECORD_FORMS = ["ack-", "trail-", "share-", "key-", "policy-"] as const;

/** Platform records named in full rather than by form: the access record holders and versions are written to. */
export const RESERVED_RECORD_IDS = ["pacspace-access-record"] as const;

/**
 * Records in a reserved form that are written through the public API by design: the key-page release record
 * (`RELEASE_RECORD` in apps/frontend/scripts/keypages/release-record.mjs), which the release workspace's own
 * key writes on every key-page release.
 */
export const RESERVED_FORM_EXCEPTIONS = ["key-pages"] as const;

export function isReservedRecordForm(entityId: string): boolean {
  const id = String(entityId ?? "").trim().toLowerCase();
  if ((RESERVED_FORM_EXCEPTIONS as readonly string[]).includes(id)) return false;
  return RESERVED_RECORD_FORMS.some((form) => id.startsWith(form)) || (RESERVED_RECORD_IDS as readonly string[]).includes(id);
}

export const RECORD_RESERVED_MESSAGE = "This record name is reserved for PacSpace.";
