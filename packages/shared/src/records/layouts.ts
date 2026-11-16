import { LayoutDocumentV1, computeLayoutDigestV1, validateLayoutDocumentV1 } from '../proof/layout-document-v1';
import { LayoutRegistry, RegisteredLayout, buildLayoutRegistry } from '../proof/slot-encoding-v1';
import { PUBLISHED_LAYOUT_DOCUMENTS_V1, PUBLISHED_RECORD_CONTENT_SCHEMAS_V1 } from './layouts.generated';
import type { RecordContentSchemaV1 } from './record-content-v1';

/**
 * Published layout documents (ADR 0012 section 4) and their sealed
 * record-content schemas. The registry is built once from the embedded
 * copies of docs/spec/records/layouts/*.json; the JCS digest of each
 * document is what the operator registers on the contract, so a stale copy
 * here fails `gen-shared-layouts.mjs --check`.
 *
 * This module holds the carried set: what the checker, the SDKs and the
 * browser carry (docs/spec/records/carried-layouts.json). A server process
 * holds every published layout: `layouts.server.ts`, the first import of the
 * package's server entry, adds the rest through `addPublishedLayouts`.
 */
const documents: LayoutDocumentV1[] = [...PUBLISHED_LAYOUT_DOCUMENTS_V1];
const contentSchemas: RecordContentSchemaV1[] = [...PUBLISHED_RECORD_CONTENT_SCHEMAS_V1];
let registry: LayoutRegistry | null = null;

export function getPublishedLayoutRegistry(): LayoutRegistry {
  if (!registry) {
    for (const doc of documents) validateLayoutDocumentV1(doc);
    registry = buildLayoutRegistry([...documents]);
  }
  return registry;
}

export function getPublishedLayout(layoutId: number): RegisteredLayout | undefined {
  return getPublishedLayoutRegistry().get(layoutId);
}

export function getPublishedLayoutByName(name: string): RegisteredLayout | undefined {
  for (const entry of getPublishedLayoutRegistry().values()) {
    if (entry.doc.name === name) return entry;
  }
  return undefined;
}

export function listPublishedLayouts(): RegisteredLayout[] {
  return [...getPublishedLayoutRegistry().values()].sort((a, b) => a.doc.layoutId - b.doc.layoutId);
}

/** The sealed record-content schema of that name, among the layouts this process holds. */
export function getPublishedRecordContentSchema(name: string): RecordContentSchemaV1 | undefined {
  return contentSchemas.find((s) => s.name === name);
}

/** Every sealed record-content schema this process holds, by name. */
export function listPublishedRecordContentSchemas(): RecordContentSchemaV1[] {
  return [...contentSchemas].sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
}

/**
 * Add published layout documents and content schemas to the ones this
 * process holds, and drop the built registry so the next read sees them.
 * Adding a document or schema that is already held, unchanged, does nothing.
 * A document whose id or name is held with other contents, or a schema whose
 * name is held with other contents, is refused: a published layout never
 * changes.
 */
export function addPublishedLayouts(docs: readonly LayoutDocumentV1[], schemas: readonly RecordContentSchemaV1[]): void {
  const sameJson = (a: unknown, b: unknown) => JSON.stringify(a) === JSON.stringify(b);
  const newDocs: LayoutDocumentV1[] = [];
  for (const doc of docs) {
    validateLayoutDocumentV1(doc);
    const held = [...documents, ...newDocs].find((d) => d.layoutId === doc.layoutId || d.name === doc.name);
    if (!held) newDocs.push(doc);
    else if (computeLayoutDigestV1(held) !== computeLayoutDigestV1(doc)) {
      throw new Error(`layout ${doc.layoutId} (${doc.name}) is already published as ${held.layoutId} (${held.name}) with other contents`);
    }
  }
  const newSchemas: RecordContentSchemaV1[] = [];
  for (const schema of schemas) {
    const held = [...contentSchemas, ...newSchemas].find((s) => s.name === schema.name);
    if (!held) newSchemas.push(schema);
    else if (!sameJson(held, schema)) throw new Error(`record-content schema ${schema.name} is already published with other contents`);
  }
  if (newDocs.length === 0 && newSchemas.length === 0) return;
  documents.push(...newDocs);
  contentSchemas.push(...newSchemas);
  registry = null;
}

export { PUBLISHED_LAYOUT_DOCUMENTS_V1 };
export type { LayoutDocumentV1 };
