import { LayoutDocumentV1, validateLayoutDocumentV1 } from '../proof/layout-document-v1';
import { LayoutRegistry, RegisteredLayout, buildLayoutRegistry } from '../proof/slot-encoding-v1';
import { PUBLISHED_LAYOUT_DOCUMENTS_V1 } from './layouts.generated';

/**
 * Published layout documents (ADR 0012 section 4). The registry is built
 * once from the embedded copies of docs/spec/records/layouts/*.json; the
 * JCS digest of each document is what the operator registers on the
 * contract, so a stale copy here fails `gen-shared-layouts.mjs --check`.
 */
let registry: LayoutRegistry | null = null;

export function getPublishedLayoutRegistry(): LayoutRegistry {
  if (!registry) {
    for (const doc of PUBLISHED_LAYOUT_DOCUMENTS_V1) validateLayoutDocumentV1(doc);
    registry = buildLayoutRegistry([...PUBLISHED_LAYOUT_DOCUMENTS_V1]);
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

export { PUBLISHED_LAYOUT_DOCUMENTS_V1 };
export type { LayoutDocumentV1 };
