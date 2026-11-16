// GENERATED FILE. Do not edit by hand.
// Source: docs/spec/records/layouts/*.json and docs/spec/records/record-content/*.json
// Regenerate: node scripts/records/gen-shared-layouts.mjs
import type { LayoutDocumentV1 } from '../proof/layout-document-v1';
import type { RecordContentSchemaV1 } from './record-content-v1';

export const PUBLISHED_LAYOUT_DOCUMENTS_V1: readonly LayoutDocumentV1[] = [
  // 0x0008-machine-action-record-v2.json
  {
    "schema": "layout-document/v1",
    "layoutId": 8,
    "layoutVersion": 2,
    "name": "machine-action-record/v2",
    "recordTypeId": "machine-action-record",
    "encodingVersion": 1,
    "stateBits": 96,
    "sealBits": 160,
    "public": false,
    "recordAttempts": true,
    "fields": [
      {
        "name": "layoutId",
        "type": "counter",
        "bits": 16,
        "fixed": 8
      },
      {
        "name": "layoutVersion",
        "type": "counter",
        "bits": 8,
        "fixed": 2
      },
      {
        "name": "lifecycle",
        "type": "enum",
        "bits": 8,
        "values": {
          "recorded": 1,
          "amended": 2,
          "closed": 3
        }
      },
      {
        "name": "flags",
        "type": "flags",
        "bits": 8,
        "bitNames": {
          "transition_not_applied": 0,
          "delivery_failed": 1
        }
      },
      {
        "name": "seq",
        "type": "counter",
        "bits": 24
      },
      {
        "name": "reserved",
        "type": "reserved",
        "bits": 32
      }
    ],
    "lifecycle": {
      "field": "lifecycle",
      "genesis": [
        "recorded"
      ],
      "terminal": [
        "closed"
      ],
      "transitions": {
        "recorded": [
          "recorded",
          "amended",
          "closed"
        ],
        "amended": [
          "recorded",
          "amended",
          "closed"
        ],
        "closed": []
      }
    },
    "sealedRecordSchema": "record-content/machine-action-record/v2"
  } as LayoutDocumentV1,
];

export const PUBLISHED_RECORD_CONTENT_SCHEMAS_V1: readonly RecordContentSchemaV1[] = [
  // machine-action-record-v2.json
  {
    "schema": "record-content-schema/v1",
    "name": "record-content/machine-action-record/v2",
    "layout": "machine-action-record/v2",
    "visibility": "sealed",
    "requiredFields": [
      "title",
      "occurredAt",
      "actorId",
      "payloads"
    ],
    "optionalFields": [
      "instructedBy",
      "kind",
      "description",
      "references",
      "amends",
      "note",
      "attemptedTarget",
      "ruleId",
      "failureClass"
    ],
    "fields": {
      "title": {
        "type": "string",
        "maxLength": 120
      },
      "occurredAt": {
        "type": "string",
        "format": "rfc3339-utc"
      },
      "actorId": {
        "type": "string"
      },
      "instructedBy": {
        "type": "string"
      },
      "kind": {
        "type": "string",
        "format": "lowercase-hyphen"
      },
      "description": {
        "type": "string"
      },
      "payloads": {
        "type": "array",
        "items": "payload-ref/v1",
        "minItems": 1
      },
      "references": {
        "type": "array",
        "items": "record-ref/v1"
      },
      "amends": {
        "type": "record-ref/v1",
        "fields": {
          "recordKey": "bytes32-hex",
          "seq": "integer"
        }
      },
      "note": {
        "type": "string"
      },
      "attemptedTarget": {
        "type": "string",
        "when": "attempt record"
      },
      "ruleId": {
        "type": "string",
        "when": "attempt record"
      },
      "failureClass": {
        "type": "string",
        "when": "failure record"
      }
    }
  } as RecordContentSchemaV1,
];
