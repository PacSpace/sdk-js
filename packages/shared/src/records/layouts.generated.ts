// GENERATED FILE. Do not edit by hand.
// Source: docs/spec/records/layouts/*.json and docs/spec/records/record-content/*.json
// Regenerate: node scripts/records/gen-shared-layouts.mjs
import type { LayoutDocumentV1 } from '../proof/layout-document-v1';
import type { RecordContentSchemaV1 } from './record-content-v1';

export const PUBLISHED_LAYOUT_DOCUMENTS_V1: readonly LayoutDocumentV1[] = [
  // 0x0001-geoint-tracked-entity-v1.json
  {
    "schema": "layout-document/v1",
    "layoutId": 1,
    "layoutVersion": 1,
    "name": "geoint-tracked-entity/v1",
    "recordTypeId": "geoint-tracked-entity",
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
        "fixed": 1
      },
      {
        "name": "layoutVersion",
        "type": "counter",
        "bits": 8,
        "fixed": 1
      },
      {
        "name": "lifecycle",
        "type": "enum",
        "bits": 8,
        "values": {
          "detected": 1,
          "tracked": 2,
          "corroborated": 3,
          "lost": 4,
          "archived": 5
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
        "detected"
      ],
      "terminal": [
        "archived"
      ],
      "transitions": {
        "detected": [
          "tracked",
          "lost",
          "archived"
        ],
        "tracked": [
          "tracked",
          "corroborated",
          "lost",
          "archived"
        ],
        "corroborated": [
          "tracked",
          "lost",
          "archived"
        ],
        "lost": [
          "tracked",
          "archived"
        ],
        "archived": []
      }
    },
    "sealedRecordSchema": "record-content/geoint-tracked-entity/v1",
    "notes": [
      "Entity identity lives in the keyed record key, not in the state region.",
      "Precise position, sensor, actor, model reference, confidence, source count, and classification live only in the sealed record.",
      "A forbidden transition is recorded as an attempt record: seq advances, lifecycle is unchanged, flag transition_not_applied is set."
    ]
  } as LayoutDocumentV1,
  // 0x0002-model-version-record-v1.json
  {
    "schema": "layout-document/v1",
    "layoutId": 2,
    "layoutVersion": 1,
    "name": "model-version-record/v1",
    "recordTypeId": "model-version-record",
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
        "fixed": 2
      },
      {
        "name": "layoutVersion",
        "type": "counter",
        "bits": 8,
        "fixed": 1
      },
      {
        "name": "lifecycle",
        "type": "enum",
        "bits": 8,
        "values": {
          "submitted": 1,
          "under_test": 2,
          "approved": 3,
          "deployed": 4,
          "suspended": 5,
          "retired": 6,
          "revoked": 7
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
        "submitted"
      ],
      "terminal": [
        "retired",
        "revoked"
      ],
      "transitions": {
        "submitted": [
          "under_test",
          "revoked"
        ],
        "under_test": [
          "approved",
          "submitted",
          "revoked"
        ],
        "approved": [
          "deployed",
          "suspended",
          "revoked"
        ],
        "deployed": [
          "suspended",
          "retired",
          "revoked"
        ],
        "suspended": [
          "deployed",
          "retired",
          "revoked"
        ],
        "retired": [],
        "revoked": []
      }
    },
    "sealedRecordSchema": "record-content/model-version-record/v1",
    "notes": [
      "One record per approved system version. Revoke is reachable from every non-terminal state, including straight from deployed.",
      "An action record's modelRecordRef points at one seq of one of these records; a relying party checks that the referenced seq was approved or deployed at the action's time."
    ]
  } as LayoutDocumentV1,
  // 0x0003-geoint-aoi-cell-v1.json
  {
    "schema": "layout-document/v1",
    "layoutId": 3,
    "layoutVersion": 1,
    "name": "geoint-aoi-cell/v1",
    "recordTypeId": "geoint-aoi-cell",
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
        "fixed": 3
      },
      {
        "name": "layoutVersion",
        "type": "counter",
        "bits": 8,
        "fixed": 1
      },
      {
        "name": "lifecycle",
        "type": "enum",
        "bits": 8,
        "values": {
          "registered": 1,
          "monitoring": 2,
          "retired": 3
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
        "name": "activityLevel",
        "type": "quantity",
        "bits": 8,
        "unitCode": "level",
        "scale": 0,
        "semantics": "perRecord"
      },
      {
        "name": "reserved",
        "type": "reserved",
        "bits": 24
      }
    ],
    "lifecycle": {
      "field": "lifecycle",
      "genesis": [
        "registered"
      ],
      "terminal": [
        "retired"
      ],
      "transitions": {
        "registered": [
          "monitoring",
          "retired"
        ],
        "monitoring": [
          "monitoring",
          "retired"
        ],
        "retired": []
      }
    },
    "sealedRecordSchema": "record-content/geoint-aoi-cell/v1",
    "notes": [
      "Registered layout exercised by vectors only in the first release; the demo shows the same lane reading it.",
      "activityLevel is a per-window declared quantity (0 to 255) chosen by the operator; the window bounds and inputs live in the sealed record."
    ]
  } as LayoutDocumentV1,
  // 0x0004-balance-account-v1.json
  {
    "schema": "layout-document/v1",
    "layoutId": 4,
    "layoutVersion": 1,
    "name": "balance-account/v1",
    "recordTypeId": "balance-account",
    "encodingVersion": 1,
    "stateBits": 96,
    "sealBits": 160,
    "public": true,
    "recordAttempts": true,
    "fields": [
      {
        "name": "layoutId",
        "type": "counter",
        "bits": 16,
        "fixed": 4
      },
      {
        "name": "layoutVersion",
        "type": "counter",
        "bits": 8,
        "fixed": 1
      },
      {
        "name": "lifecycle",
        "type": "enum",
        "bits": 8,
        "values": {
          "active": 1,
          "frozen": 2,
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
        "bits": 32
      },
      {
        "name": "reserved",
        "type": "reserved",
        "bits": 24
      }
    ],
    "lifecycle": {
      "field": "lifecycle",
      "genesis": [
        "active"
      ],
      "terminal": [
        "closed"
      ],
      "transitions": {
        "active": [
          "active",
          "frozen",
          "closed"
        ],
        "frozen": [
          "active",
          "closed"
        ],
        "closed": []
      }
    },
    "sealedRecordSchema": "record-content/balance-account/v1",
    "notes": [
      "One record per customer. Every ordinary balance delta is the transition active to active.",
      "Nothing about money is public: no amount, sign, currency, or running total appears in the state region. The amount is in the sealed record.",
      "This layout document is public from the production cutover."
    ]
  } as LayoutDocumentV1,
  // 0x0005-usage-meter-v1.json
  {
    "schema": "layout-document/v1",
    "layoutId": 5,
    "layoutVersion": 1,
    "name": "usage-meter/v1",
    "recordTypeId": "usage-meter",
    "encodingVersion": 1,
    "stateBits": 96,
    "sealBits": 160,
    "public": true,
    "recordAttempts": true,
    "fields": [
      {
        "name": "layoutId",
        "type": "counter",
        "bits": 16,
        "fixed": 5
      },
      {
        "name": "layoutVersion",
        "type": "counter",
        "bits": 8,
        "fixed": 1
      },
      {
        "name": "lifecycle",
        "type": "enum",
        "bits": 8,
        "values": {
          "active": 1,
          "suspended": 2,
          "closed": 3
        }
      },
      {
        "name": "flags",
        "type": "flags",
        "bits": 8,
        "bitNames": {
          "transition_not_applied": 0,
          "delivery_failed": 1,
          "units_credit": 2
        }
      },
      {
        "name": "seq",
        "type": "counter",
        "bits": 24
      },
      {
        "name": "units",
        "type": "quantity",
        "bits": 32,
        "unitCode": "api_call",
        "scale": 0,
        "semantics": "perRecord"
      }
    ],
    "lifecycle": {
      "field": "lifecycle",
      "genesis": [
        "active"
      ],
      "terminal": [
        "closed"
      ],
      "transitions": {
        "active": [
          "active",
          "suspended",
          "closed"
        ],
        "suspended": [
          "active",
          "closed"
        ],
        "closed": []
      }
    },
    "sealedRecordSchema": "record-content/usage-meter/v1",
    "notes": [
      "Public units are a declared choice by the tenant: anyone reading the chain sees the quantities and their timing for a blinded customer.",
      "units is a per-record quantity; a reversal sets flag units_credit and carries the reversed quantity.",
      "This layout document is public from the production cutover."
    ]
  } as LayoutDocumentV1,
  // 0x0006-machine-action-record-v1.json
  {
    "schema": "layout-document/v1",
    "layoutId": 6,
    "layoutVersion": 1,
    "name": "machine-action-record/v1",
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
        "fixed": 6
      },
      {
        "name": "layoutVersion",
        "type": "counter",
        "bits": 8,
        "fixed": 1
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
    "sealedRecordSchema": "record-content/machine-action-record/v1",
    "notes": [
      "The general layout (records buyer posture plan, D1 and D2): one record per thing a machine did or produced, one entry per event in that record's life. Every ordinary entry is the transition recorded to recorded.",
      "Three lifecycle words: recorded, amended, closed. A transition the table forbids, for example any word after closed, is recorded as an attempt with transition_not_applied set (recordAttempts); nothing is refused at intake for that reason.",
      "Nothing about the content is public: the state region carries one of three words, two flags, and the entry number. The title, the time, who acted, the payload fingerprints, and every reference are in the sealed record.",
      "Sealed references[] generalize modelRecordRef: each names one entry of one record as { recordKey, seq }; amends names the entry this one supersedes and is checked by the same rule that checks Balance adjusts (D17).",
      "Not public: this document is served on the public layout endpoint only when counsel confirms capture; the chain 296 registration card registers it, the chain 295 card (public layouts only) does not."
    ]
  } as LayoutDocumentV1,
  // 0x0007-balance-account-v2.json
  {
    "schema": "layout-document/v1",
    "layoutId": 7,
    "layoutVersion": 2,
    "name": "balance-account/v2",
    "recordTypeId": "balance-account",
    "encodingVersion": 1,
    "stateBits": 96,
    "sealBits": 160,
    "public": true,
    "recordAttempts": true,
    "fields": [
      {
        "name": "layoutId",
        "type": "counter",
        "bits": 16,
        "fixed": 7
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
          "active": 1,
          "frozen": 2,
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
        "bits": 32
      },
      {
        "name": "reserved",
        "type": "reserved",
        "bits": 24
      }
    ],
    "lifecycle": {
      "field": "lifecycle",
      "genesis": [
        "active"
      ],
      "terminal": [
        "closed"
      ],
      "transitions": {
        "active": [
          "active",
          "frozen",
          "closed"
        ],
        "frozen": [
          "active",
          "closed"
        ],
        "closed": []
      }
    },
    "sealedRecordSchema": "record-content/balance-account/v2",
    "notes": [
      "One record per customer. Every ordinary balance delta is the transition active to active. The public state region is unchanged from balance-account/v1: the lifecycle words, the two flags, and the entry number.",
      "Nothing about money is public: no amount, sign, currency, or running total appears in the state region. The amount is in the sealed record.",
      "The sealed record grows by one optional field, adjusts, naming the earlier delta this one corrects as { referenceId } or { recordId } (records buyer posture plan, D17 and Slice E1). A layout never changes once registered, so the grown schema is a new layout id (0x0007) at layoutVersion 2 of the same recordTypeId; a record never changes layout, so a customer's record stays on the layout it opened under.",
      "Layout id choice: 0x0007 is the next free id after the five shipped layouts and the general layout (0x0006); the id is an internal registration handle and never appears in tenant-facing copy.",
      "This layout document is public. It is registered on chain 296 by the general registration card and on chain 295 by the public-layouts card; writes under it wait for BALANCE_LAYOUT_V2_ENABLED after both cards run."
    ]
  } as LayoutDocumentV1,
];

export const PUBLISHED_RECORD_CONTENT_SCHEMAS_V1: readonly RecordContentSchemaV1[] = [
  // balance-account-v1.json
  {
    "schema": "record-content-schema/v1",
    "name": "record-content/balance-account/v1",
    "layout": "balance-account/v1",
    "visibility": "sealed",
    "description": "Sealed record for one balance delta or account lifecycle change. The money is here and nowhere public.",
    "requiredFields": [
      "customerId",
      "amount",
      "currency",
      "reason",
      "referenceId",
      "occurredAt"
    ],
    "optionalFields": [
      "metadataDigest",
      "checkpointRef",
      "attemptedTarget",
      "ruleId",
      "failureClass"
    ],
    "fields": {
      "customerId": {
        "type": "string"
      },
      "amount": {
        "type": "string",
        "format": "signed-decimal",
        "description": "Signed decimal string, for example -12.50."
      },
      "currency": {
        "type": "string",
        "format": "iso-4217"
      },
      "reason": {
        "type": "string"
      },
      "referenceId": {
        "type": "string",
        "description": "Tenant idempotency reference for the delta."
      },
      "metadataDigest": {
        "type": "bytes32-hex",
        "description": "keccak256 of the JCS-canonical delta metadata, when metadata was supplied."
      },
      "occurredAt": {
        "type": "string",
        "format": "rfc3339-utc"
      },
      "checkpointRef": {
        "type": "string",
        "description": "Checkpoint identifier when this record is a checkpoint-bound transition."
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
  // balance-account-v2.json
  {
    "schema": "record-content-schema/v1",
    "name": "record-content/balance-account/v2",
    "layout": "balance-account/v2",
    "visibility": "sealed",
    "description": "Sealed record for one balance delta or account lifecycle change. The money is here and nowhere public. Version 2 adds the optional adjusts field naming the earlier delta this one corrects.",
    "requiredFields": [
      "customerId",
      "amount",
      "currency",
      "reason",
      "referenceId",
      "occurredAt"
    ],
    "optionalFields": [
      "metadataDigest",
      "checkpointRef",
      "adjusts",
      "attemptedTarget",
      "ruleId",
      "failureClass"
    ],
    "fields": {
      "customerId": {
        "type": "string"
      },
      "amount": {
        "type": "string",
        "format": "signed-decimal",
        "description": "Signed decimal string, for example -12.50."
      },
      "currency": {
        "type": "string",
        "format": "iso-4217"
      },
      "reason": {
        "type": "string"
      },
      "referenceId": {
        "type": "string",
        "description": "Tenant idempotency reference for the delta."
      },
      "metadataDigest": {
        "type": "bytes32-hex",
        "description": "keccak256 of the JCS-canonical delta metadata, when metadata was supplied."
      },
      "occurredAt": {
        "type": "string",
        "format": "rfc3339-utc"
      },
      "checkpointRef": {
        "type": "string",
        "description": "Checkpoint identifier when this record is a checkpoint-bound transition."
      },
      "adjusts": {
        "type": "adjusts-ref/v1",
        "fields": {
          "referenceId": "string",
          "recordId": "string"
        },
        "description": "The earlier delta this one corrects, named by exactly one of its referenceId or its recordId. Checked at intake by the same rule that checks amends on machine-action-record/v1 (D17)."
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
  // geoint-aoi-cell-v1.json
  {
    "schema": "record-content-schema/v1",
    "name": "record-content/geoint-aoi-cell/v1",
    "layout": "geoint-aoi-cell/v1",
    "visibility": "sealed",
    "description": "Sealed record for one activity window of an area-of-interest cell.",
    "requiredFields": [
      "cellRef",
      "windowStart",
      "windowEnd",
      "actorId"
    ],
    "optionalFields": [
      "inputsRef",
      "modelRecordRef",
      "payloads",
      "attemptedTarget",
      "ruleId",
      "failureClass"
    ],
    "fields": {
      "cellRef": {
        "type": "string"
      },
      "windowStart": {
        "type": "string",
        "format": "rfc3339-utc"
      },
      "windowEnd": {
        "type": "string",
        "format": "rfc3339-utc"
      },
      "actorId": {
        "type": "string"
      },
      "inputsRef": {
        "type": "string"
      },
      "modelRecordRef": {
        "type": "object",
        "fields": {
          "recordKey": "bytes32-hex",
          "seq": "integer"
        }
      },
      "payloads": {
        "type": "array",
        "items": "payload-ref/v1"
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
  // geoint-tracked-entity-v1.json
  {
    "schema": "record-content-schema/v1",
    "name": "record-content/geoint-tracked-entity/v1",
    "layout": "geoint-tracked-entity/v1",
    "visibility": "sealed",
    "description": "Sealed record for one transition of a tracked entity. Hashed into recordHash; disclosed only inside a receipt. PacSpace stores these values and computes none of them.",
    "requiredFields": [
      "observedAt",
      "position",
      "sourceRef",
      "actorId",
      "modelRecordRef",
      "conclusion"
    ],
    "optionalFields": [
      "confidenceBand",
      "sourceCount",
      "classification",
      "inputsRef",
      "payloads",
      "attemptedTarget",
      "ruleId",
      "failureClass"
    ],
    "fields": {
      "observedAt": {
        "type": "string",
        "format": "rfc3339-utc"
      },
      "position": {
        "type": "object",
        "fields": {
          "lat": "decimal-string",
          "lon": "decimal-string",
          "altM": "decimal-string",
          "crs": "string"
        }
      },
      "sourceRef": {
        "type": "string",
        "description": "Sensor or source reference chosen by the tenant."
      },
      "actorId": {
        "type": "string"
      },
      "modelRecordRef": {
        "type": "object",
        "fields": {
          "recordKey": "bytes32-hex",
          "seq": "integer"
        },
        "description": "The committed model-version record (layout 0x0002) and the seq that was current when this action was taken."
      },
      "conclusion": {
        "type": "string"
      },
      "inputsRef": {
        "type": "string"
      },
      "confidenceBand": {
        "type": "string"
      },
      "sourceCount": {
        "type": "integer"
      },
      "classification": {
        "type": "string"
      },
      "payloads": {
        "type": "array",
        "items": "payload-ref/v1",
        "description": "Digests of imagery or sensor dumps the tenant hashed where they live. The storage locator is not part of the record."
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
    },
    "excluded": [
      "storage locators (URI, bucket, path) ride in the receipt envelope, never in the record",
      "PacSpace bookkeeping (seq, previousWord, anchorId, itemIndex) is never part of the record content"
    ]
  } as RecordContentSchemaV1,
  // machine-action-record-v1.json
  {
    "schema": "record-content-schema/v1",
    "name": "record-content/machine-action-record/v1",
    "layout": "machine-action-record/v1",
    "visibility": "sealed",
    "description": "Sealed record for one entry in the record of something a machine did or produced: what it was, when, who acted, the fingerprints of the files it names, and the entries it refers to.",
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
        "maxLength": 120,
        "description": "What this entry records, in the tenant's words; at most 120 characters (RECORD_TITLE_TOO_LONG)."
      },
      "occurredAt": {
        "type": "string",
        "format": "rfc3339-utc",
        "description": "When it happened, UTC."
      },
      "actorId": {
        "type": "string",
        "description": "Who or what did it: an operator, an agent, or a machine, named by the tenant."
      },
      "instructedBy": {
        "type": "string",
        "description": "Who told the actor to do it, when the tenant tracks that."
      },
      "kind": {
        "type": "string",
        "format": "lowercase-hyphen",
        "description": "The tenant's own word for the sort of thing this is, lowercase with hyphens, for example signed-contract or agent-configuration."
      },
      "description": {
        "type": "string",
        "description": "A few sentences the tenant wants sealed with the entry."
      },
      "payloads": {
        "type": "array",
        "items": "payload-ref/v1",
        "minItems": 1,
        "description": "The fingerprints of the files this entry is about: { alg, digest, byteLength } each, digested where the bytes live. At least one (RECORD_PAYLOADS_REQUIRED); the files themselves and their locations are never part of the record."
      },
      "references": {
        "type": "array",
        "items": "record-ref/v1",
        "description": "Entries of other records this entry refers to, each { recordKey, seq }. The general form of modelRecordRef; a relying party resolves each against that record's history."
      },
      "amends": {
        "type": "record-ref/v1",
        "fields": {
          "recordKey": "bytes32-hex",
          "seq": "integer"
        },
        "description": "The entry this one supersedes, as { recordKey, seq }: an earlier entry of this record, or an entry of a closed record that this entry also names in references[]."
      },
      "note": {
        "type": "string",
        "description": "Free text for the entry, for example why it was amended or closed."
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
    },
    "excluded": [
      "Storage locators (bucket paths, URLs, file names) are never part of the record; a payload is named only by its fingerprint.",
      "PacSpace bookkeeping (seq, words, anchor ids, openings, the batch seed) is never part of the record content."
    ]
  } as RecordContentSchemaV1,
  // model-version-record-v1.json
  {
    "schema": "record-content-schema/v1",
    "name": "record-content/model-version-record/v1",
    "layout": "model-version-record/v1",
    "visibility": "sealed",
    "description": "Sealed record for one transition of an approved system version.",
    "requiredFields": [
      "modelId",
      "versionLabel",
      "buildDigest",
      "recordedAt",
      "actorId"
    ],
    "optionalFields": [
      "testSuiteRef",
      "testResultDigest",
      "approvingAuthorityRef",
      "attemptedTarget",
      "ruleId",
      "failureClass"
    ],
    "fields": {
      "modelId": {
        "type": "string"
      },
      "versionLabel": {
        "type": "string"
      },
      "buildDigest": {
        "type": "payload-ref/v1",
        "description": "Digest of the model weights or build artifact, computed by the tenant where the bytes live."
      },
      "testSuiteRef": {
        "type": "string"
      },
      "testResultDigest": {
        "type": "payload-ref/v1"
      },
      "approvingAuthorityRef": {
        "type": "string"
      },
      "recordedAt": {
        "type": "string",
        "format": "rfc3339-utc"
      },
      "actorId": {
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
  // usage-meter-v1.json
  {
    "schema": "record-content-schema/v1",
    "name": "record-content/usage-meter/v1",
    "layout": "usage-meter/v1",
    "visibility": "sealed",
    "description": "Sealed record for one metered usage entry. The quantity is public in the state region by the tenant's declaration; who was metered and at what price is sealed.",
    "requiredFields": [
      "customerId",
      "meterId",
      "referenceId",
      "occurredAt"
    ],
    "optionalFields": [
      "unitPriceRef",
      "attemptedTarget",
      "ruleId",
      "failureClass"
    ],
    "fields": {
      "customerId": {
        "type": "string"
      },
      "meterId": {
        "type": "string"
      },
      "unitPriceRef": {
        "type": "string"
      },
      "referenceId": {
        "type": "string"
      },
      "occurredAt": {
        "type": "string",
        "format": "rfc3339-utc"
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
