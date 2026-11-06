# Module 00: Execution Intelligence & Architecture-Selection Engine

This module provides the deterministic **Requirement-Analysis & Architecture-Selection Engine** used to design the right backend **for** any frontend or system specification—deciding *what* components to implement, *how* to configure them, and *why*.

---

## 1. Requirement Analysis & Domain Classification Engine

Before writing any schema or endpoint, classify the target system across 7 orthogonal axes:

```typescript
export interface SystemRequirementsProfile {
  domainType:
    | 'fintech_payments'
    | 'ecommerce_marketplace'
    | 'b2b_saas_multitenant'
    | 'realtime_collaboration'
    | 'media_social_content'
    | 'healthcare_regulated'
    | 'ai_native_platform'
    | 'iot_high_ingest';
  consistencyRequirement: 'strict_serializable_ledger' | 'strong_per_aggregate' | 'eventual_read_heavy';
  tenancyModel: 'single_tenant' | 'b2c_user_scoped' | 'b2b_shared_orgs' | 'enterprise_regulated_silos';
  realtimeNeeds: ('none' | 'server_push_notifications' | 'ai_token_streaming' | 'bidirectional_rooms_presence')[];
  searchNeeds: ('basic_filter_sort' | 'full_text_typo_tolerant' | 'faceted_ecommerce' | 'hybrid_semantic_vector')[];
  fileHandlingNeeds: ('none' | 'small_avatars_docs' | 'large_video_media_streaming' | 'regulated_pii_documents')[];
  complianceFrameworks: ('NONE' | 'PCI_DSS' | 'HIPAA' | 'GDPR_CCPA' | 'SOC2_ISO27001')[];
  expectedPeakRps: number;
}

export interface SelectedBackendArchitecture {
  primaryDatabase: { engine: string; isolationDefault: string; poolingStrategy: string };
  secondaryStores: { role: string; engine: string; rationale: string }[];
  tenancyStrategy: { pattern: 'RLS_SHARED_SCHEMA' | 'SCHEMA_PER_TENANT' | 'DB_PER_TENANT'; rationale: string };
  apiProtocols: { protocol: 'REST' | 'GraphQL' | 'WebSocket' | 'SSE' | 'gRPC'; useCase: string }[];
  eventAndQueueLayer: { broker: string; pattern: string; rationale: string };
  securityControls: string[];
  latencySloByTier: Record<'tier0_cached' | 'tier1_interactive' | 'tier2_complex' | 'tier3_async_cutoff', number>;
  drTargets: { rpoSeconds: number; rtoSeconds: number; backupStrategy: string };
}

/**
 * Deterministic Architecture-Selection Engine:
 * Evaluates product requirements and outputs the exact backend topology and rationale.
 */
export function selectBackendArchitecture(profile: SystemRequirementsProfile): SelectedBackendArchitecture {
  const secondaryStores: SelectedBackendArchitecture['secondaryStores'] = [
    {
      role: 'Cache, Rate Limiting, Distributed Leases',
      engine: 'Redis 7+ / Valkey',
      rationale: 'Required for atomic Lua token-bucket rate limiting, session state, and cache stampede protection.',
    },
  ];

  // 1. Search Infrastructure Selection
  if (profile.searchNeeds.includes('full_text_typo_tolerant') || profile.searchNeeds.includes('faceted_ecommerce')) {
    secondaryStores.push({
      role: 'Full-Text & Faceted Search',
      engine: profile.expectedPeakRps > 2000 ? 'OpenSearch / Elasticsearch' : 'Meilisearch',
      rationale: 'Offloads typo-tolerant lexical BM25 queries and high-cardinality facet aggregations from primary RDBMS.',
    });
  }
  if (profile.searchNeeds.includes('hybrid_semantic_vector') || profile.domainType === 'ai_native_platform') {
    secondaryStores.push({
      role: 'Vector Similarity & Hybrid Search',
      engine: 'PostgreSQL pgvector (HNSW) or Qdrant',
      rationale: 'Supports cosine/inner-product vector embeddings combined with metadata filtering.',
    });
  }

  // 2. High-Ingest / Document Selection
  if (profile.domainType === 'iot_high_ingest' || profile.domainType === 'media_social_content') {
    secondaryStores.push({
      role: 'High-Write Telemetry / Polymorphic Feeds',
      engine: 'MongoDB / TimescaleDB / Cassandra',
      rationale: 'Handles high-velocity append workloads and polymorphic schemas without rigid ALTER TABLE locks.',
    });
  }

  // 3. Multi-Tenancy Strategy Selection
  let tenancyStrategy: SelectedBackendArchitecture['tenancyStrategy'] = {
    pattern: 'RLS_SHARED_SCHEMA',
    rationale: 'Shared tables with tenant_id + PostgreSQL FORCE ROW LEVEL SECURITY provides optimal operational density.',
  };
  if (profile.tenancyModel === 'enterprise_regulated_silos' || profile.complianceFrameworks.includes('HIPAA')) {
    tenancyStrategy = {
      pattern: 'DB_PER_TENANT',
      rationale: 'Strict blast-radius, per-tenant encryption keys (CMEK), and independent point-in-time recovery required by enterprise/regulated tenants.',
    };
  }

  // 4. API & Real-Time Protocol Selection
  const apiProtocols: SelectedBackendArchitecture['apiProtocols'] = [
    { protocol: 'REST', useCase: 'Versioned resource CRUD, webhooks, file streaming, and public OpenAPI contracts' },
  ];
  if (profile.realtimeNeeds.includes('server_push_notifications') || profile.realtimeNeeds.includes('ai_token_streaming')) {
    apiProtocols.push({
      protocol: 'SSE',
      useCase: 'Unidirectional server-to-client live notifications and AI token streaming with Last-Event-ID resume',
    });
  }
  if (profile.realtimeNeeds.includes('bidirectional_rooms_presence')) {
    apiProtocols.push({
      protocol: 'WebSocket',
      useCase: 'Bidirectional low-latency rooms, collaborative state sync, cursor presence, and heartbeats backed by Redis/NATS PubSub',
    });
  }

  // 5. Event Broker & Queue Selection
  const eventAndQueueLayer =
    profile.expectedPeakRps > 5000 || profile.domainType === 'fintech_payments'
      ? {
          broker: 'Apache Kafka + BullMQ Workers',
          pattern: 'Committed Transactional Outbox -> Kafka Partitioned Log -> Idempotent Consumer Inbox + Saga Orchestrator',
          rationale: 'Durable log replay, strict per-partition ordering by aggregateId, and decoupled microservice consumers.',
        }
      : {
          broker: 'Redis BullMQ / RabbitMQ',
          pattern: 'Committed Transactional Outbox -> Lease-Locked Workers with Heartbeat Renewal & DLQ',
          rationale: 'Low operational overhead with delayed retries, priority queues, and dead-letter queue replay.',
        };

  return {
    primaryDatabase: {
      engine: 'PostgreSQL 16+',
      isolationDefault:
        profile.consistencyRequirement === 'strict_serializable_ledger'
          ? 'READ COMMITTED default + REPEATABLE READ / SERIALIZABLE for ledger & invariant transactions'
          : 'READ COMMITTED with atomic UPDATE RETURNING & deterministic FOR UPDATE row locking',
      poolingStrategy: 'PgBouncer Transaction Pooling + Primary/Replica Read-Your-Own-Writes router',
    },
    secondaryStores,
    tenancyStrategy,
    apiProtocols,
    eventAndQueueLayer,
    securityControls: [
      '4-Pillar Separation: Identity Verification vs. AuthN vs. Session Management vs. RBAC/ABAC/ReBAC AuthZ',
      'Probabilistic Risk-Based Authentication (RBA) + Hardware-Backed WebAuthn/Passkeys',
      'SSRF Safe Fetcher (Private CIDR + Cloud Metadata 169.254.169.254 blocklist)',
      'KMS/Vault Envelope Encryption (AES-256-GCM with AAD context binding)',
    ],
    latencySloByTier: {
      tier0_cached: 50,
      tier1_interactive: 200,
      tier2_complex: 600,
      tier3_async_cutoff: 1000,
    },
    drTargets:
      profile.domainType === 'fintech_payments' || profile.complianceFrameworks.includes('HIPAA')
        ? { rpoSeconds: 0, rtoSeconds: 60, backupStrategy: 'Synchronous standby replica + continuous WAL PITR archiving' }
        : { rpoSeconds: 300, rtoSeconds: 900, backupStrategy: 'Continuous WAL archiving (PITR) + daily verified snapshots' },
  };
}
```

---

## 2. Decision Matrix: When to Use Which Backend Pattern

| Architectural Question | Option A | Option B | Option C | Selection Rule |
| :--- | :--- | :--- | :--- | :--- |
| **Client-Server Real-Time Push** | **SSE (Server-Sent Events)** | **WebSockets** | **HTTP Long-Polling** | Choose **SSE** for unidirectional streams (AI responses, live tickers, order status, notifications) because it works natively over HTTP/2, proxies, and `Last-Event-ID`. Choose **WebSockets** only when true bidirectional low-latency client-to-server messaging (chat rooms, multiplayer canvas, collaborative cursors) is required. |
| **Distributed Consistency** | **Single-DB ACID Transaction** | **Transactional Outbox + Inbox** | **Saga (Orchestration / Choreography)** | Always keep strongly coupled invariants in a **Single-DB ACID Transaction** first. Use **Transactional Outbox + Inbox** to propagate committed state to search/cache/other services. Use a **Saga** with compensating transactions when a business workflow spans multiple external APIs or independent service databases. |
| **Message Broker Selection** | **Redis / BullMQ** | **RabbitMQ** | **Apache Kafka / NATS JetStream** | Choose **BullMQ** for background job queues (emails, PDFs, retries, delayed jobs). Choose **RabbitMQ** for complex routing topologies (topic/fanout/headers exchanges). Choose **Kafka / NATS JetStream** when you need an immutable, replayable event log with high throughput and partition-ordered stream processing. |
| **Multi-Tenant Isolation** | **Shared Table + RLS (`tenant_id`)** | **Schema-per-Tenant** | **Database-per-Tenant** | Default to **Shared Table + PostgreSQL RLS** for 95% of B2B SaaS apps (easiest migrations & connection pooling). Use **Schema-per-Tenant** only for moderate tenant counts needing logical separation. Use **Database-per-Tenant** for high-value enterprise/regulated tenants requiring physical isolation, custom residency, and independent restore. |
| **File Upload Pipeline** | **Direct Client-to-S3 Presigned PUT** | **Backend Streaming Proxy to Quarantine** | **In-Memory Multipart Buffer** | **Never** use In-Memory Multipart Buffering in production. Use **Presigned URLs** into a Quarantine bucket (triggers S3/GCS event -> Malware Scan Worker) for large files (`> 10MB`), or **Backend Streaming Proxy** with zero-buffer chunk transforms for strict synchronous header validation + quarantine ingest. |
