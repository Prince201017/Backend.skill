# Module 00: Execution Intelligence & Architecture-Selection Engine

This module provides the **Requirements-Driven Architecture-Selection Engine** used to design the backend **for** any frontend or system specification. It evaluates operational complexity, failure modes, and measurable capacity evidence before introducing distributed infrastructure beyond a primary relational database.

---

## 1. Threat Model, Trust Boundaries & Operational Engineering Rules

### Threat Model & Architectural Failure Modes
1. **Premature Distributed Complexity**: Introducing Redis, Apache Kafka, Elasticsearch, and Kubernetes by default for workloads that fit comfortably inside a single PostgreSQL cluster creates **dual-write inconsistencies**, **split-brain failure modes**, **unpatched attack surface**, and **operational alert fatigue**.
2. **Unverified Availability & DR Claims**: Declaring `RPO = 0s` and `RTO = 60s` in a configuration object does not guarantee those outcomes during a region outage or corrupt migration. RPO and RTO are **target objectives** until verified by automated restore drills and failover chaos tests.
3. **Trust Boundary**: Architecture selection governs the boundaries between **Public Edge Ingress**, **Application Compute**, **Primary Transactional Storage**, **Asynchronous Workers**, and **External Third-Party Providers**. Every additional datastore or message broker introduces a new network trust boundary requiring TLS, authentication, network ACLs, and secret rotation.

### Mandatory vs. Optional Infrastructure Rule
- **Mandatory Baseline**: A single ACID relational database (PostgreSQL 16+) with connection pooling, transaction-scoped Row-Level Security (`FORCE ROW LEVEL SECURITY`), parameterized queries, and an in-database Transactional Outbox / Job table (`FOR UPDATE SKIP LOCKED`) is sufficient for the majority of early-to-mid-scale SaaS, FinTech, and E-Commerce workloads (typically up to $\sim 500\text{–}1,500$ write TPS and millions of rows on modern NVMe instances).
- **Evidence Gate for Additional Infrastructure**: Only introduce a secondary store (Redis/Valkey, OpenSearch/Meilisearch, Kafka/NATS, dedicated Vector DB) when a **specific functional capability** or **measured capacity threshold** cannot be met by PostgreSQL alone.

---

## 2. Requirements-Driven Architecture-Selection Engine

```typescript
export interface MeasuredCapacityAssumptions {
  sustainedReadRps: number;
  sustainedWriteRps: number;
  peakBurstRps: number;
  corpusDocumentCount: number;
  vectorEmbeddingCount: number;
  independentConsumerServiceCount: number;
  teamHasDedicatedPlatformSre: boolean;
}

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
  capacity: MeasuredCapacityAssumptions;
}

export interface InfrastructureRecommendation {
  role: string;
  selectedOption: string;
  simplerAlternative: string;
  evidenceTriggerToUpgrade: string;
  operationalFailureModes: string[];
  preferManagedServiceWhen: string;
}

export interface SelectedBackendArchitecture {
  computeRuntime: InfrastructureRecommendation;
  primaryDatabase: {
    engine: string;
    isolationDefault: string;
    poolingStrategy: string;
    failureModes: string[];
  };
  secondaryStores: InfrastructureRecommendation[];
  tenancyStrategy: {
    pattern: 'RLS_SHARED_SCHEMA' | 'SCHEMA_PER_TENANT' | 'DB_PER_TENANT';
    rationale: string;
    operationalCost: string;
  };
  apiProtocols: { protocol: 'REST' | 'GraphQL' | 'WebSocket' | 'SSE' | 'gRPC'; useCase: string }[];
  eventAndQueueLayer: InfrastructureRecommendation;
  mandatorySecurityControls: string[];
  latencySloTargetsMs: Record<'tier0_cached' | 'tier1_interactive' | 'tier2_complex' | 'tier3_async_cutoff', number>;
  drObjectives: {
    targetRpoSeconds: number;
    targetRtoSeconds: number;
    verificationRequirement: string;
    backupArchitecture: string;
  };
}

/**
 * Evidence-Based Architecture-Selection Engine:
 * Defaults to the simplest defensible architecture (PostgreSQL-first) and only introduces
 * Redis, external search engines, Kafka, or Kubernetes when justified by explicit functional
 * requirements or measured capacity constraints.
 */
export function selectBackendArchitecture(profile: SystemRequirementsProfile): SelectedBackendArchitecture {
  const { capacity } = profile;
  const secondaryStores: InfrastructureRecommendation[] = [];

  // 1. Cache, Rate Limiting & Ephemeral State Selection (Not a blind default!)
  const needsCrossPodPubSub = profile.realtimeNeeds.includes('bidirectional_rooms_presence');
  const needsHighThroughputRateLimiter = capacity.peakBurstRps > 1500 || capacity.sustainedReadRps > 2000;

  if (needsCrossPodPubSub || needsHighThroughputRateLimiter) {
    secondaryStores.push({
      role: 'Cache, Sub-Millisecond Rate Limiting & Realtime Pub/Sub Backplane',
      selectedOption: 'Managed Redis 7+ / Valkey',
      simplerAlternative: 'PostgreSQL UNLOGGED tables + in-process LRU cache (for < 1,000 RPS without WebSocket rooms)',
      evidenceTriggerToUpgrade:
        'Measured primary DB CPU > 40% spent on token-bucket/session updates, or multi-pod WebSocket room fanout required.',
      operationalFailureModes: [
        'Cache stampede on cold restart if single-flight coalescing is omitted',
        'Split-brain stale reads if eviction/invalidation fails after DB commit',
        'Memory exhaustion (OOM eviction) if keys lack explicit TTLs',
      ],
      preferManagedServiceWhen:
        'Always prefer managed Redis/Memorystore/ElastiCache unless running bare-metal with dedicated 24/7 SRE on-call.',
    });
  }

  // 2. Search Infrastructure Selection (Compare PostgreSQL FTS/pgvector vs. External Engines)
  const needsTypoOrFacetedSearch =
    profile.searchNeeds.includes('full_text_typo_tolerant') ||
    profile.searchNeeds.includes('faceted_ecommerce');

  if (needsTypoOrFacetedSearch) {
    const useDedicatedSearchEngine = capacity.corpusDocumentCount > 1_000_000 || capacity.sustainedReadRps > 500;
    secondaryStores.push({
      role: 'Full-Text & Faceted Search',
      selectedOption: useDedicatedSearchEngine
        ? 'Managed Meilisearch / OpenSearch (synced via Committed Outbox)'
        : 'PostgreSQL tsvector + GIN + pg_trgm indexes',
      simplerAlternative: 'PostgreSQL native FTS (tsvector + GIN) with pg_trgm trigram similarity',
      evidenceTriggerToUpgrade:
        'PostgreSQL GIN/trigram p95 query latency > 150ms on > 1M documents, or complex multi-attribute facet counts degrade OLTP buffer cache.',
      operationalFailureModes: [
        'Eventual consistency lag between PostgreSQL commit and search index visibility',
        'Out-of-order outbox delivery overwriting newer documents unless external version comparison is enforced',
      ],
      preferManagedServiceWhen:
        'Prefer managed Meilisearch Cloud / AWS OpenSearch whenever team size < 3 dedicated infrastructure engineers.',
    });
  }

  if (profile.searchNeeds.includes('hybrid_semantic_vector') || profile.domainType === 'ai_native_platform') {
    const useDedicatedVectorDb = capacity.vectorEmbeddingCount > 5_000_000;
    secondaryStores.push({
      role: 'Vector Similarity & Hybrid Search',
      selectedOption: useDedicatedVectorDb
        ? 'Dedicated Vector DB (Qdrant / Milvus) synced via Outbox'
        : 'PostgreSQL pgvector (HNSW index with halfvec/scalar quantization)',
      simplerAlternative: 'PostgreSQL pgvector inside primary or read-replica DB (zero cross-system sync lag, full ACID joins with tenant_id)',
      evidenceTriggerToUpgrade:
        'HNSW graph exceeds available PostgreSQL shared_buffers/RAM (> 5M–10M 1536-dim vectors) or vector recall queries starve transactional OLTP IOPS.',
      operationalFailureModes: [
        'HNSW index build memory spikes during large bulk backfills',
        'Post-filtering starvation in multi-tenant vector queries if iterative index scans (pgvector 0.8+) or tenant partitioning are not configured',
      ],
      preferManagedServiceWhen:
        'Use managed PostgreSQL with pgvector first; adopt managed Qdrant/Pinecone only after proving pgvector RAM/IOPS saturation.',
    });
  }

  // 3. Multi-Tenancy Strategy Selection
  let tenancyStrategy: SelectedBackendArchitecture['tenancyStrategy'] = {
    pattern: 'RLS_SHARED_SCHEMA',
    rationale:
      'Shared tables with composite (tenant_id, id) keys + PostgreSQL FORCE ROW LEVEL SECURITY + composite foreign keys.',
    operationalCost:
      'Lowest operational overhead: single schema migration pipeline and shared PgBouncer connection pool.',
  };

  if (profile.tenancyModel === 'enterprise_regulated_silos') {
    tenancyStrategy = {
      pattern: 'DB_PER_TENANT',
      rationale:
        'Physical database isolation required for per-tenant customer-managed encryption keys (CMEK), strict data residency, or independent tenant PITR restore.',
      operationalCost:
        'High operational cost: requires automated fleet migration orchestration, per-database connection pool limits, and tenant routing directory.',
    };
  }

  // 4. API & Real-Time Protocol Selection
  const apiProtocols: SelectedBackendArchitecture['apiProtocols'] = [
    { protocol: 'REST', useCase: 'Versioned resource CRUD, webhooks, streaming uploads, and OpenAPI 3.x contracts' },
  ];
  if (
    profile.realtimeNeeds.includes('server_push_notifications') ||
    profile.realtimeNeeds.includes('ai_token_streaming')
  ) {
    apiProtocols.push({
      protocol: 'SSE',
      useCase: 'Unidirectional server-to-client live feeds and AI token streaming over HTTP/2 with Last-Event-ID resume',
    });
  }
  if (profile.realtimeNeeds.includes('bidirectional_rooms_presence')) {
    apiProtocols.push({
      protocol: 'WebSocket',
      useCase: 'Bidirectional low-latency collaborative rooms and presence heartbeats',
    });
  }

  // 5. Event Broker & Queue Selection (PostgreSQL SKIP LOCKED vs. BullMQ vs. Kafka)
  let eventAndQueueLayer: InfrastructureRecommendation;
  if (capacity.independentConsumerServiceCount >= 4 || capacity.sustainedWriteRps > 3000) {
    eventAndQueueLayer = {
      role: 'Event Streaming & Asynchronous Background Jobs',
      selectedOption: 'Managed Kafka / NATS JetStream + Committed Transactional Outbox',
      simplerAlternative: 'PostgreSQL background_jobs table (FOR UPDATE SKIP LOCKED) or Redis BullMQ',
      evidenceTriggerToUpgrade:
        'Multiple independent microservice consumers require durable log replay, or sustained job enqueue rate exceeds > 2,000–3,000 jobs/sec.',
      operationalFailureModes: [
        'Consumer rebalance storms if max.poll.interval.ms is exceeded by slow handlers',
        'Partition hot-spotting if a single whale tenant_id or aggregate_id dominates traffic',
        'Outbox poison-pill head-of-line blocking if dead-letter quarantine is missing',
      ],
      preferManagedServiceWhen:
        'Always use Managed Kafka (Confluent / MSK) or NATS Cloud rather than self-hosting ZooKeeper/KRaft brokers without dedicated SREs.',
    };
  } else if (needsHighThroughputRateLimiter || needsCrossPodPubSub) {
    eventAndQueueLayer = {
      role: 'Asynchronous Background Jobs & Retries',
      selectedOption: 'PostgreSQL Transactional Outbox + Redis BullMQ Workers',
      simplerAlternative: 'Pure PostgreSQL job queue (FOR UPDATE SKIP LOCKED with lease heartbeats)',
      evidenceTriggerToUpgrade:
        'Redis is already deployed for caching/PubSub and sub-second delayed job scheduling at > 500 jobs/sec is needed.',
      operationalFailureModes: [
        'Lost jobs if Redis maxmemory-policy is not set to noeviction',
        'Duplicate execution if worker lease heartbeats fail without fencing token checks',
      ],
      preferManagedServiceWhen: 'Use managed Redis with AOF persistence and noeviction policy for queue instances.',
    };
  } else {
    eventAndQueueLayer = {
      role: 'Asynchronous Background Jobs & Transactional Outbox',
      selectedOption: 'PostgreSQL-Native Lease Queue & Outbox (FOR UPDATE SKIP LOCKED + Fencing Tokens)',
      simplerAlternative: 'None (this is the baseline zero-extra-infrastructure pattern)',
      evidenceTriggerToUpgrade:
        'Upgrade to Redis BullMQ or Kafka only when job polling/locking exceeds 15% of primary PostgreSQL CPU or > 1,000 jobs/sec.',
      operationalFailureModes: [
        'Table bloat if completed/processed rows are not pruned or partitioned regularly (pg_partman / daily batch delete)',
      ],
      preferManagedServiceWhen: 'Runs inside the primary managed PostgreSQL instance (Cloud SQL / RDS / Supabase).',
    };
  }

  // 6. Compute Runtime Selection (Managed Serverless Containers vs. Kubernetes)
  const computeRuntime: InfrastructureRecommendation =
    capacity.teamHasDedicatedPlatformSre && capacity.independentConsumerServiceCount >= 8
      ? {
          role: 'Application & Worker Compute Platform',
          selectedOption: 'Managed Kubernetes (GKE Autopilot / EKS) with Pod Disruption Budgets',
          simplerAlternative: 'Managed Serverless Containers (Google Cloud Run / AWS ECS Fargate / Fly.io)',
          evidenceTriggerToUpgrade:
            'Dedicated platform SRE team managing >= 8 microservices requiring custom service mesh, StatefulSets, or DaemonSets.',
          operationalFailureModes: [
            'Dropped in-flight requests during rolling deploys if preStop hooks and readiness draining are misconfigured',
            'Control-plane upgrade incompatibilities and CNI/ingress misconfigurations',
          ],
          preferManagedServiceWhen: 'Use GKE Autopilot or ECS Fargate to avoid manual node-group patching.',
        }
      : {
          role: 'Application & Worker Compute Platform',
          selectedOption: 'Managed Container Runtime (Google Cloud Run / AWS App Runner / ECS Fargate)',
          simplerAlternative: 'Single PaaS service + background worker process',
          evidenceTriggerToUpgrade:
            'Move to Kubernetes only when workload requires custom kernel/network topologies or dedicated node affinity.',
          operationalFailureModes: [
            'Cold-start latency spikes if min-instances is 0 on latency-sensitive Tier 1 APIs',
            'Connection pool exhaustion if max-instances * pool_size exceeds PostgreSQL max_connections (use PgBouncer!)',
          ],
          preferManagedServiceWhen: 'Default choice for teams without a dedicated Kubernetes platform team.',
        };

  return {
    computeRuntime,
    primaryDatabase: {
      engine: 'PostgreSQL 16+ (Managed Cloud SQL / RDS / Aurora / Supabase)',
      isolationDefault:
        profile.consistencyRequirement === 'strict_serializable_ledger'
          ? 'READ COMMITTED default + explicit REPEATABLE READ / SERIALIZABLE with 40001 retry for intersecting predicate invariants'
          : 'READ COMMITTED with single-statement atomic UPDATE ... RETURNING and deterministic sorted FOR UPDATE row locks',
      poolingStrategy:
        'Transaction-mode PgBouncer (or Supavisor / RDS Proxy) + explicit transaction-scoped SET LOCAL context',
      failureModes: [
        'Connection exhaustion if application pods open direct connections without a transaction pooler',
        'Cross-tenant context bleed if SET (session-level) is used instead of SET LOCAL (transaction-level) on pooled connections',
        'Lock queue cascading outages if DDL migrations run without SET lock_timeout = 2s',
      ],
    },
    secondaryStores,
    tenancyStrategy,
    apiProtocols,
    eventAndQueueLayer,
    mandatorySecurityControls: [
      'Server-Derived Identity & Active Tenant Membership Verification before setting DB transaction context (Module 13)',
      'Action-Specific RBAC + Verified Server-Side ReBAC Ownership Policy (Module 02)',
      'Fenced Idempotency Locks with Ambiguous Payment Reconciliation + Persistent Webhook Replay Guard (Module 04)',
      'Transport-Matched DNS-Pinned SSRF Dispatcher + CIDR-Verified Proxy IP Extraction (Module 08)',
      'Immutable Version/SHA-256 Bound Quarantine File Scanning & Mandatory CDR Sanitization (Module 05)',
    ],
    latencySloTargetsMs: {
      tier0_cached: 50,
      tier1_interactive: 200,
      tier2_complex: 600,
      tier3_async_cutoff: 1000,
    },
    drObjectives:
      profile.domainType === 'fintech_payments' || profile.complianceFrameworks.includes('HIPAA')
        ? {
            targetRpoSeconds: 0,
            targetRtoSeconds: 120,
            verificationRequirement:
              'Target objective only; requires synchronous multi-AZ standby + weekly automated PITR restore and failover chaos verification to certify actual RPO/RTO.',
            backupArchitecture: 'Multi-AZ synchronous standby replica + continuous WAL archiving to immutable WORM bucket',
          }
        : {
            targetRpoSeconds: 300,
            targetRtoSeconds: 900,
            verificationRequirement:
              'Target objective only; requires automated weekly PITR restore test into an ephemeral verification instance measuring actual recovery duration.',
            backupArchitecture: 'Continuous WAL archiving (PITR) + daily automated base snapshots',
          },
  };
}
```

---

## 3. Secure vs. Insecure Architecture Selection Patterns

| Pattern | Secure / Evidence-Based Practice | Insecure / Over-Engineered Anti-Pattern |
| :--- | :--- | :--- |
| **Queue & Outbox Selection** | Start with PostgreSQL `outbox_events` and `background_jobs` (`FOR UPDATE SKIP LOCKED`) inside the same ACID database; upgrade to BullMQ/Kafka only when measured DB CPU or multi-consumer replay requires it. | Deploying Kafka + ZooKeeper + Redis + Elasticsearch on Day 1 for a 50-RPS application, causing dual-write bugs and operational outages. |
| **Disaster Recovery Claims** | Document `targetRpoSeconds` and `targetRtoSeconds` as **objectives** and run an automated weekly restore pipeline that measures and alerts on actual recovery time. | Claiming "Guaranteed RPO=0 and RTO=60s" solely because a configuration file states those numbers without testing WAL replay or failover time. |
| **Vector & Full-Text Search** | Use PostgreSQL `tsvector` (GIN) and `pgvector` (HNSW) first so search queries enforce `tenant_id` and ACID visibility in a single store; move to OpenSearch/Qdrant only when corpus size or query latency demands it. | Syncing sensitive tenant documents to an external search cluster without outbox ordering (`_version_type: external`) or tenant ACL filters. |

---

## 4. Verification & Test Requirements for Architecture Decisions

1. **Baseline Simplicity Test**: Verify that a standard B2B SaaS profile (`sustainedReadRps: 200`, `sustainedWriteRps: 50`, `corpusDocumentCount: 50_000`, `realtimeNeeds: ['server_push_notifications']`) selects **PostgreSQL-native queues/search** and **Managed Container Runtime** without forcing Redis, Kafka, or Kubernetes.
2. **Scale Upgrade Trigger Test**: Verify that high-scale profiles (`sustainedWriteRps: 4_000`, `independentConsumerServiceCount: 6`, `vectorEmbeddingCount: 10_000_000`) deterministically select dedicated event streaming and vector infrastructure with documented failure modes.
3. **DR Qualification Check**: Verify that all DR outputs distinguish `targetRpoSeconds` / `targetRtoSeconds` from verified capabilities and mandate automated restore drills.

### Authoritative References
- **PostgreSQL 16 Concurrency & `FOR UPDATE SKIP LOCKED`**: https://www.postgresql.org/docs/current/sql-select.html#SQL-FOR-UPDATE-SHARE
- **pgvector HNSW Indexing & Iterative Scans**: https://github.com/pgvector/pgvector
- **AWS Well-Architected Framework — Reliability Pillar (RPO/RTO Verification)**: https://docs.aws.amazon.com/wellarchitected/latest/reliability-pillar/welcome.html
