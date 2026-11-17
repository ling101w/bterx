-- Independent experience data: no foreign keys to task or finding lifecycles.
-- Preserve the quoted schema token for Database.migrate's safe substitution.
CREATE SCHEMA IF NOT EXISTS "artex_experience";

CREATE TABLE IF NOT EXISTS "artex_experience".curation_runs (
    id TEXT PRIMARY KEY, conversation_id BIGINT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('prepared','running','no_source','saved','partial','skipped','failed','cancelled')),
    snapshots JSONB NOT NULL DEFAULT '{}', saved_entry_ids JSONB NOT NULL DEFAULT '[]',
    rejected_items JSONB NOT NULL DEFAULT '[]', skipped_items JSONB NOT NULL DEFAULT '[]',
    attempt_count INTEGER NOT NULL DEFAULT 0, error_code TEXT NOT NULL DEFAULT '',
    started_at TIMESTAMPTZ NOT NULL DEFAULT now(), finished_at TIMESTAMPTZ,
    lease_until TIMESTAMPTZ NOT NULL DEFAULT now()+interval '8 minutes'
);
CREATE INDEX IF NOT EXISTS experience_curation_conversation
    ON "artex_experience".curation_runs(conversation_id,started_at DESC);
CREATE UNIQUE INDEX IF NOT EXISTS experience_curation_active_conversation
    ON "artex_experience".curation_runs(conversation_id) WHERE status IN ('prepared','running');
ALTER TABLE "artex_experience".curation_runs ADD COLUMN IF NOT EXISTS trigger_type TEXT NOT NULL DEFAULT 'manual';

CREATE TABLE IF NOT EXISTS "artex_experience".intent_experiences (
    exploration_id BIGINT NOT NULL, task_id BIGINT NOT NULL, intent_id BIGINT NOT NULL,
    experience_id TEXT NOT NULL, experience_revision TEXT NOT NULL, method_snapshot JSONB NOT NULL,
    adopted_at TIMESTAMPTZ NOT NULL DEFAULT now(), result_state TEXT NOT NULL DEFAULT 'pending_execution',
    terminal_state TEXT NOT NULL DEFAULT '', evidence_node_ids JSONB NOT NULL DEFAULT '[]',
    evidence_activity_ids JSONB NOT NULL DEFAULT '[]', feedback_state TEXT NOT NULL DEFAULT 'awaiting_execution',
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(), PRIMARY KEY(intent_id,experience_id)
);
CREATE INDEX IF NOT EXISTS experience_intent_results
    ON "artex_experience".intent_experiences(task_id,result_state,feedback_state);

-- Operator-managed exclusions keep validation/self-test sources out of the
-- learning set. No task/finding foreign key: exclusion survives source cleanup.
CREATE TABLE IF NOT EXISTS "artex_experience".source_exclusions (
    source_key TEXT PRIMARY KEY,
    reason TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS "artex_experience".sources (
    source_key TEXT PRIMARY KEY,
    source_type TEXT NOT NULL,
    source_id BIGINT NOT NULL,
    source_task_id BIGINT,
    revision TEXT NOT NULL,
    snapshot_id TEXT NOT NULL,
    snapshot JSONB NOT NULL,
    published_revision TEXT NOT NULL DEFAULT '',
    observed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    published_at TIMESTAMPTZ,
    lease_until TIMESTAMPTZ
);
ALTER TABLE "artex_experience".sources
    ADD COLUMN IF NOT EXISTS published_extractor_version TEXT NOT NULL DEFAULT '';

CREATE TABLE IF NOT EXISTS "artex_experience".entries (
    id TEXT PRIMARY KEY,
    source_key TEXT NOT NULL,
    source_revision TEXT NOT NULL,
    source_task_id BIGINT,
    source_company_ids JSONB NOT NULL DEFAULT '[]'::jsonb,
    snapshot_id TEXT NOT NULL,
    title TEXT NOT NULL DEFAULT '',
    category TEXT NOT NULL DEFAULT '',
    tags JSONB NOT NULL DEFAULT '[]'::jsonb,
    applicable_when TEXT NOT NULL DEFAULT '',
    steps JSONB NOT NULL DEFAULT '[]'::jsonb,
    success_criteria TEXT NOT NULL DEFAULT '',
    pitfalls JSONB NOT NULL DEFAULT '[]'::jsonb,
    not_applicable TEXT NOT NULL DEFAULT '',
    outcome TEXT NOT NULL DEFAULT 'inconclusive'
        CHECK (outcome IN ('success','negative','inconclusive')),
    evidence JSONB NOT NULL DEFAULT '[]'::jsonb,
    status TEXT NOT NULL DEFAULT 'candidate'
        CHECK (status IN ('candidate','verified','deprecated')),
    verification_basis TEXT NOT NULL DEFAULT '',
    transfer_scope TEXT NOT NULL DEFAULT 'project'
        CHECK (transfer_scope IN ('generic','project')),
    extractor_version TEXT NOT NULL DEFAULT '1',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT experience_source_revision_unique
        UNIQUE(source_key, source_revision, extractor_version),
    CONSTRAINT experience_tags_array CHECK (jsonb_typeof(tags)='array'),
    CONSTRAINT experience_steps_array CHECK (jsonb_typeof(steps)='array'),
    CONSTRAINT experience_pitfalls_array CHECK (jsonb_typeof(pitfalls)='array'),
    CONSTRAINT experience_company_array CHECK (jsonb_typeof(source_company_ids)='array')
);

CREATE TABLE IF NOT EXISTS "artex_experience".usage (
    id BIGSERIAL PRIMARY KEY,
    experience_id TEXT NOT NULL,
    task_id BIGINT,
    intent_id BIGINT,
    event TEXT NOT NULL
        CHECK (event IN ('retrieved','adopted','helpful','unhelpful','not_applicable')),
    note TEXT NOT NULL DEFAULT '',
    run_key TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Additive v3 migration: older entries keep their original steps and receive
-- an empty chain until they are extracted from a new bounded source snapshot.
ALTER TABLE "artex_experience".entries
    ADD COLUMN IF NOT EXISTS attack_chain JSONB NOT NULL DEFAULT '[]'::jsonb;
ALTER TABLE "artex_experience".entries
    ADD COLUMN IF NOT EXISTS root_cause TEXT NOT NULL DEFAULT '';
DO $experience_chain_migration$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint
      WHERE conname='experience_attack_chain_array'
      AND conrelid='"artex_experience".entries'::regclass) THEN
        ALTER TABLE "artex_experience".entries ADD CONSTRAINT experience_attack_chain_array
          CHECK (jsonb_typeof(attack_chain)='array');
    END IF;
END $experience_chain_migration$;

CREATE INDEX IF NOT EXISTS experience_entries_status_time
    ON "artex_experience".entries(status, updated_at DESC);
CREATE INDEX IF NOT EXISTS experience_entries_source_task
    ON "artex_experience".entries(source_task_id, status);
CREATE INDEX IF NOT EXISTS experience_entries_source
    ON "artex_experience".entries(source_key, source_revision);
CREATE INDEX IF NOT EXISTS experience_entries_tags
    ON "artex_experience".entries USING GIN(tags);
CREATE INDEX IF NOT EXISTS experience_sources_pending
    ON "artex_experience".sources(observed_at, lease_until)
    WHERE published_revision<>revision;
CREATE INDEX IF NOT EXISTS experience_usage_entry_time
    ON "artex_experience".usage(experience_id, created_at DESC);
CREATE INDEX IF NOT EXISTS experience_usage_task
    ON "artex_experience".usage(task_id, created_at DESC);
CREATE UNIQUE INDEX IF NOT EXISTS experience_usage_run_dedup
    ON "artex_experience".usage(
        experience_id, COALESCE(task_id,0), COALESCE(intent_id,0), event, run_key
    ) WHERE run_key<>'';

-- Explicit method review is distinct from a confirmed source finding.
CREATE TABLE IF NOT EXISTS "artex_experience".reviews (
    id BIGSERIAL PRIMARY KEY,
    experience_id TEXT NOT NULL,
    decision TEXT NOT NULL CHECK (decision IN ('verified','candidate','deprecated')),
    note TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS experience_reviews_entry
    ON "artex_experience".reviews(experience_id,id DESC);

-- Retain a method while its cited facts remain unchanged. Additional facts in
-- the source task do not invalidate an unrelated, already extracted method.
ALTER TABLE "artex_experience".entries
    ADD COLUMN IF NOT EXISTS dependency_revisions JSONB NOT NULL DEFAULT '{}'::jsonb;
ALTER TABLE "artex_experience".entries
    ADD COLUMN IF NOT EXISTS method_key TEXT NOT NULL DEFAULT '';
ALTER TABLE "artex_experience".usage
    ADD COLUMN IF NOT EXISTS evidence_node_ids JSONB NOT NULL DEFAULT '[]'::jsonb;
ALTER TABLE "artex_experience".usage
    ADD COLUMN IF NOT EXISTS evidence_activity_ids JSONB NOT NULL DEFAULT '[]'::jsonb;
