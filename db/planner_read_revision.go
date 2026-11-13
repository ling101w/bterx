package db

import (
	"context"
	"fmt"
)

// PlannerReadRevision invalidates round-local evidence reads on local/direct
// source changes. It deliberately excludes planner's own activity writes,
// which would otherwise invalidate the cache on every repeated tool call.
func (s *ExplorationStore) PlannerReadRevision(ctx context.Context) (string, error) {
	var revision string
	err := s.db.QueryRowContext(ctx, `WITH exps AS (
 SELECT $1::bigint AS id
 UNION SELECT source.exploration_id FROM tasks current
 JOIN task_relations relation ON relation.task_id=current.id
 JOIN tasks source ON source.id=relation.source_task_id AND source.deleted_at IS NULL
 WHERE current.exploration_id=$1 AND current.deleted_at IS NULL
), nodes AS (
 SELECT count(*) AS n,coalesce(max(updated_at)::text,'') AS latest,
 coalesce(sum(content_version),0)::text AS versions FROM exploration_nodes
 WHERE exploration_id IN (SELECT id FROM exps)
), edges AS (
 SELECT count(*) AS n,coalesce(max(created_at)::text,'') AS latest FROM exploration_edges
 WHERE exploration_id IN (SELECT id FROM exps)
) SELECT nodes.n::text||'/'||nodes.latest||'/'||nodes.versions||'/'||
 edges.n::text||'/'||edges.latest FROM nodes,edges`, s.expID).Scan(&revision)
	return revision, err
}

// Trace queries additionally depend on live worker output; ordinary fact reads
// must not be invalidated by every unrelated worker command.
func (s *ExplorationStore) PlannerTraceReadRevision(ctx context.Context) (string, error) {
	base, err := s.PlannerReadRevision(ctx)
	if err != nil {
		return "", err
	}
	var activityID int64
	err = s.db.QueryRowContext(ctx, `WITH exps AS (
 SELECT $1::bigint AS id UNION SELECT source.exploration_id FROM tasks current
 JOIN task_relations relation ON relation.task_id=current.id
 JOIN tasks source ON source.id=relation.source_task_id AND source.deleted_at IS NULL
 WHERE current.exploration_id=$1 AND current.deleted_at IS NULL
) SELECT coalesce(max(id),0) FROM activity WHERE exploration_id IN (SELECT id FROM exps)
 AND worker LIKE 'work%' AND kind IN ('tool_result','result')`, s.expID).Scan(&activityID)
	return fmt.Sprintf("%s/%d", base, activityID), err
}
