package db

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// RetractFact marks a non-origin fact node as retracted or disputed and records
// structured retraction provenance inside its payload without deleting history.
func (s *ExplorationStore) RetractFact(factID int64, state, reason, by string, evidenceActivityID int64) (*Node, error) {
	if factID <= 0 {
		return nil, fmt.Errorf("invalid fact_id")
	}
	if state != StateFactRetracted && state != StateFactDisputed {
		return nil, fmt.Errorf("invalid fact state %q: must be %q or %q", state, StateFactRetracted, StateFactDisputed)
	}
	reason = strings.TrimSpace(reason)
	if reason == "" {
		return nil, fmt.Errorf("retraction reason is required")
	}
	if strings.TrimSpace(by) == "" {
		by = "supervisor"
	}

	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	var kind, curState string
	var rawPayload []byte
	err = tx.QueryRow(`SELECT kind, state, payload FROM exploration_nodes
WHERE id=$1 AND exploration_id=$2 FOR UPDATE`, factID, s.expID).Scan(&kind, &curState, &rawPayload)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("fact #%d not found in this task", factID)
	}
	if err != nil {
		return nil, err
	}
	if kind != KindFact {
		return nil, fmt.Errorf("node #%d is %q, not a fact", factID, kind)
	}
	if curState == StateOrigin {
		return nil, fmt.Errorf("origin fact #%d cannot be retracted", factID)
	}

	payload := map[string]any{}
	if len(rawPayload) > 0 {
		_ = json.Unmarshal(rawPayload, &payload)
	}
	retraction := map[string]any{
		"state":      state,
		"reason":     reason,
		"by":         by,
		"prev_state": curState,
		"at":         time.Now().UTC().Format(time.RFC3339),
	}
	if evidenceActivityID > 0 {
		retraction["evidence_activity_id"] = evidenceActivityID
	}
	payload["retraction"] = retraction
	updatedPayload, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	updatedPayload = jsonbClean(updatedPayload)

	node, err := scanNode(tx.QueryRow(`UPDATE exploration_nodes
SET state=$1, payload=$2, content_version=content_version+1
WHERE id=$3 AND exploration_id=$4
RETURNING `+nodeCols, state, string(updatedPayload), factID, s.expID))
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return node, nil
}

// DependentActiveIntents returns all downstream intent nodes (open, running, or
// paused) reachable from rootNodeID along derived_from / yields edges within this
// exploration. Used by supervisor_retract_fact to cascade-stop intents built on a
// retracted hallucination.
func (s *ExplorationStore) DependentActiveIntents(rootNodeID int64) ([]*Node, error) {
	if rootNodeID <= 0 {
		return nil, nil
	}
	rows, err := s.db.Query(`
WITH RECURSIVE downstream(id, depth) AS (
	SELECT dst_id, 1
	FROM exploration_edges
	WHERE exploration_id=$1 AND src_id=$2 AND rel IN ('derived_from', 'yields')
	UNION
	SELECT e.dst_id, d.depth + 1
	FROM exploration_edges e
	JOIN downstream d ON e.src_id = d.id
	WHERE e.exploration_id=$1 AND e.rel IN ('derived_from', 'yields') AND d.depth < 12
)
SELECT `+nodeCols+`
FROM exploration_nodes
WHERE exploration_id=$1
  AND kind='intent'
  AND state IN ('open', 'running', 'paused')
  AND id IN (SELECT id FROM downstream)
ORDER BY id ASC`, s.expID, rootNodeID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanNodes(rows)
}

// AssetNotesForAssets returns recent active asset-scoped notes/pitfalls anchored
// to any of assetIDs within this exploration. Retracted, disputed, unverified, and
// origin nodes are excluded so workers only receive verified, live asset intel.
func (s *ExplorationStore) AssetNotesForAssets(assetIDs []int64, limit int) ([]*Node, error) {
	if len(assetIDs) == 0 {
		return nil, nil
	}
	if limit <= 0 {
		limit = 8
	}
	args := make([]any, 0, len(assetIDs)+2)
	args = append(args, s.expID)
	marks := make([]string, 0, len(assetIDs))
	for _, id := range assetIDs {
		args = append(args, id)
		marks = append(marks, "$"+fmt.Sprint(len(args)))
	}
	args = append(args, limit)
	limitPlaceholder := "$" + fmt.Sprint(len(args))
	rows, err := s.db.Query(`
SELECT `+nodeCols+`
FROM exploration_nodes n
WHERE n.exploration_id=$1
  AND n.kind='fact'
  AND n.state='confirmed'
  AND (
    COALESCE(n.payload->>'asset_note', '') = 'true'
    OR n.origin = 'supervisor'
  )
  AND EXISTS (
    SELECT 1 FROM exploration_anchors a
    WHERE a.node_id = n.id AND a.asset_id IN (`+strings.Join(marks, ",")+`)
  )
ORDER BY n.id DESC
LIMIT `+limitPlaceholder, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	nodes, err := scanNodes(rows)
	if err != nil || len(nodes) == 0 {
		return nodes, err
	}
	ids := make([]int64, len(nodes))
	for i, n := range nodes {
		ids[i] = n.ID
	}
	if anchors, err := s.NodeAnchors(ids); err == nil {
		for _, n := range nodes {
			n.Anchors = anchors[n.ID]
		}
	}
	return nodes, nil
}

// NodeAnchors loads asset anchor IDs for the given exploration node IDs.
func (s *ExplorationStore) NodeAnchors(nodeIDs []int64) (map[int64][]int64, error) {
	if len(nodeIDs) == 0 {
		return map[int64][]int64{}, nil
	}
	args := make([]any, 0, len(nodeIDs)+1)
	args = append(args, s.expID)
	marks := make([]string, 0, len(nodeIDs))
	for _, id := range nodeIDs {
		args = append(args, id)
		marks = append(marks, "$"+fmt.Sprint(len(args)))
	}
	rows, err := s.db.Query(`
SELECT a.node_id, a.asset_id
FROM exploration_anchors a
JOIN exploration_nodes n ON n.id = a.node_id
WHERE n.exploration_id = $1 AND a.node_id IN (`+strings.Join(marks, ",")+`)
ORDER BY a.node_id, a.asset_id`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make(map[int64][]int64, len(nodeIDs))
	for rows.Next() {
		var nid, aid int64
		if err := rows.Scan(&nid, &aid); err != nil {
			return nil, err
		}
		out[nid] = append(out[nid], aid)
	}
	return out, rows.Err()
}

// VerifyActivityBelongsToExploration checks whether activityID exists inside this
// exploration and returns its summary record (nil if absent).
func (s *ExplorationStore) VerifyActivityBelongsToExploration(activityID int64) (*Activity, error) {
	if activityID <= 0 {
		return nil, nil
	}
	var a Activity
	var nodeID sql.NullInt64
	var tool sql.NullString
	var summary sql.NullString
	err := s.db.QueryRow(`
SELECT id, node_id, COALESCE(worker,''), COALESCE(kind,''), tool, is_error, summary, created_at
FROM activity
WHERE id=$1 AND exploration_id=$2`, activityID, s.expID).Scan(
		&a.ID, &nodeID, &a.Worker, &a.Kind, &tool, &a.IsError, &summary, &a.CreatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if nodeID.Valid {
		v := nodeID.Int64
		a.NodeID = &v
	}
	a.Tool = tool.String
	a.Summary = summary.String
	return &a, nil
}

// GetActivityWithDetail returns one activity row including its full Detail body
// for bounded supervisor drill-down (nil if absent in this exploration).
func (s *ExplorationStore) GetActivityWithDetail(activityID int64) (*Activity, error) {
	if activityID <= 0 {
		return nil, nil
	}
	var a Activity
	var nodeID sql.NullInt64
	var tool, summary, detail sql.NullString
	err := s.db.QueryRow(`
SELECT id, node_id, COALESCE(worker,''), COALESCE(kind,''), tool, is_error, summary, detail, created_at
FROM activity
WHERE id=$1 AND exploration_id=$2`, activityID, s.expID).Scan(
		&a.ID, &nodeID, &a.Worker, &a.Kind, &tool, &a.IsError, &summary, &detail, &a.CreatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if nodeID.Valid {
		v := nodeID.Int64
		a.NodeID = &v
	}
	a.Tool = tool.String
	a.Summary = summary.String
	a.Detail = detail.String
	return &a, nil
}
