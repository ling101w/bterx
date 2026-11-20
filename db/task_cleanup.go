package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

type TaskCleanupJob struct {
	ID            int64           `json:"id"`
	TaskID        int64           `json:"task_id"`
	ExplorationID int64           `json:"exploration_id"`
	TaskName      string          `json:"task_name"`
	Plan          json.RawMessage `json:"-"`
	Progress      json.RawMessage `json:"progress"`
	State         string          `json:"state"`
	Attempts      int             `json:"attempts"`
	LastError     string          `json:"last_error,omitempty"`
}

const cleanupColumns = `id,task_id,exploration_id,task_name,plan,progress,state,attempts,last_error`

func scanTaskCleanup(row interface{ Scan(...any) error }) (*TaskCleanupJob, error) {
	var j TaskCleanupJob
	err := row.Scan(&j.ID, &j.TaskID, &j.ExplorationID, &j.TaskName, &j.Plan, &j.Progress, &j.State, &j.Attempts, &j.LastError)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return &j, err
}

// QueueTaskCleanup hides and freezes a drained task atomically with a durable
// deletion plan. The caller must have installed the runtime deletion barrier.
func (d *DB) QueueTaskCleanup(ctx context.Context, id int64, plan func(*sql.Tx, int64) (json.RawMessage, error)) (*TaskCleanupJob, error) {
	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `SET LOCAL lock_timeout='2s'`); err != nil {
		return nil, err
	}
	var expID int64
	var name string
	err = tx.QueryRowContext(ctx, `SELECT exploration_id,COALESCE(name,'') FROM tasks WHERE id=$1 AND deleted_at IS NULL FOR UPDATE`, id).Scan(&expID, &name)
	if errors.Is(err, sql.ErrNoRows) {
		return scanTaskCleanup(tx.QueryRowContext(ctx, `SELECT `+cleanupColumns+` FROM task_cleanup_jobs WHERE task_id=$1`, id))
	}
	if err != nil {
		return nil, err
	}
	var busy bool
	if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM task_archives WHERE task_id=$1 AND state NOT IN ('archive_failed','restored'))`, id).Scan(&busy); err != nil {
		return nil, err
	}
	if busy {
		return nil, fmt.Errorf("任务正在归档，请先完成归档操作")
	}
	raw, err := plan(tx, expID)
	if err != nil {
		return nil, err
	}
	j, err := scanTaskCleanup(tx.QueryRowContext(ctx, `INSERT INTO task_cleanup_jobs(task_id,exploration_id,task_name,plan) VALUES($1,$2,$3,$4) RETURNING `+cleanupColumns, id, expID, name, raw))
	if err != nil {
		return nil, err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE tasks SET deleted_at=now(),paused=true,queued=false,queued_at=NULL,run_segment_started_at=NULL WHERE id=$1`, id); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return j, nil
}

// TaskCleanupStep holds only this job's row lock by default. The handler may
// briefly exclude asset writers when checking ownership, but must never perform
// graph or filesystem cleanup under that global lock.
func (d *DB) TaskCleanupStep(ctx context.Context, step func(context.Context, *sql.Tx, *TaskCleanupJob) error) (*TaskCleanupJob, error) {
	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `SET LOCAL lock_timeout='500ms'`); err != nil {
		return nil, err
	}
	j, err := scanTaskCleanup(tx.QueryRowContext(ctx, `SELECT `+cleanupColumns+` FROM task_cleanup_jobs WHERE state='pending' AND next_attempt_at<=now() ORDER BY next_attempt_at,id FOR UPDATE SKIP LOCKED LIMIT 1`))
	if err != nil || j == nil {
		return j, err
	}
	if err = step(ctx, tx, j); err != nil {
		return j, err
	}
	_, err = tx.ExecContext(ctx, `UPDATE task_cleanup_jobs SET progress=$2,state=$3,attempts=0,last_error='',next_attempt_at=now(),updated_at=now(),completed_at=CASE WHEN $3='done' THEN now() ELSE NULL END WHERE id=$1`, j.ID, j.Progress, j.State)
	if err != nil {
		return j, err
	}
	return j, tx.Commit()
}

func (d *DB) FailTaskCleanup(ctx context.Context, id int64, cause error) error {
	// Successful batches reset attempts, so slow but progressing jobs do not fail.
	msg := cause.Error()
	if len(msg) > 600 {
		msg = msg[:600]
	}
	_, err := d.ExecContext(ctx, `UPDATE task_cleanup_jobs SET attempts=attempts+1,last_error=$2,state=CASE WHEN attempts>=4 THEN 'failed' ELSE 'pending' END,next_attempt_at=now()+interval '5 seconds',updated_at=now() WHERE id=$1 AND state='pending'`, id, msg)
	return err
}

func (d *DB) ListTaskCleanups(ctx context.Context) ([]*TaskCleanupJob, error) {
	rows, err := d.QueryContext(ctx, `SELECT `+cleanupColumns+` FROM task_cleanup_jobs ORDER BY (state<>'done') DESC,id DESC LIMIT 30`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	jobs := make([]*TaskCleanupJob, 0)
	for rows.Next() {
		j, err := scanTaskCleanup(rows)
		if err != nil {
			return nil, err
		}
		jobs = append(jobs, j)
	}
	return jobs, rows.Err()
}

func (d *DB) RetryTaskCleanup(ctx context.Context, id int64) (bool, error) {
	res, err := d.ExecContext(ctx, `UPDATE task_cleanup_jobs SET state='pending',attempts=0,last_error='',next_attempt_at=now(),updated_at=now() WHERE id=$1 AND state='failed'`, id)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n > 0, err
}

// These ownership helpers are used only while the short batch transaction
// excludes asset/anchor writers. Include provenance-only associations too.
func LockCleanupOwnership(ctx context.Context, tx *sql.Tx) error {
	_, err := tx.ExecContext(ctx, `LOCK TABLE assets, exploration_anchors, task_asset_links IN SHARE ROW EXCLUSIVE MODE`)
	return err
}

func CleanupAssetIDs(ctx context.Context, tx *sql.Tx, taskID, expID int64) ([]int64, error) {
	rows, err := tx.QueryContext(ctx, `SELECT id FROM assets WHERE $1=ANY(task_ids) UNION SELECT asset_id FROM exploration_anchors ea JOIN exploration_nodes n ON n.id=ea.node_id WHERE n.exploration_id=$2 UNION SELECT asset_id FROM task_asset_links WHERE task_id=$1`, taskID, expID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	ids := make([]int64, 0)
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

func CleanupTrafficHosts(ctx context.Context, tx *sql.Tx, taskID, expID int64) ([]string, error) {
	return hostsForTaskDeletionContext(ctx, tx, taskID, expID)
}

// Export the batch cap for tests without depending on wall-clock performance.
const TaskCleanupBatchTimeout = 5 * time.Second
