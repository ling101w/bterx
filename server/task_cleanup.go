package server

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	pgdb "github.com/Autumn-27/artex/db"
)

type taskCleanupPlan struct {
	Options  DeleteTaskOptions `json:"options"`
	AssetIDs []int64           `json:"asset_ids"`
	Hosts    []string          `json:"hosts"`
	Cutoff   int64             `json:"cutoff"`
	MaxRowID int64             `json:"max_rowid"`
}

type taskCleanupProgress struct {
	Phase           string           `json:"phase"`
	Cursor          int              `json:"cursor"`
	ActivityDeleted int64            `json:"activity_deleted"`
	NodesDeleted    int64            `json:"nodes_deleted"`
	KeepFiles       bool             `json:"keep_files,omitempty"`
	Result          DeleteTaskResult `json:"result"`
}

func (s *Server) queueTaskCleanup(ctx context.Context, id string, opts DeleteTaskOptions) (*pgdb.TaskCleanupJob, error) {
	if opts.DeleteTraffic && s.m.traffic == nil {
		return nil, errors.New("流量存储未就绪，尚未提交删除；请恢复流量存储后重试")
	}
	n, _ := strconv.ParseInt(id, 10, 64)
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	j, err := s.m.pg.QueueTaskCleanup(ctx, n, func(tx *sql.Tx, expID int64) (json.RawMessage, error) {
		p := taskCleanupPlan{Options: opts, Cutoff: time.Now().Unix()}
		if opts.DeleteAssets || opts.DeleteTraffic {
			if err := pgdb.LockCleanupOwnership(ctx, tx); err != nil {
				return nil, err
			}
		}
		var err error
		if opts.DeleteAssets {
			p.AssetIDs, err = pgdb.CleanupAssetIDs(ctx, tx, n, expID)
			if err != nil {
				return nil, err
			}
		}
		if opts.DeleteTraffic {
			p.Hosts, err = pgdb.CleanupTrafficHosts(ctx, tx, n, expID)
			if err != nil {
				return nil, err
			}
			if s.m.traffic != nil {
				p.MaxRowID, err = s.m.traffic.CleanupWatermark(ctx)
				if err != nil {
					return nil, err
				}
			}
		}
		return json.Marshal(p)
	})
	if err == nil {
		s.m.forgetTask(id, n)
	}
	return j, err
}

func (s *Server) startTaskCleanupWorker() {
	if s.m.pg == nil {
		return
	}
	s.cleanupWG.Add(1)
	go func() {
		defer s.cleanupWG.Done()
		timer := time.NewTimer(0)
		defer timer.Stop()
		for {
			select {
			case <-s.ctx.Done():
				return
			case <-timer.C:
			}
			ctx, cancel := context.WithTimeout(s.ctx, pgdb.TaskCleanupBatchTimeout)
			j, err := s.m.pg.TaskCleanupStep(ctx, s.taskCleanupStep)
			cancel()
			if err != nil && s.ctx.Err() == nil {
				if j != nil {
					failureCtx, stop := context.WithTimeout(s.ctx, 3*time.Second)
					if failErr := s.m.pg.FailTaskCleanup(failureCtx, j.ID, err); failErr != nil {
						log.Printf("[task-cleanup] record failure %d: %v", j.ID, failErr)
					}
					stop()
				}
				log.Printf("[task-cleanup] batch: %v", err)
			}
			delay := 100 * time.Millisecond
			if j == nil || err != nil {
				delay = time.Second
			}
			timer.Reset(delay)
		}
	}()
}

func (s *Server) taskCleanupStep(ctx context.Context, tx *sql.Tx, j *pgdb.TaskCleanupJob) error {
	var plan taskCleanupPlan
	var p taskCleanupProgress
	if err := json.Unmarshal(j.Plan, &plan); err != nil {
		return err
	}
	if err := json.Unmarshal(j.Progress, &p); err != nil {
		return err
	}
	if p.Phase == "" {
		p.Phase = "traffic"
		p.Result.Deleted = strconv.FormatInt(j.TaskID, 10)
	}
	next := func(phase string) { p.Phase = phase; p.Cursor = 0 }
	switch p.Phase {
	case "traffic":
		if !plan.Options.DeleteTraffic {
			next("assets")
			break
		}
		if p.Cursor >= len(plan.Hosts) {
			next("blobs")
			break
		}
		if time.Now().Unix() <= plan.Cutoff {
			break
		}
		if s.m.traffic == nil {
			return errors.New("流量存储未就绪，保留剩余数据，请恢复流量存储后重试")
		}
		if err := pgdb.LockCleanupOwnership(ctx, tx); err != nil {
			return err
		}
		allowed, err := pgdb.CleanupTrafficHosts(ctx, tx, j.TaskID, j.ExplorationID)
		if err != nil {
			return err
		}
		set := make(map[string]bool, len(allowed))
		for _, h := range allowed {
			set[h] = true
		}
		end := min(p.Cursor+32, len(plan.Hosts))
		hosts := make([]string, 0, end-p.Cursor)
		for _, h := range plan.Hosts[p.Cursor:end] {
			if set[h] {
				hosts = append(hosts, h)
			}
		}
		// SQLite commits first; if the progress transaction fails, retrying the
		// same host group is harmless. Every batch rechecks current ownership.
		limit := max(1, 64>>j.Attempts)
		n, exhausted, err := s.m.traffic.DeleteHostsBatchContext(ctx, hosts, plan.Cutoff, plan.MaxRowID, limit, fmt.Sprintf("task:%d", j.TaskID))
		if err != nil {
			return err
		}
		p.Result.TrafficDeleted = n
		if exhausted {
			p.Cursor = end
		}
	case "blobs":
		if s.m.traffic != nil {
			done, legacy, err := s.m.traffic.CollectCleanupBlobsContext(ctx, 32)
			if err != nil {
				return err
			}
			if !done {
				break
			}
			if legacy {
				p.Result.CleanupWarning = "历史流量仍引用磁盘文件，相关 blob 的空间回收已延后"
			}
			s.m.traffic.ReclaimAfterCleanup()
		}
		next("assets")
	case "assets":
		if !plan.Options.DeleteAssets || p.Cursor >= len(plan.AssetIDs) {
			next("activity")
			break
		}
		if err := pgdb.LockCleanupOwnership(ctx, tx); err != nil {
			return err
		}
		end := min(p.Cursor+max(1, 100>>j.Attempts), len(plan.AssetIDs))
		ids := plan.AssetIDs[p.Cursor:end]
		res, err := tx.ExecContext(ctx, `DELETE FROM assets a WHERE a.id=ANY($1) AND NOT EXISTS(SELECT 1 FROM tasks t WHERE t.id<>$2 AND t.deleted_at IS NULL AND t.id=ANY(a.task_ids)) AND NOT EXISTS(SELECT 1 FROM exploration_anchors ea JOIN exploration_nodes n ON n.id=ea.node_id JOIN tasks t ON t.exploration_id=n.exploration_id WHERE ea.asset_id=a.id AND t.id<>$2 AND t.deleted_at IS NULL) AND NOT EXISTS(SELECT 1 FROM task_asset_links link JOIN tasks t ON t.id=link.task_id WHERE link.asset_id=a.id AND t.id<>$2 AND t.deleted_at IS NULL)`, ids, j.TaskID)
		if err != nil {
			return err
		}
		n, _ := res.RowsAffected()
		p.Result.AssetsDeleted += n
		res, err = tx.ExecContext(ctx, `UPDATE assets SET task_ids=array_remove(task_ids,$2) WHERE id=ANY($1) AND $2=ANY(task_ids)`, ids, j.TaskID)
		if err != nil {
			return err
		}
		n, _ = res.RowsAffected()
		p.Result.AssetsDetached += n
		p.Cursor = end
	case "activity":
		n, err := cleanupDeleteRows(ctx, tx, `DELETE FROM activity WHERE id IN (SELECT id FROM activity WHERE exploration_id=$1 ORDER BY id LIMIT $2)`, j.ExplorationID, max(1, 1000>>j.Attempts))
		if err != nil {
			return err
		}
		p.ActivityDeleted += n
		if n == 0 {
			next("findings")
		}
	case "findings":
		if !plan.Options.DeleteFindings {
			next("nodes")
			break
		}
		n, err := cleanupDeleteRows(ctx, tx, `DELETE FROM findings WHERE id IN (SELECT f.id FROM findings f WHERE f.task_id=$1 AND NOT EXISTS(SELECT 1 FROM finding_case_members m JOIN finding_case_members other ON other.case_id=m.case_id JOIN findings f2 ON f2.id=other.finding_id JOIN tasks t ON t.id=f2.task_id WHERE m.finding_id=f.id AND t.id<>$1 AND t.deleted_at IS NULL) ORDER BY f.id LIMIT $2)`, j.TaskID, max(1, 50>>j.Attempts))
		if err != nil {
			return err
		}
		p.Result.FindingsDeleted += n
		if n == 0 {
			next("nodes")
		}
	case "nodes":
		n, err := cleanupDeleteRows(ctx, tx, `DELETE FROM exploration_nodes WHERE id IN (SELECT id FROM exploration_nodes WHERE exploration_id=$1 ORDER BY id LIMIT $2)`, j.ExplorationID, max(1, 100>>j.Attempts))
		if err != nil {
			return err
		}
		p.NodesDeleted += n
		if n == 0 {
			next("records")
		}
	case "records":
		if !plan.Options.DeleteLLMRecords {
			next("database")
			break
		}
		n, err := cleanupDeleteRows(ctx, tx, `DELETE FROM llm_records WHERE id IN (SELECT id FROM llm_records WHERE COALESCE(task_id,'')=$1 ORDER BY id LIMIT $2)`, strconv.FormatInt(j.TaskID, 10), max(1, 100>>j.Attempts))
		if err != nil {
			return err
		}
		p.Result.LLMRecordsDeleted += n
		if n == 0 {
			next("database")
		}
	case "database":
		// The heavy graph has already gone. No global asset lock is held here.
		// After draining a large exploration, stale statistics can still make
		// foreign-key cascades scan the entire activity heap for zero rows. These
		// probes should use their indexes; keep this choice local to this batch.
		if _, err := tx.ExecContext(ctx, `SET LOCAL enable_seqscan=off; SET LOCAL plan_cache_mode=force_custom_plan`); err != nil {
			return err
		}
		if plan.Options.DeleteFindings {
			if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM findings WHERE task_id=$1)`, j.TaskID).Scan(&p.KeepFiles); err != nil {
				return err
			}
			if p.KeepFiles {
				p.Result.CleanupWarning = "已保留被其他任务共用的漏洞报告及工作文件"
			}
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM tasks WHERE id=$1 AND deleted_at IS NOT NULL`, j.TaskID); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM explorations WHERE id=$1`, j.ExplorationID); err != nil {
			return err
		}
		next("files")
	case "files":
		if plan.Options.DeleteFiles && !p.KeepFiles {
			changed, done, err := cleanupTaskFilesBatch(ctx, s.m.dir, strconv.FormatInt(j.TaskID, 10), j.ExplorationID, 2048)
			p.Result.FilesDeleted = p.Result.FilesDeleted || changed
			if err != nil {
				return err
			}
			if !done {
				break
			}
		}
		next("done")
		j.State = "done"
	default:
		return fmt.Errorf("unknown task cleanup phase %q", p.Phase)
	}
	raw, err := json.Marshal(p)
	j.Progress = raw
	return err
}

func cleanupDeleteRows(ctx context.Context, tx *sql.Tx, query string, args ...any) (int64, error) {
	res, err := tx.ExecContext(ctx, query, args...)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// Workspaces and transcripts have exact owners. Bound unlink work and never
// follow symlinks into another task's workspace. A restart simply re-enumerates.
func cleanupTaskFilesBatch(ctx context.Context, root, id string, expID int64, limit int) (changed, done bool, err error) {
	if _, ok := canonicalTaskID(id); !ok {
		return false, false, errors.New("invalid task id")
	}
	targets := []string{filepath.Join(root, "tasks", id)}
	entries, err := os.ReadDir(filepath.Join(root, "transcripts"))
	if err != nil && !os.IsNotExist(err) {
		return false, false, err
	}
	prefix := fmt.Sprintf("exp%d-", expID)
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), prefix) && (e.IsDir() || strings.HasSuffix(e.Name(), ".jsonl")) {
			targets = append(targets, filepath.Join(root, "transcripts", e.Name()))
		}
	}
	for _, path := range targets {
		if err := ctx.Err(); err != nil {
			return changed, false, err
		}
		removed, finished, e := cleanupRemoveTree(ctx, path, &limit)
		changed = changed || removed
		if e != nil {
			return changed, false, e
		}
		if !finished {
			return changed, false, nil
		}
	}
	return changed, true, nil
}

func cleanupRemoveTree(ctx context.Context, path string, left *int) (changed, done bool, err error) {
	if err := ctx.Err(); err != nil {
		return false, false, err
	}
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return false, true, nil
	}
	if err != nil {
		return false, false, err
	}
	if *left <= 0 {
		return false, false, nil
	}
	if info.IsDir() {
		entries, err := os.ReadDir(path)
		if err != nil {
			return false, false, err
		}
		for _, e := range entries {
			c, d, err := cleanupRemoveTree(ctx, filepath.Join(path, e.Name()), left)
			changed = changed || c
			if err != nil {
				return changed, false, err
			}
			if !d {
				return changed, false, nil
			}
		}
	}
	if *left <= 0 {
		return changed, false, nil
	}
	if err := ctx.Err(); err != nil {
		return changed, false, err
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return changed, false, err
	}
	*left--
	return true, true, nil
}

func (s *Server) listTaskCleanups(w http.ResponseWriter, r *http.Request) {
	jobs, err := s.m.pg.ListTaskCleanups(r.Context())
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"jobs": jobs})
}

func (s *Server) retryTaskCleanup(w http.ResponseWriter, r *http.Request) {
	id, ok := pathInt(r, "id")
	if !ok {
		writeErr(w, 400, "invalid id")
		return
	}
	ok, err := s.m.pg.RetryTaskCleanup(r.Context(), id)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if !ok {
		writeErr(w, 409, "清理任务未处于失败状态")
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}
