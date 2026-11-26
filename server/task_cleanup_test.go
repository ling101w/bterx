package server

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	pgdb "github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/traffic"
)

func cleanupTestManager(t *testing.T) *Manager {
	t.Helper()
	if os.Getenv("ARTEX_RUNTIME_RECOVERY_TEST") != "1" {
		t.Skip("Disposable cleanup database opt-in required")
	}
	u, err := url.Parse(os.Getenv("ARTEX_PG_DSN"))
	if err != nil || u.Hostname() != "127.0.0.1" || !strings.HasPrefix(u.Path, "/artex_runtime_test") {
		t.Fatal("Dedicated localhost cleanup test database required")
	}
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { m.Close() })
	return m
}

func TestCleanupJobResumesAndPreservesSharedEvidence(t *testing.T) {
	m := cleanupTestManager(t)
	owner, err := m.CreateTask("synthetic cleanup owner", "No target access", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	other, err := m.CreateTask("synthetic shared owner", "No target access", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	ownerID := mustTaskID(t, owner.ID)
	otherID := mustTaskID(t, other.ID)
	t.Cleanup(func() {
		m.pg.Exec(`DELETE FROM task_cleanup_jobs WHERE task_id=$1`, ownerID)
		m.DeleteTask(owner.ID, DeleteTaskOptions{DeleteAssets: true, DeleteFindings: true})
		m.DeleteTask(other.ID, DeleteTaskOptions{DeleteAssets: true, DeleteFindings: true})
	})
	privateHost := fmt.Sprintf("private-%s.example.test", owner.ID)
	sharedHost := fmt.Sprintf("shared-%s.example.test", owner.ID)
	private, err := m.Assets().UpsertRootDomain(pgdb.UpsertRootDomainReq{Domain: privateHost, TaskID: ownerID})
	if err != nil {
		t.Fatal(err)
	}
	shared, err := m.Assets().UpsertRootDomain(pgdb.UpsertRootDomainReq{Domain: sharedHost, TaskID: ownerID})
	if err != nil {
		t.Fatal(err)
	}
	// A provenance-only association must protect the shared host and asset.
	if _, err := m.pg.Exec(`INSERT INTO task_asset_links(task_id,asset_id,source) VALUES($1,$2,'test')`, otherID, shared); err != nil {
		t.Fatal(err)
	}
	if _, err := m.pg.Exec(`INSERT INTO activity(exploration_id,kind,summary) SELECT $1,'test','synthetic' FROM generate_series(1,2501)`, owner.ExpID); err != nil {
		t.Fatal(err)
	}
	node, err := owner.Store.AddNode("fact", map[string]any{"summary": "synthetic"}, 0, "confirmed", "test", nil)
	if err != nil {
		t.Fatal(err)
	}
	finding, err := m.pg.AddFinding(ownerID, node, "test", "synthetic private report", "low", "test", "test", "test", nil)
	if err != nil {
		t.Fatal(err)
	}
	tr, err := traffic.Open(filepath.Join(m.dir, "traffic"), "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	m.traffic = tr
	for _, host := range []string{privateHost, sharedHost} {
		if _, err := tr.DB().Exec(`INSERT INTO exchanges(id,host,ts,path) VALUES(?,?,1,'')`, host, host); err != nil {
			t.Fatal(err)
		}
	}
	createDeleteFixture(t, m.dir, filepath.Join("tasks", owner.ID, "notes.txt"), false)
	createDeleteFixture(t, m.dir, filepath.Join("tasks", other.ID, "notes.txt"), false)
	s := &Server{m: m}
	j, err := s.queueTaskCleanup(t.Context(), owner.ID, DeleteTaskOptions{DeleteAssets: true, DeleteTraffic: true, DeleteFiles: true, DeleteFindings: true})
	if err != nil {
		t.Fatal(err)
	}
	duplicate, err := s.queueTaskCleanup(t.Context(), owner.ID, DeleteTaskOptions{})
	if err != nil || duplicate == nil || duplicate.ID != j.ID || string(duplicate.Plan) != string(j.Plan) {
		t.Fatal("repeat delete changed the cleanup plan", err)
	}
	if task, _ := m.pg.GetTask(ownerID); task != nil {
		t.Fatal("queued deletion stayed runnable")
	}
	// Make time deterministic without waiting for the capture cutoff second.
	var plan taskCleanupPlan
	if err := json.Unmarshal(j.Plan, &plan); err != nil {
		t.Fatal(err)
	}
	plan.Cutoff--
	raw, _ := json.Marshal(plan)
	if _, err := m.pg.Exec(`UPDATE task_cleanup_jobs SET plan=$2 WHERE id=$1`, j.ID, raw); err != nil {
		t.Fatal(err)
	}
	var firstID int64
	for i := 0; i < 200; i++ {
		ctx, cancel := context.WithTimeout(t.Context(), pgdb.TaskCleanupBatchTimeout)
		job, err := m.pg.TaskCleanupStep(ctx, s.taskCleanupStep)
		cancel()
		if err != nil {
			t.Fatal(err)
		}
		if job == nil {
			t.Fatal("job disappeared")
		}
		if firstID == 0 {
			firstID = job.ID
		} else if job.ID != firstID {
			t.Fatal("job identity changed")
		}
		// Recreate the coordinator between batches, as on a process restart.
		s = &Server{m: m}
		var p taskCleanupProgress
		json.Unmarshal(job.Progress, &p)
		if p.Phase == "activity" && p.ActivityDeleted > 0 && p.ActivityDeleted < 2501 {
			var remaining int
			if err := m.pg.QueryRow(`SELECT count(*) FROM activity WHERE exploration_id=$1`, owner.ExpID).Scan(&remaining); err != nil || remaining == 0 {
				t.Fatal("activity was not batched", remaining, err)
			}
		}
		if job.State == "done" {
			break
		}
		if i == 199 {
			t.Fatal("cleanup did not complete")
		}
	}
	for label, q := range map[string]string{"task": `SELECT count(*) FROM tasks WHERE id=$1`, "nodes": `SELECT count(*) FROM exploration_nodes WHERE exploration_id=$1`, "activity": `SELECT count(*) FROM activity WHERE exploration_id=$1`} {
		arg := owner.ExpID
		if label == "task" {
			arg = ownerID
		}
		var n int
		if err := m.pg.QueryRow(q, arg).Scan(&n); err != nil || n != 0 {
			t.Fatal(label, n, err)
		}
	}
	var n int
	if err := m.pg.QueryRow(`SELECT count(*) FROM assets WHERE id=$1`, shared).Scan(&n); err != nil || n != 1 {
		t.Fatal("shared asset lost", n, err)
	}
	if err := m.pg.QueryRow(`SELECT count(*) FROM assets WHERE id=$1`, private).Scan(&n); err != nil || n != 0 {
		t.Fatal("private asset retained", n, err)
	}
	if err := m.pg.QueryRow(`SELECT count(*) FROM findings WHERE id=$1`, finding).Scan(&n); err != nil || n != 0 {
		t.Fatal("private report retained", n, err)
	}
	if err := tr.DB().QueryRow(`SELECT count(*) FROM exchanges WHERE host=?`, sharedHost).Scan(&n); err != nil || n != 1 {
		t.Fatal("shared traffic lost", n, err)
	}
	if err := tr.DB().QueryRow(`SELECT count(*) FROM exchanges WHERE host=?`, privateHost).Scan(&n); err != nil || n != 0 {
		t.Fatal("private traffic retained", n, err)
	}
	assertPathMissing(t, filepath.Join(m.dir, "tasks", owner.ID))
	assertPathExists(t, filepath.Join(m.dir, "tasks", other.ID))
}

func TestCleanupFilesDoNotFollowOtherTaskSymlinks(t *testing.T) {
	root := t.TempDir()
	keep := filepath.Join(root, "tasks", "78", "important")
	createDeleteFixture(t, root, filepath.Join("tasks", "78", "important"), false)
	if err := os.MkdirAll(filepath.Join(root, "tasks", "77"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Dir(keep), filepath.Join(root, "tasks", "77", "shared")); err != nil {
		t.Skip(err)
	}
	for i := 0; i < 20; i++ {
		_, done, err := cleanupTaskFilesBatch(t.Context(), root, "77", 12, 1)
		if err != nil {
			t.Fatal(err)
		}
		if done {
			break
		}
	}
	assertPathExists(t, keep)
	assertPathMissing(t, filepath.Join(root, "tasks", "77"))
}

func TestCleanupBatchCancellationRetainsJobProgress(t *testing.T) {
	m := cleanupTestManager(t)
	task, err := m.CreateTask("synthetic cancel cleanup", "No target access", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	id := mustTaskID(t, task.ID)
	t.Cleanup(func() {
		m.pg.Exec(`DELETE FROM task_cleanup_jobs WHERE task_id=$1`, id)
		m.DeleteTask(task.ID, DeleteTaskOptions{})
	})
	s := &Server{m: m}
	j, err := s.queueTaskCleanup(t.Context(), task.ID, DeleteTaskOptions{})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Millisecond)
	defer cancel()
	_, err = m.pg.TaskCleanupStep(ctx, func(ctx context.Context, tx *sql.Tx, job *pgdb.TaskCleanupJob) error {
		job.Progress = json.RawMessage(`{"phase":"done"}`)
		_, err := tx.ExecContext(ctx, `SELECT pg_sleep(10)`)
		return err
	})
	if err == nil {
		t.Fatal("batch ignored cancellation")
	}
	jobs, err := m.pg.ListTaskCleanups(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	for _, job := range jobs {
		if job.ID == j.ID && string(job.Progress) != "{}" {
			t.Fatal("cancelled progress committed", string(job.Progress))
		}
	}
}

func TestCleanupPreservesSharingAddedAfterQueueAndCommonReportFiles(t *testing.T) {
	m := cleanupTestManager(t)
	owner, err := m.CreateTask("synthetic late sharing", "No target access", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	other, err := m.CreateTask("synthetic second owner", "No target access", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	id := mustTaskID(t, owner.ID)
	otherID := mustTaskID(t, other.ID)
	host := fmt.Sprintf("late-share-%d.example.test", id)
	asset, err := m.Assets().UpsertRootDomain(pgdb.UpsertRootDomainReq{Domain: host, TaskID: id})
	if err != nil {
		t.Fatal(err)
	}
	f1, err := m.pg.AddFinding(id, 0, "test", "shared report", "low", "test", "test", "test", nil)
	if err != nil {
		t.Fatal(err)
	}
	f2, err := m.pg.AddFinding(otherID, 0, "test", "other report", "low", "test", "test", "test", nil)
	if err != nil {
		t.Fatal(err)
	}
	var caseID int64
	if err := m.pg.QueryRow(`INSERT INTO finding_cases(task_id,origin_task_id,title,reason) VALUES($1,$1,'shared fixture','test') RETURNING id`, id).Scan(&caseID); err != nil {
		t.Fatal(err)
	}
	if _, err := m.pg.Exec(`INSERT INTO finding_case_members(finding_id,case_id) VALUES($1,$3),($2,$3)`, f1, f2, caseID); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		m.pg.Exec(`DELETE FROM task_cleanup_jobs WHERE task_id=$1`, id)
		m.pg.Exec(`DELETE FROM finding_case_members WHERE case_id=$1;DELETE FROM finding_case_events WHERE case_id=$1;DELETE FROM finding_cases WHERE id=$1`, caseID)
		m.pg.DeleteTaskCascade(id, true, true)
		m.pg.DeleteTaskCascade(otherID, true, true)
		m.pg.Exec(`DELETE FROM findings WHERE id=ANY($1)`, []int64{f1, f2})
	})
	tr, err := traffic.Open(filepath.Join(m.dir, "traffic"), "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	m.traffic = tr
	if _, err := tr.DB().Exec(`INSERT INTO exchanges(id,host,ts,path) VALUES('late',?,1,'')`, host); err != nil {
		t.Fatal(err)
	}
	createDeleteFixture(t, m.dir, filepath.Join("tasks", owner.ID, "shared-proof.txt"), false)
	s := &Server{m: m}
	j, err := s.queueTaskCleanup(t.Context(), owner.ID, DeleteTaskOptions{DeleteAssets: true, DeleteTraffic: true, DeleteFiles: true, DeleteFindings: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.Assets().UpsertRootDomain(pgdb.UpsertRootDomainReq{Domain: host, TaskID: otherID}); err != nil {
		t.Fatal(err)
	}
	var plan taskCleanupPlan
	json.Unmarshal(j.Plan, &plan)
	plan.Cutoff--
	raw, _ := json.Marshal(plan)
	if _, err := m.pg.Exec(`UPDATE task_cleanup_jobs SET plan=$2 WHERE id=$1`, j.ID, raw); err != nil {
		t.Fatal(err)
	}
	completed := false
	for i := 0; i < 50; i++ {
		job, err := m.pg.TaskCleanupStep(t.Context(), s.taskCleanupStep)
		if err != nil {
			t.Fatal(err)
		}
		if job != nil && job.ID == j.ID && job.State == "done" {
			completed = true
			break
		}
	}
	if !completed {
		t.Fatal("late-sharing cleanup did not complete")
	}
	listed, err := m.pg.ListTaskCleanups(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	for _, job := range listed {
		if job.ID == j.ID {
			t.Fatal("completed cleanup job should not remain in active cleanup list")
		}
	}
	for label, q := range map[string]string{"shared asset": `SELECT count(*) FROM assets WHERE id=$1`, "shared report": `SELECT count(*) FROM findings WHERE id=$1`} {
		arg := asset
		if label == "shared report" {
			arg = f1
		}
		var n int
		if err := m.pg.QueryRow(q, arg).Scan(&n); err != nil || n != 1 {
			t.Fatal(label, n, err)
		}
	}
	var n int
	if err := tr.DB().QueryRow(`SELECT count(*) FROM exchanges WHERE host=?`, host).Scan(&n); err != nil || n != 1 {
		t.Fatal("late sharing lost traffic", n, err)
	}
	assertPathExists(t, filepath.Join(m.dir, "tasks", owner.ID, "shared-proof.txt"))
}
