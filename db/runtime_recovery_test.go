package db

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
)

func runtimeRecoveryDB(t *testing.T) *DB {
	t.Helper()
	if os.Getenv("ARTEX_RUNTIME_RECOVERY_TEST") != "1" {
		t.Skip("Dedicated runtime recovery database opt-in required")
	}
	dsn := os.Getenv("ARTEX_PG_DSN")
	u, err := url.Parse(dsn)
	if err != nil || u.Hostname() != "127.0.0.1" || !strings.HasPrefix(u.Path, "/artex_runtime_test") {
		t.Fatal("Use a dedicated localhost artex_runtime_test database")
	}
	d, err := Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	return d
}

func TestIntentWriteCancellationRollsBackBeforeRetry(t *testing.T) {
	d := runtimeRecoveryDB(t)
	task, err := d.CreateTask("Synthetic cancellation regression", "No target access", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.DeleteTask(task.ID) })
	asset, err := d.Assets().UpsertRootDomain(UpsertRootDomainReq{Domain: fmt.Sprintf("runtime-%d.example.test", task.ID), TaskID: task.ID})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Assets().DeleteByIDs([]int64{asset}) })
	store := d.Exploration(task.ExplorationID)
	parent, err := store.AddNode("fact", map[string]any{"summary": "Synthetic parent"}, 0, "confirmed", "test", nil)
	if err != nil {
		t.Fatal(err)
	}
	block, err := d.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer block.Rollback()
	var blockerPID int
	if err := block.QueryRow(`SELECT pg_backend_pid()`).Scan(&blockerPID); err != nil {
		t.Fatal(err)
	}
	if _, err := block.Exec(`LOCK TABLE exploration_anchors IN SHARE ROW EXCLUSIVE MODE`); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	payload := map[string]any{"summary": "Synthetic cancelled intent"}
	go func() {
		_, err := store.AddIntentWithParentsContext(ctx, payload, 5, []int64{asset}, []int64{parent}, "planner")
		done <- err
	}()
	deadline := time.Now().Add(3 * time.Second)
	for {
		var waiting bool
		if err := d.QueryRow(`SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE $1=ANY(pg_blocking_pids(pid)))`, blockerPID).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("intent never reached the held anchor lock")
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("cancelled write succeeded")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("cancelled intent kept waiting for the lock")
	}
	if err := block.Rollback(); err != nil {
		t.Fatal(err)
	}
	id, err := store.AddIntentWithParentsContext(t.Context(), payload, 5, []int64{asset}, []int64{parent}, "planner")
	if err != nil {
		t.Fatal(err)
	}
	var nodes, anchors, parents int
	if err := d.QueryRow(`SELECT count(*) FROM exploration_nodes WHERE exploration_id=$1 AND kind='intent' AND payload->>'summary'=$2`, task.ExplorationID, payload["summary"]).Scan(&nodes); err != nil {
		t.Fatal(err)
	}
	if err := d.QueryRow(`SELECT count(*) FROM exploration_anchors WHERE node_id=$1`, id).Scan(&anchors); err != nil {
		t.Fatal(err)
	}
	if err := d.QueryRow(`SELECT count(*) FROM exploration_edges WHERE exploration_id=$1 AND src_id=$2 AND dst_id=$3 AND rel='derived_from'`, task.ExplorationID, parent, id).Scan(&parents); err != nil {
		t.Fatal(err)
	}
	if nodes != 1 || anchors != 1 || parents != 1 {
		t.Fatalf("retry was not atomic: nodes=%d anchors=%d parents=%d", nodes, anchors, parents)
	}
}

func TestDeleteCancellationReleasesGlobalLocks(t *testing.T) {
	d := runtimeRecoveryDB(t)
	task, err := d.CreateTask("Synthetic deletion cancellation", "No target access", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.DeleteTask(task.ID) })
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	entered := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		_, err := d.DeleteTaskCascadePreparedContext(ctx, task.ID, false, false, false, func(TaskDeletePreparation) error { close(entered); <-ctx.Done(); return ctx.Err() })
		done <- err
	}()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("delete did not reach reversible preparation")
	}
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("cancelled deletion committed")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("delete cancellation did not return")
	}
	if task, err := d.GetTask(task.ID); err != nil || task == nil {
		t.Fatal("cancelled deletion lost the task", err)
	}
	probe, err := d.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer probe.Rollback()
	if _, err := probe.Exec(`SET LOCAL lock_timeout='500ms'; LOCK TABLE assets, exploration_anchors IN SHARE ROW EXCLUSIVE MODE`); err != nil {
		t.Fatal("global locks survived cancellation", err)
	}
}

func TestDeleteCancellationInterruptsCascade(t *testing.T) {
	d := runtimeRecoveryDB(t)
	task, err := d.CreateTask("Synthetic slow cascade", "No target access", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	name := fmt.Sprintf("runtime_slow_delete_%d", task.ID)
	_, err = d.Exec(fmt.Sprintf(`CREATE FUNCTION %s() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN PERFORM pg_sleep(10); RETURN OLD; END$$;
CREATE TRIGGER %s BEFORE DELETE ON explorations FOR EACH ROW WHEN (OLD.id=%d) EXECUTE FUNCTION %s()`, name, name, task.ExplorationID, name))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		d.Exec(fmt.Sprintf(`DROP TRIGGER IF EXISTS %s ON explorations; DROP FUNCTION IF EXISTS %s()`, name, name))
		d.DeleteTask(task.ID)
	})
	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err = d.DeleteTaskCascadePreparedContext(ctx, task.ID, true, false, false, nil)
	if err == nil || time.Since(start) > 2*time.Second {
		t.Fatal("cascade ignored caller deadline", err)
	}
	if task, err := d.GetTask(task.ID); err != nil || task == nil {
		t.Fatal("timed-out cascade lost the task", err)
	}
}
