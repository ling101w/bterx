package server

import (
	"context"
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

func TestManagerDeleteContextRestoresFilesAndTraffic(t *testing.T) {
	if os.Getenv("ARTEX_RUNTIME_RECOVERY_TEST") != "1" {
		t.Skip("Disposable recovery database opt-in required")
	}
	u, err := url.Parse(os.Getenv("ARTEX_PG_DSN"))
	if err != nil || u.Hostname() != "127.0.0.1" || !strings.HasPrefix(u.Path, "/artex_runtime_test") {
		t.Fatal("Dedicated localhost runtime test database required")
	}
	dataDir := t.TempDir()
	m, err := NewManager(dataDir, "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { m.Close() })
	task, err := m.CreateTask("Synthetic external rollback", "No target access", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	taskID := mustTaskID(t, task.ID)
	host := fmt.Sprintf("cancel-delete-%d.example.test", taskID)
	if _, err := m.Assets().UpsertHTTPService(pgdb.UpsertHTTPServiceReq{URL: "https://" + host, TaskID: taskID}); err != nil {
		t.Fatal(err)
	}
	createDeleteFixture(t, dataDir, filepath.Join("tasks", task.ID), true)
	transcript := filepath.Join("transcripts", fmt.Sprintf("exp%d-main.jsonl", task.ExpID))
	createDeleteFixture(t, dataDir, transcript, false)
	tr, err := traffic.Open(filepath.Join(dataDir, "traffic"), "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	m.traffic = tr
	_, err = tr.DB().Exec(`INSERT INTO exchanges(id,host,method,url,path) VALUES('local-delete-proof',?,'GET',?,'')`, host, "https://"+host+"/")
	if err != nil {
		t.Fatal(err)
	}
	name := fmt.Sprintf("slow_delete_context_%d", taskID)
	_, err = m.pg.Exec(fmt.Sprintf(`CREATE FUNCTION %s() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN PERFORM pg_sleep(10); RETURN OLD; END$$;
CREATE TRIGGER %s BEFORE DELETE ON tasks FOR EACH ROW WHEN (OLD.id=%d) EXECUTE FUNCTION %s()`, name, name, taskID, name))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		m.pg.Exec(fmt.Sprintf(`DROP TRIGGER IF EXISTS %s ON tasks; DROP FUNCTION IF EXISTS %s()`, name, name))
		m.DeleteTask(task.ID, DeleteTaskOptions{DeleteAssets: true})
	})
	ctx, cancel := context.WithTimeout(t.Context(), 250*time.Millisecond)
	defer cancel()
	_, err = m.DeleteTaskContext(ctx, task.ID, DeleteTaskOptions{DeleteTraffic: true, DeleteFiles: true})
	if err == nil {
		t.Fatal("slow task deletion ignored cancellation")
	}
	if restored, err := m.pg.GetTask(taskID); err != nil || restored == nil {
		t.Fatal("cancelled delete lost task", err)
	}
	assertPathExists(t, filepath.Join(dataDir, "tasks", task.ID))
	assertPathExists(t, filepath.Join(dataDir, transcript))
	var count int
	if err := tr.DB().QueryRow(`SELECT count(*) FROM exchanges WHERE id='local-delete-proof'`).Scan(&count); err != nil || count != 1 {
		t.Fatal("traffic stage was not rolled back", count, err)
	}
	stage, err := tr.StageDeleteHostsExactContext(t.Context(), nil)
	if err != nil {
		t.Fatal("traffic write lock remained after rollback", err)
	}
	if err := stage.Rollback(); err != nil {
		t.Fatal(err)
	}
	probe, err := m.pg.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer probe.Rollback()
	if _, err := probe.Exec(`SET LOCAL lock_timeout='500ms'; LOCK TABLE assets, exploration_anchors IN SHARE ROW EXCLUSIVE MODE`); err != nil {
		t.Fatal("global asset lock remained after rollback", err)
	}
}
