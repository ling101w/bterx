package traffic

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestStageDeleteContextCancelsWriteLockWait(t *testing.T) {
	tr, err := Open(t.TempDir(), "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer tr.Close()
	tr.wmu.Lock()
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Millisecond)
	defer cancel()
	_, err = tr.StageDeleteHostsExactContext(ctx, []string{"synthetic.example.test"})
	tr.wmu.Unlock()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("write lock ignored cancellation", err)
	}
	stage, err := tr.StageDeleteHostsExactContext(t.Context(), nil)
	if err != nil {
		t.Fatal("cancelled waiter retained the write lock", err)
	}
	if err := stage.Rollback(); err != nil {
		t.Fatal(err)
	}
}

func TestStageDeleteContextRollsBackCancelledSQL(t *testing.T) {
	root := t.TempDir()
	tr, err := Open(root, "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer tr.Close()
	_, err = tr.DB().Exec(`INSERT INTO exchanges(id,host,method,url,path) VALUES('cancel-fixture','synthetic.example.test','GET','https://synthetic.example.test/','');
CREATE TRIGGER slow_delete BEFORE DELETE ON exchanges BEGIN
 SELECT sum(value) FROM (WITH RECURSIVE counter(value) AS (SELECT 1 UNION ALL SELECT value+1 FROM counter WHERE value<100000000) SELECT value FROM counter);
END;`)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err = tr.StageDeleteHostsExactContext(ctx, []string{"synthetic.example.test"})
	if err == nil || time.Since(start) > 2*time.Second {
		t.Fatal("SQLite deletion ignored cancellation", err)
	}
	var count int
	if err := tr.DB().QueryRow(`SELECT count(*) FROM exchanges WHERE id='cancel-fixture'`).Scan(&count); err != nil || count != 1 {
		t.Fatal("cancelled delete removed committed traffic", count, err)
	}
	if _, err := tr.DB().Exec(`DROP TRIGGER slow_delete`); err != nil {
		t.Fatal(err)
	}
	stage, err := tr.StageDeleteHostsExactContext(t.Context(), []string{"synthetic.example.test"})
	if err != nil {
		t.Fatal("write lock or transaction survived cancellation", err)
	}
	if err := stage.Rollback(); err != nil {
		t.Fatal(err)
	}
}
