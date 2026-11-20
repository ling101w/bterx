package traffic

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCleanupTrafficSnapshotReceiptAndSharedBlobs(t *testing.T) {
	tr, err := Open(t.TempDir(), "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer tr.Close()
	shared := strings.Repeat("a", 64)
	own := strings.Repeat("b", 64)
	for _, h := range []string{shared, own} {
		path := filepath.Join(tr.dir, "_blobs", "sha256", h[:2], h+".bin")
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("synthetic"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 5; i++ {
		id := fmt.Sprint(i)
		host := "own.example.test"
		if i == 4 {
			host = "shared.example.test"
		}
		if _, err := tr.db.Exec(`INSERT INTO exchanges(id,host,ts,path) VALUES(?,?,1,'')`, id, host); err != nil {
			t.Fatal(err)
		}
		h := own
		if i == 3 || i == 4 {
			h = shared
		}
		if _, err := tr.db.Exec(`INSERT INTO blob_refs(hash,exchange_id) VALUES(?,?)`, h, id); err != nil {
			t.Fatal(err)
		}
	}
	watermark, err := tr.CleanupWatermark(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tr.db.Exec(`INSERT INTO exchanges(id,host,ts,path) VALUES('new','own.example.test',3,'')`); err != nil {
		t.Fatal(err)
	}
	var total int64
	for i := 0; i < 5; i++ {
		n, done, err := tr.DeleteHostsBatchContext(t.Context(), []string{"own.example.test"}, 2, watermark, 2, "test-job")
		if err != nil {
			t.Fatal(err)
		}
		total = n
		if done {
			break
		}
	}
	if total != 4 {
		t.Fatalf("receipt=%d, want 4", total)
	}
	n, done, err := tr.DeleteHostsBatchContext(t.Context(), nil, 2, watermark, 2, "test-job")
	if err != nil || !done || n != 4 {
		t.Fatal("receipt replay lost progress", n, done, err)
	}
	var left int
	if err := tr.db.QueryRow(`SELECT count(*) FROM exchanges`).Scan(&left); err != nil || left != 2 {
		t.Fatal("new or shared traffic removed", left, err)
	}
	if done, legacy, err := tr.CollectCleanupBlobsContext(t.Context(), 10); err != nil || !done || legacy {
		t.Fatal(done, legacy, err)
	}
	if _, err := tr.blobPath(shared); err != nil {
		t.Fatal("shared blob deleted", err)
	}
	if _, err := tr.blobPath(own); err == nil {
		t.Fatal("orphaned private blob retained")
	}
}

func TestCleanupTrafficCancellationKeepsBatch(t *testing.T) {
	tr, err := Open(t.TempDir(), "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer tr.Close()
	if _, err := tr.db.Exec(`INSERT INTO exchanges(id,host,ts) VALUES('one','own.example.test',1)`); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, _, err := tr.DeleteHostsBatchContext(ctx, []string{"own.example.test"}, 2, 10, 2, "cancelled"); err == nil {
		t.Fatal("cancelled batch succeeded")
	}
	var n int
	if err := tr.db.QueryRow(`SELECT count(*) FROM exchanges`).Scan(&n); err != nil || n != 1 {
		t.Fatal("cancelled batch committed", n, err)
	}
}

func TestCleanupLegacyStageRecoversCommittedDeletion(t *testing.T) {
	tr, err := Open(t.TempDir(), "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer tr.Close()
	host := "legacy.example.test"
	path := filepath.Join(tr.dir, sanitize(host), "request.http")
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("synthetic legacy capture"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := tr.db.Exec(`INSERT INTO exchanges(id,host,ts,path) VALUES('legacy',?,1,?)`, host, host+"/request.http"); err != nil {
		t.Fatal(err)
	}
	watermark, err := tr.CleanupWatermark(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if _, done, err := tr.DeleteHostsBatchContext(t.Context(), []string{host}, 2, watermark, 10, "legacy-job"); err != nil || !done {
		t.Fatal(done, err)
	}
	tr.reaping.Wait()
	// Simulate the process exiting after the SQLite commit and before the
	// asynchronous filesystem reaper starts. The recovery journal must identify
	// the exact hosts even when PostgreSQL progress has already advanced.
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("synthetic recovery capture"), 0600); err != nil {
		t.Fatal(err)
	}
	stage, _, err := tr.stageTreesForArchive([]string{filepath.Dir(path)}, []string{host}, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := tr.RecoverHostDeleteStages(nil); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("committed legacy directory was restored", err)
	}
	if _, err := os.Stat(stage); !os.IsNotExist(err) {
		t.Fatal("completed legacy stage retained", err)
	}
}
