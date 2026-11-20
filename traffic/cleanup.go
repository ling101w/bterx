package traffic

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func (t *Traffic) CleanupWatermark(ctx context.Context) (int64, error) {
	var n int64
	err := t.db.QueryRowContext(ctx, `SELECT COALESCE(max(rowid),0) FROM exchanges`).Scan(&n)
	return n, err
}

// DeleteHostsBatchContext deletes a bounded slice of a frozen traffic snapshot.
// The coordinator must exclude ownership changes until this call returns. A
// SQLite receipt is committed with the rows, so replay after a process exit
// cannot lose or double-count progress. Blob collection is a separate phase.
func (t *Traffic) DeleteHostsBatchContext(ctx context.Context, hosts []string, cutoff, maxRowID int64, limit int, receipt string) (total int64, exhausted bool, err error) {
	if err = t.lockWriteContext(ctx); err != nil {
		return
	}
	defer t.wmu.Unlock()
	tx, err := t.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, false, err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS cleanup_blob_candidates(hash TEXT PRIMARY KEY); CREATE TABLE IF NOT EXISTS cleanup_receipts(job TEXT PRIMARY KEY, deleted INTEGER NOT NULL DEFAULT 0)`); err != nil {
		return 0, false, err
	}
	if _, err = tx.ExecContext(ctx, `INSERT OR IGNORE INTO cleanup_receipts(job) VALUES(?)`, receipt); err != nil {
		return 0, false, err
	}
	var n int64
	if len(hosts) > 0 {
		placeholders := strings.TrimSuffix(strings.Repeat("?,", len(hosts)), ",")
		args := make([]any, 0, len(hosts)+3)
		for _, h := range hosts {
			args = append(args, h)
		}
		args = append(args, cutoff, maxRowID, limit)
		where := `rowid IN (SELECT rowid FROM exchanges WHERE host IN (` + placeholders + `) AND COALESCE(ts,0)<=? AND rowid<=? ORDER BY rowid LIMIT ?)`
		if _, err = tx.ExecContext(ctx, `INSERT OR IGNORE INTO cleanup_blob_candidates(hash) SELECT hash FROM blob_refs WHERE exchange_id IN (SELECT id FROM exchanges WHERE `+where+`)`, args...); err != nil {
			return 0, false, err
		}
		n, err = t.deleteWhereContext(ctx, tx, where, args...)
		if err != nil {
			return 0, false, err
		}
	}
	if _, err = tx.ExecContext(ctx, `UPDATE cleanup_receipts SET deleted=deleted+? WHERE job=?`, n, receipt); err != nil {
		return 0, false, err
	}
	if err = tx.QueryRowContext(ctx, `SELECT deleted FROM cleanup_receipts WHERE job=?`, receipt).Scan(&total); err != nil {
		return 0, false, err
	}
	// Legacy host directories are renamed only after every exchange for that
	// host is gone, including newer captures excluded from the snapshot.
	var dirs []string
	var directoryHosts []string
	if n < int64(limit) {
		for _, host := range hosts {
			var remaining bool
			if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM exchanges WHERE host=?)`, host).Scan(&remaining); err != nil {
				return 0, false, err
			}
			if !remaining {
				dirs = append(dirs, filepath.Join(t.dir, sanitize(host)))
				directoryHosts = append(directoryHosts, host)
			}
		}
	}
	stage, moves, err := t.stageTreesForArchive(dirs, directoryHosts, 0, 0)
	if err != nil {
		_ = restoreTrees(stage, moves)
		return 0, false, err
	}
	if err = tx.Commit(); err != nil {
		_ = restoreTrees(stage, moves)
		return 0, false, err
	}
	t.reapStage(stage)
	return total, n < int64(limit), nil
}

// CollectCleanupBlobsContext bounds physical collection and checks references
// under the recorder lock. Legacy file references cannot be proven absent from
// SQLite, so leave those candidates for the existing legacy-aware collector.
func (t *Traffic) CollectCleanupBlobsContext(ctx context.Context, limit int) (done bool, legacy bool, err error) {
	if err = t.lockWriteContext(ctx); err != nil {
		return
	}
	defer t.wmu.Unlock()
	if _, err = t.db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS cleanup_blob_candidates(hash TEXT PRIMARY KEY)`); err != nil {
		return
	}
	if err = t.db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM exchanges WHERE path<>'')`).Scan(&legacy); err != nil {
		return
	}
	if legacy {
		return true, true, nil
	}
	rows, err := t.db.QueryContext(ctx, `SELECT hash FROM cleanup_blob_candidates ORDER BY hash LIMIT ?`, limit)
	if err != nil {
		return false, false, err
	}
	var hashes []string
	for rows.Next() {
		var h string
		if err = rows.Scan(&h); err != nil {
			rows.Close()
			return false, false, err
		}
		hashes = append(hashes, h)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return false, false, err
	}
	for _, h := range hashes {
		if !blobHashRe.MatchString(h) {
			return false, false, fmt.Errorf("invalid cleanup blob hash")
		}
		var live bool
		if err = t.db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM blob_refs WHERE hash=?)`, h).Scan(&live); err != nil {
			return false, false, err
		}
		if !live {
			for _, path := range []string{filepath.Join(t.dir, "_blobs", "sha256", h[:2], h+".bin"), filepath.Join(t.dir, "_blobs", "sha256", h[:2], h[2:4], h+".bin")} {
				if err = os.Remove(path); err != nil && !os.IsNotExist(err) {
					return false, false, err
				}
			}
		}
		if _, err = t.db.ExecContext(ctx, `DELETE FROM cleanup_blob_candidates WHERE hash=?`, h); err != nil {
			return false, false, err
		}
	}
	return len(hashes) < limit, false, nil
}

func (t *Traffic) ReclaimAfterCleanup() { t.reclaim() }
