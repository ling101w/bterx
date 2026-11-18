package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/artex/db"
)

func TestAddIntentToolCancellationDoesNotCommitLater(t *testing.T) {
	if os.Getenv("ARTEX_RUNTIME_RECOVERY_TEST") != "1" {
		t.Skip("Dedicated recovery database opt-in required")
	}
	u, err := url.Parse(os.Getenv("ARTEX_PG_DSN"))
	if err != nil || u.Hostname() != "127.0.0.1" || !strings.HasPrefix(u.Path, "/artex_runtime_test") {
		t.Fatal("Dedicated localhost runtime test database required")
	}
	d, err := db.Open(os.Getenv("ARTEX_PG_DSN"))
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	task, err := d.CreateTask("Synthetic tool cancellation", "No target access", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer d.DeleteTask(task.ID)
	asset, err := d.Assets().UpsertRootDomain(db.UpsertRootDomainReq{Domain: fmt.Sprintf("tool-cancel-%d.example.test", task.ID), TaskID: task.ID})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Assets().DeleteByIDs([]int64{asset})
	store := d.Exploration(task.ExplorationID)
	tools := NewToolSet(store, "planner")
	tool := tools.addIntent()
	block, err := d.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer block.Rollback()
	if _, err := block.Exec(`LOCK TABLE exploration_anchors IN SHARE ROW EXCLUSIVE MODE`); err != nil {
		t.Fatal(err)
	}
	input, _ := json.Marshal(map[string]any{"summary": "Synthetic cancel and retry", "asset_ids": []int64{asset}})
	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	result, err := tool.Call(ctx, input, nil)
	if err == nil && !result.IsError {
		t.Fatal("cancelled tool reported success")
	}
	if time.Since(start) > 2*time.Second {
		t.Fatal("tool ignored its cancellation context")
	}
	if err := block.Rollback(); err != nil {
		t.Fatal(err)
	}
	result, err = tool.Call(t.Context(), input, nil)
	if err != nil || result.IsError {
		t.Fatal("fresh retry failed", result, err)
	}
	var count int
	if err := d.QueryRow(`SELECT count(*) FROM exploration_nodes WHERE exploration_id=$1 AND kind='intent' AND payload->>'summary'='Synthetic cancel and retry'`, task.ExplorationID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatal("cancelled call committed after retry", count)
	}
}
