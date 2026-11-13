package db

import (
	"context"
	"testing"
)

func TestPlannerReadRevisionTracksEvidenceAndSeparatesWorkerOutput(t *testing.T) {
	d,err:=Open(testDSN(t));if err!=nil {t.Fatal(err)};defer d.Close()
	var expID int64
	err=d.QueryRow(`INSERT INTO explorations(description,goal) VALUES('planner cache integration test','test') RETURNING id`).Scan(&expID)
	if err!=nil {t.Fatal(err)}
	defer d.Exec(`DELETE FROM explorations WHERE id=$1`,expID)
	s:=&ExplorationStore{db:d,expID:expID}
	ctx:=context.Background()
	before,err:=s.PlannerReadRevision(ctx);if err!=nil {t.Fatal(err)}
	_,err=s.AddNode(KindFact,map[string]any{"summary":"evidence"},0,"confirmed","worker",nil)
	if err!=nil {t.Fatal(err)}
	after,err:=s.PlannerReadRevision(ctx);if err!=nil {t.Fatal(err)}
	if before==after {t.Fatal("new evidence did not invalidate revision")}
	traceBefore,err:=s.PlannerTraceReadRevision(ctx);if err!=nil {t.Fatal(err)}
	_,err=d.Exec(`INSERT INTO activity(exploration_id,worker,kind,summary) VALUES($1,'planner','tool_result','planner read')`,expID)
	if err!=nil {t.Fatal(err)}
	stable,err:=s.PlannerReadRevision(ctx);if err!=nil {t.Fatal(err)}
	if stable!=after {t.Fatal("planner's own read invalidated fact cache")}
	_,err=d.Exec(`INSERT INTO activity(exploration_id,worker,kind,summary) VALUES($1,'work#1','tool_result','worker output')`,expID)
	if err!=nil {t.Fatal(err)}
	stable,err=s.PlannerReadRevision(ctx);if err!=nil {t.Fatal(err)}
	traceAfter,err:=s.PlannerTraceReadRevision(ctx);if err!=nil {t.Fatal(err)}
	if stable!=after {t.Fatal("unrelated command output invalidated fact cache")}
	if traceAfter==traceBefore {t.Fatal("new worker output did not invalidate trace cache")}
}
