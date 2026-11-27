package server

import (
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/intercept"
	"modernc.org/sqlite"
)

func TestJevCascadeEscalationPolicy(t *testing.T) {
	cases := []struct {
		name     string
		dec      intercept.Decision
		err      error
		escalate bool
	}{
		{"clear_allow", intercept.Decision{Action: "allow", Confidence: 0.95}, nil, false},
		{"borderline_allow_above_thresh", intercept.Decision{Action: "allow", Confidence: 0.60}, nil, false},
		{"clear_high_conf_deny", intercept.Decision{Action: "deny", Confidence: 0.91}, nil, false},
		{"borderline_deny_below_080", intercept.Decision{Action: "deny", Confidence: 0.65}, nil, true},
		{"ask_low_conf_or_truncated", intercept.Decision{Action: "ask", Confidence: 0.42}, nil, true},
		{"jev_transport_error", intercept.Decision{}, errors.New("connection refused"), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, reason := shouldEscalateJevToSecondary(tc.dec, tc.err)
			if got != tc.escalate {
				t.Fatalf("escalate=%v (reason=%q), want %v", got, reason, tc.escalate)
			}
			if got && reason == "" {
				t.Fatal("expected non-empty escalation reason")
			}
		})
	}
}

func TestJudgeConfigPreservesSecondaryProfileIDWhenOmitted(t *testing.T) {
	judgeConfigSQLiteNow.Do(func() {
		sqlite.MustRegisterDeterministicScalarFunction("now", 0, func(*sqlite.FunctionContext, []driver.Value) (driver.Value, error) {
			return "2026-01-01 00:00:00", nil
		})
	})
	sqldb, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sqldb.Close() })
	if _, err := sqldb.Exec(`CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT, updated_at TEXT)`); err != nil {
		t.Fatal(err)
	}
	pg := &db.DB{DB: sqldb}
	s := &Server{m: &Manager{pg: pg, interceptor: intercept.New(pg)}}

	// Set secondary_profile_id = 35 explicitly.
	w := httptest.NewRecorder()
	s.interceptSetJudgeConfig(w, httptest.NewRequest("PUT", "/api/intercept/judge",
		strings.NewReader(`{"enabled":true,"profile_id":36,"secondary_profile_id":35,"fail_action":"allow","ask_timeout_action":"deny"}`)))
	if w.Code != 200 || s.m.interceptor.GetJudgeConfig().SecondaryProfileID != 35 {
		t.Fatalf("explicit set failed: status=%d cfg=%+v body=%s", w.Code, s.m.interceptor.GetJudgeConfig(), w.Body.String())
	}

	// Legacy client omits secondary_profile_id -> must preserve 35 instead of zeroing.
	w = httptest.NewRecorder()
	s.interceptSetJudgeConfig(w, httptest.NewRequest("PUT", "/api/intercept/judge",
		strings.NewReader(`{"enabled":true,"profile_id":36,"fail_action":"allow","ask_timeout_action":"deny"}`)))
	if w.Code != 200 || s.m.interceptor.GetJudgeConfig().SecondaryProfileID != 35 {
		t.Fatalf("omitted field wiped secondary_profile_id: status=%d cfg=%+v", w.Code, s.m.interceptor.GetJudgeConfig())
	}

	// Explicit 0 clears secondary_profile_id.
	w = httptest.NewRecorder()
	s.interceptSetJudgeConfig(w, httptest.NewRequest("PUT", "/api/intercept/judge",
		strings.NewReader(`{"enabled":true,"profile_id":36,"secondary_profile_id":0,"fail_action":"allow","ask_timeout_action":"deny"}`)))
	if w.Code != 200 || s.m.interceptor.GetJudgeConfig().SecondaryProfileID != 0 {
		t.Fatalf("explicit clear failed: status=%d cfg=%+v", w.Code, s.m.interceptor.GetJudgeConfig())
	}
	var got intercept.JudgeConfig
	w = httptest.NewRecorder()
	s.interceptGetJudgeConfig(w, httptest.NewRequest("GET", "/api/intercept/judge", nil))
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil || got.SecondaryProfileID != 0 {
		t.Fatalf("GET round-trip failed: err=%v got=%+v", err, got)
	}
}

func TestSecondaryReviewEnvelopeWrapsUserMessage(t *testing.T) {
	p := &reviewCaptureProvider{}
	in := intercept.ReviewInput{
		Version:   5,
		Tool:      "Bash",
		Arguments: json.RawMessage(`{"command":"ls -la"}`),
	}
	prompt := intercept.EffectiveJudgePrompt(intercept.DefaultJudgePrompt)
	reply, err := secondaryReviewCompletion(t.Context(), p, prompt, in)
	if err != nil || intercept.ParseVerdict(reply).Action != "ask" {
		t.Fatalf("unexpected secondary reply=%q err=%v", reply, err)
	}
	if p.request.MaxTokens < 2048 {
		t.Fatalf("MaxTokens=%d, want >=2048", p.request.MaxTokens)
	}
	userText := p.request.Messages[0].Content[0].Text
	if !strings.Contains(userText, "【安全审计裁判任务】") || !strings.Contains(userText, `"tool_name":"Bash"`) || !strings.Contains(userText, `"decision":"allow|ask|deny"`) {
		t.Fatalf("secondary review user message missing judging envelope or payload: %s", userText)
	}
}
