package agent

import (
	"context"
	"errors"
	"iter"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/norma/llm"
)

type fakeCompactionResp struct {
	msg  llm.Message
	stop string
	err  error
}

type fakeCompactionProvider struct {
	replies []fakeCompactionResp
	reqs    []llm.CompletionRequest
}

func (f *fakeCompactionProvider) Complete(ctx context.Context, req llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
	f.reqs = append(f.reqs, req)
	idx := len(f.reqs) - 1
	if idx >= len(f.replies) {
		return llm.Message{}, "", llm.Usage{}, errors.New("unexpected extra Complete call")
	}
	r := f.replies[idx]
	return r.msg, r.stop, llm.Usage{}, r.err
}

func (f *fakeCompactionProvider) Stream(ctx context.Context, req llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {
	return func(yield func(llm.StreamEvent, error) bool) {
		yield(llm.StreamEvent{}, errors.New("not implemented"))
	}
}

func sampleCompactionBlock() (*coldGraph, block, map[int64]*db.Node) {
	nodes := map[int64]*db.Node{
		10: {ID: 10, Kind: "intent", State: "done", Payload: []byte(`{"summary":"探测 /login 端点"}`)},
		11: {ID: 11, Kind: "fact", State: "confirmed", Payload: []byte(`{"summary":"确认存在 SQL 注入"}`)},
	}
	g := newColdGraph(
		[]cgNode{{ID: 10, Kind: "intent", State: "done"}, {ID: 11, Kind: "fact", State: "confirmed"}},
		[]cgEdge{{From: 10, Rel: "yields", To: 11}},
	)
	return g, block{Members: []int64{10, 11}}, nodes
}

func TestCompactorCompressNormalSuccess(t *testing.T) {
	prov := &fakeCompactionProvider{
		replies: []fakeCompactionResp{
			{
				msg:  llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{llm.TextBlock("已确认 /login 存在 SQL 注入（#10,#11）。")}},
				stop: "end_turn",
			},
		},
	}
	c := NewCompactor(prov, "test-model")
	g, b, byID := sampleCompactionBlock()

	body, err := c.compress(context.Background(), g, b, byID)
	if err != nil {
		t.Fatalf("compress failed: %v", err)
	}
	if !strings.Contains(body, "SQL 注入") {
		t.Fatalf("unexpected body: %q", body)
	}
	if len(prov.reqs) != 1 {
		t.Fatalf("calls=%d, want 1", len(prov.reqs))
	}
	if prov.reqs[0].MaxTokens != 4096 || prov.reqs[0].Thinking != "disabled" {
		t.Fatalf("req MaxTokens=%d Thinking=%q, want 4096/disabled", prov.reqs[0].MaxTokens, prov.reqs[0].Thinking)
	}
}

func TestCompactorCompressEscalatesAndLearnsFloorOnThinkingExhaustion(t *testing.T) {
	prov := &fakeCompactionProvider{
		replies: []fakeCompactionResp{
			{
				// Simulates hy4flash-free spending all 4096 tokens on thinking.
				msg:  llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{{Type: llm.BlockThinking, Thinking: "长思考占满预算..."}}},
				stop: "max_tokens",
			},
			{
				msg: llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{
					{Type: llm.BlockThinking, Thinking: "思考完毕"},
					llm.TextBlock("综合结论：/login 存在 SQL 注入（#10,#11）。"),
				}},
				stop: "end_turn",
			},
			{
				// Second block should start straight at 8192 without wasting a 4096 call.
				msg:  llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{llm.TextBlock("第二块摘要（#10,#11）。")}},
				stop: "end_turn",
			},
		},
	}
	c := NewCompactor(prov, "hy4flash-free")
	g, b, byID := sampleCompactionBlock()

	body, err := c.compress(context.Background(), g, b, byID)
	if err != nil {
		t.Fatalf("first compress failed: %v", err)
	}
	if !strings.Contains(body, "综合结论") {
		t.Fatalf("unexpected body: %q", body)
	}
	if len(prov.reqs) != 2 || prov.reqs[0].MaxTokens != 4096 || prov.reqs[1].MaxTokens != 8192 {
		t.Fatalf("unexpected budget ladder: got %v", []int{prov.reqs[0].MaxTokens, prov.reqs[1].MaxTokens})
	}

	body2, err := c.compress(context.Background(), g, b, byID)
	if err != nil {
		t.Fatalf("second compress failed: %v", err)
	}
	if !strings.Contains(body2, "第二块摘要") {
		t.Fatalf("unexpected body2: %q", body2)
	}
	if len(prov.reqs) != 3 || prov.reqs[2].MaxTokens != 8192 {
		t.Fatalf("expected learned floor 8192 on 3rd call, got reqs=%d max=%d", len(prov.reqs), prov.reqs[2].MaxTokens)
	}
}

func TestCompactorCompressEscalatesTruncatedBodyWithThinking(t *testing.T) {
	prov := &fakeCompactionProvider{
		replies: []fakeCompactionResp{
			{
				msg: llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{
					{Type: llm.BlockThinking, Thinking: "几乎耗光预算的思考"},
					llm.TextBlock("半截正"),
				}},
				stop: "max_tokens",
			},
			{
				msg: llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{
					{Type: llm.BlockThinking, Thinking: "思考完成"},
					llm.TextBlock("完整的综合结论正文（#10,#11）。"),
				}},
				stop: "end_turn",
			},
		},
	}
	c := NewCompactor(prov, "deepseek-v4.1-flash")
	g, b, byID := sampleCompactionBlock()

	body, err := c.compress(context.Background(), g, b, byID)
	if err != nil {
		t.Fatalf("compress failed: %v", err)
	}
	if body != "完整的综合结论正文（#10,#11）。" {
		t.Fatalf("got %q, want full body", body)
	}
	if len(prov.reqs) != 2 || prov.reqs[1].MaxTokens != 8192 {
		t.Fatalf("expected escalation to 8192, got %d calls", len(prov.reqs))
	}
}

func TestCompactorCompressDoesNotEscalateOnPlainEmptyEndTurn(t *testing.T) {
	prov := &fakeCompactionProvider{
		replies: []fakeCompactionResp{
			{
				msg:  llm.Message{Role: llm.RoleAssistant, Content: nil},
				stop: "end_turn",
			},
		},
	}
	c := NewCompactor(prov, "plain-model")
	g, b, byID := sampleCompactionBlock()

	_, err := c.compress(context.Background(), g, b, byID)
	if err == nil {
		t.Fatal("expected error for empty body on end_turn")
	}
	if len(prov.reqs) != 1 {
		t.Fatalf("calls=%d, want 1 (should not escalate when stop=end_turn and no thinking)", len(prov.reqs))
	}
}

func TestCompactorCompressRespectsCanceledContext(t *testing.T) {
	prov := &fakeCompactionProvider{}
	c := NewCompactor(prov, "test-model")
	g, b, byID := sampleCompactionBlock()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := c.compress(ctx, g, b, byID)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err=%v, want context.Canceled", err)
	}
	if len(prov.reqs) != 0 {
		t.Fatalf("calls=%d, want 0 when context already canceled", len(prov.reqs))
	}
}
