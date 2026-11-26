package agent

import (
	"testing"

	"github.com/Autumn-27/artex/db"
)

// helper: intent/fact node
func intent(id int64, state string) cgNode { return cgNode{ID: id, Kind: db.KindIntent, State: state} }
func fact(id int64) cgNode                 { return cgNode{ID: id, Kind: db.KindFact, State: "confirmed"} }
func yields(from, to int64) cgEdge         { return cgEdge{From: from, Rel: db.RelYields, To: to} }
func derived(from, to int64) cgEdge        { return cgEdge{From: from, Rel: db.RelDerivedFrom, To: to} }

func ptr(v int64) *int64 { return &v }

// §附 快照1: a→b→c, b→d, with d live (running) and c settled/inactive.
// Expected: d/b/a hot (b kept hot by the live b→d branch); c is a cold candidate
// but an isolated singleton → not folded.
func TestHotCold_AnyLiveBranchKeepsChainHot(t *testing.T) {
	// a(intent) → b(intent) → c(fact); b → d(intent, running)
	nodes := []cgNode{intent(1, "done"), intent(2, "done"), fact(3), intent(4, "running")}
	edges := []cgEdge{derived(1, 2), yields(2, 3), derived(2, 4)}
	g := newColdGraph(nodes, edges)
	hot := g.hotSet()
	for _, id := range []int64{1, 2, 4} {
		if !hot[id] {
			t.Fatalf("node %d should be hot (ancestor of / is live intent 4)", id)
		}
	}
	if hot[3] {
		t.Fatalf("node 3 (dead leaf c) should be cold")
	}
	structCold := g.structuralCold(hot)
	if !structCold[3] || len(structCold) != 1 {
		t.Fatalf("only node 3 should be structurally cold, got %v", structCold)
	}
}

// §附 快照2: once d also finishes, a/b/c/d are all cold and connected → one block.
func TestHotCold_WholeChainFoldsWhenAllSettled(t *testing.T) {
	nodes := []cgNode{intent(1, "done"), intent(2, "done"), fact(3), intent(4, "done")}
	edges := []cgEdge{derived(1, 2), yields(2, 3), derived(2, 4)}
	g := newColdGraph(nodes, edges)
	hot := g.hotSet()
	if len(hot) != 0 {
		t.Fatalf("nothing should be hot once all settled, got %v", hot)
	}
	structCold := g.structuralCold(hot)
	// all stamped R+ rounds ago
	stamps := map[int64]*int64{1: ptr(1), 2: ptr(1), 3: ptr(1), 4: ptr(1)}
	elig := g.eligibleCold(structCold, stamps, 100, defaultColdParams())
	if len(elig) != 4 {
		t.Fatalf("all 4 nodes should be eligible cold, got %d", len(elig))
	}
	blocks := g.group(elig, defaultColdParams())
	if len(blocks) != 1 || len(blocks[0].Members) != 4 {
		t.Fatalf("expected one 4-member block, got %+v", blocks)
	}
}

// §2.3 debounce: a freshly-cooled node (stamp too recent) is not yet eligible.
func TestDebounce_RecentlyCooledNotEligible(t *testing.T) {
	nodes := []cgNode{intent(1, "done"), fact(2)}
	edges := []cgEdge{yields(1, 2)}
	g := newColdGraph(nodes, edges)
	structCold := g.structuralCold(g.hotSet())
	stamps := map[int64]*int64{1: ptr(98), 2: ptr(98)} // cooled at round 98
	elig := g.eligibleCold(structCold, stamps, 100, defaultColdParams())
	if len(elig) != 0 {
		t.Fatalf("nodes cooled only 2 rounds ago (<R=6) must not be eligible, got %v", elig)
	}
	elig = g.eligibleCold(structCold, stamps, 104, defaultColdParams()) // now 6 rounds
	if len(elig) != 2 {
		t.Fatalf("after R rounds both should be eligible, got %v", elig)
	}
}

// §3.1: a SETTLED hub kept hot only by ancestry to a live descendant (the real
// grap.log shape — exhausted/done intents with one live branch), whose OTHER
// children are flat dead leaves. Those leaves share the hot hub as parent, have
// no cold↔cold edges, yet must group (not stay singletons). Note: were the hub
// itself live (running), rule 1 would force its facts hot — that is a different
// case; here the hub is exhausted and hot only via the 50→77 live branch.
func TestGrouping_SharedParentRescuesFlatFanout(t *testing.T) {
	// hub(50) exhausted, hot via live descendant 77; dead cold facts 51..54.
	nodes := []cgNode{intent(50, "exhausted"), intent(77, "running")}
	edges := []cgEdge{derived(50, 77)}
	for id := int64(51); id <= 54; id++ {
		nodes = append(nodes, fact(id))
		edges = append(edges, yields(50, id))
	}
	g := newColdGraph(nodes, edges)
	hot := g.hotSet()
	if !hot[50] || !hot[77] {
		t.Fatalf("hub 50 (ancestor of live 77) and live 77 must be hot")
	}
	structCold := g.structuralCold(hot)
	stamps := map[int64]*int64{}
	for id := int64(51); id <= 54; id++ {
		stamps[id] = ptr(1)
	}
	elig := g.eligibleCold(structCold, stamps, 100, defaultColdParams())
	blocks := g.group(elig, defaultColdParams())
	// rule① alone would leave 51..54 as 4 singletons; rule② groups them into 1.
	if len(blocks) != 1 {
		t.Fatalf("expected 1 shared-parent block, got %d: %+v", len(blocks), blocks)
	}
	if len(blocks[0].Members) != 4 {
		t.Fatalf("block should hold all 4 dead leaves, got %v", blocks[0].Members)
	}
	// the hot hub is an anchor, never a member.
	if len(blocks[0].Anchors) != 1 || blocks[0].Anchors[0] != 50 {
		t.Fatalf("hub 50 should be the sole anchor, got %v", blocks[0].Anchors)
	}
	for _, m := range blocks[0].Members {
		if m == 50 {
			t.Fatalf("hub 50 must not be a member")
		}
	}
}

// §3①: a lone cold child under a hot parent stays an unfolded singleton.
func TestGrouping_LoneColdChildStaysSingleton(t *testing.T) {
	nodes := []cgNode{intent(50, "running"), intent(77, "running"), fact(51)}
	edges := []cgEdge{derived(50, 77), yields(50, 51)}
	g := newColdGraph(nodes, edges)
	structCold := g.structuralCold(g.hotSet())
	elig := g.eligibleCold(structCold, map[int64]*int64{51: ptr(1)}, 100, defaultColdParams())
	blocks := g.group(elig, defaultColdParams())
	if len(blocks) != 0 {
		t.Fatalf("a single cold leaf must not fold, got %+v", blocks)
	}
}

// §5.3: signature is stable under reordering and changes when a member's
// content_version bumps.
func TestSignature_StableAndVersionSensitive(t *testing.T) {
	b := block{Members: []int64{12, 28, 41}, Anchors: []int64{50}}
	cv := map[int64]int{12: 0, 28: 0, 41: 0, 50: 0}
	s1 := blockSignature(b, cv)
	// same members, same versions → same signature
	if s1 != blockSignature(block{Members: []int64{12, 28, 41}, Anchors: []int64{50}}, cv) {
		t.Fatalf("signature must be deterministic")
	}
	// bump a member version → signature changes
	cv2 := map[int64]int{12: 0, 28: 1, 41: 0, 50: 0}
	if s1 == blockSignature(b, cv2) {
		t.Fatalf("signature must change when a member content_version changes")
	}
	// bump anchor version → signature changes (anchor summary affects body)
	cv3 := map[int64]int{12: 0, 28: 0, 41: 0, 50: 1}
	if s1 == blockSignature(b, cv3) {
		t.Fatalf("signature must change when an anchor content_version changes")
	}
}

// computeStampOps: stamp on first cool, never re-stamp, clear on revival.
func TestStampOps(t *testing.T) {
	structCold := map[int64]bool{1: true, 2: true}
	coldSince := map[int64]*int64{2: ptr(5), 3: ptr(4)} // 2 already stamped; 3 stamped but revived
	ops := computeStampOps(structCold, coldSince, 10)
	got := map[int64]stampOp{}
	for _, o := range ops {
		got[o.ID] = o
	}
	if o, ok := got[1]; !ok || !o.Set || o.Round != 10 {
		t.Fatalf("node 1 should be stamped at round 10, got %+v", got[1])
	}
	if _, ok := got[2]; ok {
		t.Fatalf("node 2 already stamped, must not be re-stamped")
	}
	if o, ok := got[3]; !ok || o.Set {
		t.Fatalf("node 3 revived (not cold) → stamp must be cleared, got %+v", got[3])
	}
}

func TestGrouping_SplitsOversizedComponentByMembersAndBytes(t *testing.T) {
	// Build a linear chain of 11 cold nodes: 1 -> 2 -> ... -> 11.
	var nodes []cgNode
	var edges []cgEdge
	elig := map[int64]bool{}
	for id := int64(1); id <= 11; id++ {
		if id%2 == 1 {
			nodes = append(nodes, intent(id, "done"))
		} else {
			nodes = append(nodes, fact(id))
		}
		elig[id] = true
		if id > 1 {
			edges = append(edges, derived(id-1, id))
		}
	}
	g := newColdGraph(nodes, edges)
	// MaxMembers=4 would naively yield chunks [4, 4, 3]; verify all chunks obey bounds and >= K.
	p := coldParams{R: 6, K: 2, MaxMembers: 4, MaxBytes: 0}
	blocks := g.groupWithSizes(elig, p, nil)
	if len(blocks) != 3 {
		t.Fatalf("expected 3 bounded blocks, got %d: %+v", len(blocks), blocks)
	}
	seen := map[int64]bool{}
	for i, b := range blocks {
		if len(b.Members) < p.K || len(b.Members) > p.MaxMembers {
			t.Fatalf("block %d out of bounds [%d,%d]: %+v", i, p.K, p.MaxMembers, b.Members)
		}
		for _, m := range b.Members {
			if seen[m] {
				t.Fatalf("duplicate member %d across chunks", m)
			}
			seen[m] = true
		}
	}
	if len(seen) != 11 {
		t.Fatalf("expected all 11 members covered, got %d", len(seen))
	}
	// Downstream chunk must retain its upstream cross-chunk parent as an anchor.
	if len(blocks[1].Anchors) != 1 || blocks[1].Anchors[0] != 4 {
		t.Fatalf("expected chunk 1 anchor [4], got %+v", blocks[1].Anchors)
	}

	// Trailing singleton rebalance: 9 nodes with MaxMembers=4 -> [4, 3, 2], never leaving [1].
	elig9 := map[int64]bool{}
	for id := int64(1); id <= 9; id++ {
		elig9[id] = true
	}
	blocks9 := g.groupWithSizes(elig9, p, nil)
	if len(blocks9) != 3 {
		t.Fatalf("expected 3 rebalanced blocks for 9 nodes, got %d: %+v", len(blocks9), blocks9)
	}
	for i, b := range blocks9 {
		if len(b.Members) < p.K {
			t.Fatalf("chunk %d stranded below K: %+v", i, b.Members)
		}
	}

	// Byte-budget splitting: each node costs 2000 bytes, MaxBytes=5000 -> max 2 nodes per chunk.
	pBytes := coldParams{R: 6, K: 2, MaxMembers: 24, MaxBytes: 5000}
	blocksB := g.groupWithSizes(elig, pBytes, func(int64) int { return 2000 })
	if len(blocksB) < 5 {
		t.Fatalf("expected byte-bounded split into >=5 blocks, got %d: %+v", len(blocksB), blocksB)
	}
	for i, b := range blocksB {
		if len(b.Members) < pBytes.K {
			t.Fatalf("byte-split chunk %d below K: %+v", i, b.Members)
		}
		if len(b.Members) > 3 {
			t.Fatalf("byte-split chunk %d exceeded byte cap: %+v", i, b.Members)
		}
	}
}

func TestGrouping_PrefixChunksKeepStableSignatureOnFrontierGrowth(t *testing.T) {
	// Start with chain 1..6 (MaxMembers=4 -> chunks [1,2,3,4], [5,6]).
	build := func(n int64) (*coldGraph, map[int64]bool, map[int64]int) {
		var nodes []cgNode
		var edges []cgEdge
		elig := map[int64]bool{}
		cvers := map[int64]int{}
		for id := int64(1); id <= n; id++ {
			nodes = append(nodes, fact(id))
			elig[id] = true
			cvers[id] = 0
			if id > 1 {
				edges = append(edges, derived(id-1, id))
			}
		}
		return newColdGraph(nodes, edges), elig, cvers
	}
	p := coldParams{R: 6, K: 2, MaxMembers: 4, MaxBytes: 32 * 1024}
	g6, e6, cv6 := build(6)
	b6 := g6.groupWithSizes(e6, p, nil)
	g10, e10, cv10 := build(10)
	b10 := g10.groupWithSizes(e10, p, nil)
	if blockSignature(b6[0], cv6) != blockSignature(b10[0], cv10) {
		t.Fatalf("prefix chunk 0 signature drifted when tail grew: %+v vs %+v", b6[0], b10[0])
	}
}
