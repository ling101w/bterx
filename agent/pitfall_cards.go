package agent

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Autumn-27/artex/db"
)

// PitfallCard is a compact, deterministically matched operational card pushed
// into worker context when target asset fingerprints or intent context match.
// Cards live in code as small defaults and can be extended via JSON files in
// <workDir>/pitfall-cards/*.json without running an LLM retrieval agent.
type PitfallCard struct {
	ID            string   `json:"id"`
	Title         string   `json:"title"`
	MatchTechs    []string `json:"match_techs,omitempty"`
	MatchKeywords []string `json:"match_keywords,omitempty"`
	Guidance      string   `json:"guidance"`
}

var builtinPitfallCards = []PitfallCard{
	{
		ID:            "pitfall-spa-200",
		Title:         "SPA 前端路由 200 假阳性核验",
		MatchTechs:    []string{"vue", "react", "angular", "next.js", "nuxt", "webpack", "vite"},
		MatchKeywords: []string{"spa", "index.html", "前端", "路由"},
		Guidance:      "单页应用对不存在的路径常返回 HTTP 200 + 相同 index.html 壳。判断接口或目录存在前，务必对比响应 Content-Type、长度与基线随机路径响应，避免把统一回退页误记为已确认接口或鉴权绕过。",
	},
	{
		ID:            "pitfall-soft-200-auth",
		Title:         "HTTP 200 正文软拒绝/鉴权失败核验",
		MatchTechs:    []string{"spring", "nginx", "openresty", "gateway", "json", "graphql"},
		MatchKeywords: []string{"api", "login", "auth", "token", "jwt", "鉴权", "越权", "未授权"},
		Guidance:      "很多业务网关在未授权或报错时仍返回 HTTP 200，并在 JSON 正文中写 code!=0、login/unauthorized/expired 或跳转页。写 observed 事实前必须核对正文里的实际业务数据与状态字段，不可仅凭 HTTP 200 下结论。",
	},
	{
		ID:            "pitfall-waf-ratelimit",
		Title:         "WAF 拦截与限流特征识别",
		MatchTechs:    []string{"cloudflare", "akamai", "aliyun", "waf", "modsecurity", "safeline", "cdn"},
		MatchKeywords: []string{"waf", "403", "429", "captcha", "block", "限流", "拦截"},
		Guidance:      "遇到连续 403/429/验证码或统一拦截页时，先确认是全路径限流还是特定参数触发，及时把触发条件与特征写入 asset_note 共享给同资产其他 Worker，避免重复高频请求浪费步数。",
	},
	{
		ID:            "pitfall-java-actuator",
		Title:         "Java / Spring 端点误报与前缀核验",
		MatchTechs:    []string{"spring", "spring boot", "tomcat", "jetty", "undertow", "java"},
		MatchKeywords: []string{"actuator", "swagger", "druid", "heapdump", "env", "mappings"},
		Guidance:      "探测 Spring/Java 管理端点时需同时检查上下文前缀与 Whitelabel Error Page 特征，不要把自定义错误页当成有效端点；确认暴露时在 evidence 中保留完整路径与关键响应字段。",
	},
	{
		ID:            "pitfall-graphql-error",
		Title:         "GraphQL 响应 errors 字段核验",
		MatchTechs:    []string{"graphql", "apollo"},
		MatchKeywords: []string{"graphql", "gql", "introspection"},
		Guidance:      "GraphQL 请求即便认证失败或查询被拒通常仍返回 HTTP 200 且 data 为 null、errors 非空。判断查询有效或存在越权时，必须核实 data 中返回了真实目标字段。",
	},
}

// loadCustomPitfallCards reads optional user-maintained JSON cards from dir.
// Each file may contain either a single PitfallCard object or a JSON array of cards.
func loadCustomPitfallCards(dir string) []PitfallCard {
	if strings.TrimSpace(dir) == "" {
		return nil
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []PitfallCard
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(strings.ToLower(entry.Name()), ".json") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil || len(raw) == 0 || len(raw) > 256*1024 {
			continue
		}
		trimmed := strings.TrimSpace(string(raw))
		if strings.HasPrefix(trimmed, "[") {
			var list []PitfallCard
			if json.Unmarshal(raw, &list) == nil {
				for _, c := range list {
					if strings.TrimSpace(c.Title) != "" && strings.TrimSpace(c.Guidance) != "" {
						out = append(out, c)
					}
				}
			}
			continue
		}
		var card PitfallCard
		if json.Unmarshal(raw, &card) == nil && strings.TrimSpace(card.Title) != "" && strings.TrimSpace(card.Guidance) != "" {
			out = append(out, card)
		}
	}
	return out
}

// MatchPitfallCards deterministically matches up to maxCards short operational
// cards against target asset fingerprints and the intent summary.
func MatchPitfallCards(assets []*db.Asset, intentSummary, extraDir string, maxCards int) []PitfallCard {
	if maxCards <= 0 {
		maxCards = 3
	}
	var techParts []string
	var textParts []string
	if s := strings.ToLower(strings.TrimSpace(intentSummary)); s != "" {
		textParts = append(textParts, s)
	}
	for _, a := range assets {
		if a == nil {
			continue
		}
		for _, tech := range a.Technologies {
			if t := strings.ToLower(strings.TrimSpace(tech)); t != "" {
				techParts = append(techParts, t)
				textParts = append(textParts, t)
			}
		}
		for _, s := range []string{a.URL, a.Domain, a.ServiceName, a.ServiceType, a.PageTitle, a.AppName} {
			if v := strings.ToLower(strings.TrimSpace(s)); v != "" {
				textParts = append(textParts, v)
			}
		}
	}
	if len(techParts) == 0 && len(textParts) == 0 {
		return nil
	}
	techCorpus := strings.Join(techParts, " ")
	textCorpus := strings.Join(textParts, " ")

	candidates := make([]PitfallCard, 0, len(builtinPitfallCards))
	candidates = append(candidates, builtinPitfallCards...)
	candidates = append(candidates, loadCustomPitfallCards(extraDir)...)

	type scored struct {
		card  PitfallCard
		score int
		order int
	}
	var matched []scored
	seenID := map[string]bool{}
	for idx, c := range candidates {
		score := 0
		for _, mt := range c.MatchTechs {
			needle := strings.ToLower(strings.TrimSpace(mt))
			if needle == "" {
				continue
			}
			if strings.Contains(techCorpus, needle) {
				score += 3
			} else if strings.Contains(textCorpus, needle) {
				score += 2
			}
		}
		for _, kw := range c.MatchKeywords {
			needle := strings.ToLower(strings.TrimSpace(kw))
			if needle != "" && strings.Contains(textCorpus, needle) {
				score += 1
			}
		}
		if score <= 0 {
			continue
		}
		key := c.ID
		if key == "" {
			key = c.Title
		}
		if seenID[key] {
			continue
		}
		seenID[key] = true
		matched = append(matched, scored{card: c, score: score, order: idx})
	}
	sort.Slice(matched, func(i, j int) bool {
		if matched[i].score != matched[j].score {
			return matched[i].score > matched[j].score
		}
		return matched[i].order < matched[j].order
	})
	if len(matched) > maxCards {
		matched = matched[:maxCards]
	}
	out := make([]PitfallCard, len(matched))
	for i, m := range matched {
		out[i] = m.card
	}
	return out
}

// RenderAssetNotesBlock renders live task-local asset notes into a concise system
// prompt block for workers operating on the same asset(s).
func RenderAssetNotesBlock(notes []*db.Node) string {
	if len(notes) == 0 {
		return ""
	}
	type item struct {
		ID       int64   `json:"id"`
		Origin   string  `json:"origin,omitempty"`
		AssetIDs []int64 `json:"asset_ids,omitempty"`
		Summary  string  `json:"summary"`
		Detail   string  `json:"detail,omitempty"`
	}
	items := make([]item, 0, len(notes))
	for _, n := range notes {
		if n == nil {
			continue
		}
		var p map[string]any
		_ = json.Unmarshal(n.Payload, &p)
		summary, _ := p["summary"].(string)
		summary = strings.TrimSpace(summary)
		if summary == "" {
			continue
		}
		detail, _ := p["detail"].(string)
		detail = truncateRunes(strings.TrimSpace(detail), 240)
		items = append(items, item{
			ID:       n.ID,
			Origin:   n.Origin,
			AssetIDs: n.Anchors,
			Summary:  truncateRunes(summary, 180),
			Detail:   detail,
		})
	}
	if len(items) == 0 {
		return ""
	}
	raw, err := json.Marshal(items)
	if err != nil {
		return ""
	}
	return "\n\n【同资产实时共享备注（本任务其他 Worker / Supervisor 已确认的特征与踩坑，直接参考，勿重复踩坑）】\n" + string(raw)
}

// RenderPitfallCardsBlock renders deterministically pushed pitfall cards for a worker.
func RenderPitfallCardsBlock(cards []PitfallCard) string {
	if len(cards) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("\n\n【自动推送核验与避坑卡（按目标指纹/上下文自动匹配，降低误判与空转）】")
	for _, c := range cards {
		b.WriteString("\n- [")
		if c.ID != "" {
			b.WriteString(c.ID)
			b.WriteString(" · ")
		}
		b.WriteString(c.Title)
		b.WriteString("] ")
		b.WriteString(c.Guidance)
	}
	return b.String()
}

func truncateRunes(s string, max int) string {
	if max <= 0 {
		return ""
	}
	r := []rune(s)
	if len(r) <= max {
		return s
	}
	return string(r[:max]) + "…"
}
