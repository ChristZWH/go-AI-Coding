// Package engine 实现与规则文件完全解耦的 Banner 指纹识别引擎。
//
// 引擎只理解规则文件 schema（见 rules/default.json），不包含任何具体协议
// 的硬编码：新增一种协议只需追加一条 JSON 规则，无需修改或重新编译程序。
// 识别过程永不 panic、永不因单条数据失败而中断整批处理。
package engine

import (
	"encoding/hex"
	"log"
	"regexp"
	"strings"
)

// Result 是引擎对单条 banner 的识别结论。
type Result struct {
	Protocol   string
	Product    string
	Version    string
	OSHint     string
	Confidence float64
}

// Unknown 返回 unknown 兜底结果：识别不出时使用，属于正常业务结果而非错误。
func Unknown() Result { return Result{Protocol: "unknown"} }

// compiledRule 是加载阶段预编译好的规则：正则与 strip 变换都只编译一次，
// 识别过程零编译开销。所有字段在构造后只读，因此 Engine 天然线程安全。
type compiledRule struct {
	rule         Rule
	re           *regexp.Regexp
	productStrip *regexp.Regexp
	versionStrip *regexp.Regexp
	osStrip      *regexp.Regexp
}

// Engine 按序执行规则：patternRules 处理非空 banner（首条命中即返回），
// portRules 是 banner 为空时的端口弱信号兜底。
type Engine struct {
	patternRules []compiledRule
	portRules    []compiledRule
}

// New 编译规则集并构造引擎。个别规则写错只会跳过该条并告警，
// 不影响其余规则，更不会导致启动失败。
func New(rs RuleSet) *Engine {
	e := &Engine{}
	for _, r := range rs.Rules {
		cr, err := compileRule(r)
		if err != nil {
			log.Printf("[engine] skip invalid rule %q: %v", r.Name, err)
			continue
		}
		if r.Pattern == "" {
			e.portRules = append(e.portRules, cr)
		} else {
			e.patternRules = append(e.patternRules, cr)
		}
	}
	return e
}

func compileRule(r Rule) (compiledRule, error) {
	cr := compiledRule{rule: r}
	if r.Pattern != "" {
		p := r.Pattern
		if r.CaseInsensitive {
			p = "(?i)" + p
		}
		re, err := regexp.Compile(p)
		if err != nil {
			return cr, err
		}
		cr.re = re
	}
	var err error
	if cr.productStrip, err = compileStrip(r.Product); err != nil {
		return cr, err
	}
	if cr.versionStrip, err = compileStrip(r.Version); err != nil {
		return cr, err
	}
	if cr.osStrip, err = compileStrip(r.OSHint); err != nil {
		return cr, err
	}
	return cr, nil
}

// compileStrip 预编译 Capture.StripSuffix（按行尾锚定的正则）。
func compileStrip(c *Capture) (*regexp.Regexp, error) {
	if c == nil || c.StripSuffix == "" {
		return nil, nil
	}
	return regexp.Compile(c.StripSuffix + `\z`)
}

// escapeRe 匹配文本形态的转义序列（literal 的 \xNN、\r、\n、\t），
// 用于把"直贴文本"形态的 banner 还原为真实字节。
var escapeRe = regexp.MustCompile(`\\x([0-9a-fA-F]{2})|\\r|\\n|\\t`)

// NormalizeBanner 对 banner 做归一化，兼容两种输入形态：
//  1. 合法 JSON 转义（\u0000、\r\n）解析后已是真实字节 —— 无副作用；
//  2. 文本直贴的 literal 转义（\x00、\r\n 原文）—— 还原为真实字节。
//
// 另统一去掉尾部 \r（Windows 编辑的数据文件可能携带 CR），
// 避免行尾锚定类正则失效。
func NormalizeBanner(s string) string {
	s = escapeRe.ReplaceAllStringFunc(s, func(m string) string {
		switch m {
		case `\r`:
			return "\r"
		case `\n`:
			return "\n"
		case `\t`:
			return "\t"
		default: // \xNN
			b, err := hex.DecodeString(m[2:])
			if err != nil {
				return m // 理论不可达：escapeRe 已保证两位十六进制
			}
			return string(b)
		}
	})
	return strings.TrimRight(s, "\r")
}

// Identify 识别单条 banner：
//   - banner 非空 → 按规则顺序匹配，首条命中即返回；
//   - banner 为空 → 尝试端口弱信号规则（低置信兜底）；
//   - 都不中     → unknown。
func (e *Engine) Identify(banner string, port int) Result {
	b := NormalizeBanner(banner)
	if strings.TrimSpace(b) != "" {
		for _, cr := range e.patternRules {
			if m := cr.re.FindStringSubmatch(b); m != nil {
				return cr.apply(m)
			}
		}
		return Unknown()
	}
	for _, cr := range e.portRules {
		for _, p := range cr.rule.PortHint {
			if p == port {
				return cr.apply(nil)
			}
		}
	}
	return Unknown()
}

// apply 按规则生成结果：字段取值 static 优先、其次捕获组，再做 strip 变换；
// 置信度统一钳位到 [0,1]。
func (cr compiledRule) apply(m []string) Result {
	res := Result{
		Protocol:   cr.rule.Protocol,
		Confidence: clamp(cr.rule.Confidence),
	}
	res.Product = captureValue(cr.rule.Product, cr.productStrip, m)
	res.Version = captureValue(cr.rule.Version, cr.versionStrip, m)
	res.OSHint = captureValue(cr.rule.OSHint, cr.osStrip, m)
	return res
}

func captureValue(c *Capture, strip *regexp.Regexp, m []string) string {
	if c == nil {
		return ""
	}
	v := c.Static
	if c.Group > 0 && c.Group < len(m) {
		v = m[c.Group]
	}
	if v == "" {
		return ""
	}
	if c.StripPrefix != "" {
		v = strings.TrimPrefix(v, c.StripPrefix)
	}
	if strip != nil {
		v = strip.ReplaceAllString(v, "")
	}
	return v
}

func clamp(c float64) float64 {
	if c < 0 {
		return 0
	}
	if c > 1 {
		return 1
	}
	return c
}
