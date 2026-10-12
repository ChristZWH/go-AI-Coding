package engine

// Capture 描述结果字段的取值方式（三选一）并可附加字符串变换：
//   - Static: 固定值（如产品名写死 "Redis"）
//   - Group:  取正则第 N 个捕获组（N 从 1 开始）
//   - 两者都为空: 该字段输出空串
type Capture struct {
	Static      string `json:"static,omitempty"`
	Group       int    `json:"group,omitempty"`
	StripPrefix string `json:"strip_prefix,omitempty"` // 去除前缀（字面量），如 "OpenSSH_"
	StripSuffix string `json:"strip_suffix,omitempty"` // 去除行尾后缀（正则），如 "-[0-9]+"
}

// Rule 是一条识别规则：banner 正则命中即输出 protocol 及字段取值。
// Pattern 为空 + 配置 PortHint 的规则是"端口弱信号"规则，仅当 banner 为空时生效。
type Rule struct {
	Name            string   `json:"name"`
	Protocol        string   `json:"protocol"`
	Pattern         string   `json:"pattern,omitempty"`
	CaseInsensitive bool     `json:"case_insensitive,omitempty"`
	PortHint        []int    `json:"port_hint,omitempty"`
	Product         *Capture `json:"product,omitempty"`
	Version         *Capture `json:"version,omitempty"`
	OSHint          *Capture `json:"os_hint,omitempty"`
	Confidence      float64  `json:"confidence"`
}

// RuleSet 是规则文件的顶层结构，schema 用于未来格式演进时的兼容判断。
type RuleSet struct {
	Schema int    `json:"schema"`
	Rules  []Rule `json:"rules"`
}
