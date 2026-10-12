package engine

import (
	_ "embed"
	"encoding/json"
	"os"
)

//go:embed rules/default.json
var defaultRulesJSON []byte

// DefaultRules 返回内嵌的默认识别规则（构建时打进二进制，开箱即用）。
func DefaultRules() RuleSet {
	var rs RuleSet
	if err := json.Unmarshal(defaultRulesJSON, &rs); err != nil {
		// 内嵌规则由单测 TestEmbeddedRulesValid 守护，正常运行不可能触发。
		panic("engine: embedded rules corrupted: " + err.Error())
	}
	return rs
}

// LoadRules 从外部文件加载规则集 —— 这是"规则与代码解耦"的入口：
// 挂载自定义规则文件并设置 FP_RULES_FILE 即可覆盖内嵌规则、
// 扩展新协议，无需重新编译镜像。
func LoadRules(path string) (RuleSet, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return RuleSet{}, err
	}
	var rs RuleSet
	if err := json.Unmarshal(data, &rs); err != nil {
		return RuleSet{}, err
	}
	return rs, nil
}
