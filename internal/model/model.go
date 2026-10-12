// Package model 定义 client 与 server 之间传输的原始输入与识别结果数据结构。
package model

import "encoding/json"

// RawInput 是单条网络扫描原始数据：目标 IP、端口与抓取到的 banner 原文。
type RawInput struct {
	IP     string `json:"ip"`
	Port   int    `json:"port"`
	Banner string `json:"banner"`
}

// UnmarshalJSON 宽松解析 banner 字段：banner 缺失、null 或非字符串（如数字）
// 一律按空串处理 —— 脏数据降级为 unknown，绝不让整批请求失败。
func (r *RawInput) UnmarshalJSON(data []byte) error {
	var plain struct {
		IP     string          `json:"ip"`
		Port   int             `json:"port"`
		Banner json.RawMessage `json:"banner"`
	}
	if err := json.Unmarshal(data, &plain); err != nil {
		return err
	}
	r.IP, r.Port = plain.IP, plain.Port
	if len(plain.Banner) > 0 && string(plain.Banner) != "null" {
		_ = json.Unmarshal(plain.Banner, &r.Banner) // 非字符串（数字等）保持空串
	}
	return nil
}

// Fingerprint 是单条识别结果，字段名与验收要求一一对应。
// 识别不出时 Protocol 为 "unknown"、Confidence 为 0，属于正常业务结果而非错误。
type Fingerprint struct {
	IP         string  `json:"ip"`
	Port       int     `json:"port"`
	Protocol   string  `json:"protocol"`
	Product    string  `json:"product"`
	Version    string  `json:"version"`
	OSHint     string  `json:"os_hint"`
	Confidence float64 `json:"confidence"`
}
