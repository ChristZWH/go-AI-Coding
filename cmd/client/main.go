// Banner 指纹识别 client：读取本地 JSON 文件（[{ip, port, banner}, ...]），
// POST 到 server，并将识别结果以表格形式展示。
//
// 用法：
//
//	fp-client -f data.json                              # 默认发送到 http://server:8080（Compose 服务名）
//	fp-client -f data.json --server http://localhost:8080
//	fp-client -f data.json --json                       # 输出原始 JSON 结果
//
// 环境变量：FP_SERVER_URL 可替代 --server 指定 server 地址。
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"text/tabwriter"
	"time"

	"github.com/ChristZWH/go-AI-Coding/internal/model"
)

func main() {
	var (
		file      = flag.String("f", "", "本地输入 JSON 文件路径（必填）")
		serverURL = flag.String("server", envOr("FP_SERVER_URL", "http://server:8080"), "server 地址")
		asJSON    = flag.Bool("json", false, "以 JSON 形式输出原始结果")
	)
	flag.Parse()

	if *file == "" {
		fmt.Fprintln(os.Stderr, "用法: fp-client -f <input.json> [--server http://server:8080] [--json]")
		os.Exit(2)
	}

	items, err := readInput(*file)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[client] 读取输入失败: %v\n", err)
		os.Exit(1)
	}

	results, err := send(*serverURL, items)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[client] 请求 server 失败: %v\n", err)
		os.Exit(1)
	}

	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(results); err != nil {
			fmt.Fprintf(os.Stderr, "[client] 输出失败: %v\n", err)
			os.Exit(1)
		}
		return
	}
	printTable(results)
}

// readInput 读取并解析输入文件（需为 [{ip,port,banner}, ...] 数组）。
func readInput(path string) ([]model.RawInput, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var items []model.RawInput
	if err := json.Unmarshal(data, &items); err != nil {
		return nil, fmt.Errorf("JSON 解析失败（需为 [{ip,port,banner}, ...] 数组）: %w", err)
	}
	return items, nil
}

// send 将输入批量 POST 到 server 的 /fingerprint 并解析结果。
func send(serverURL string, items []model.RawInput) ([]model.Fingerprint, error) {
	body, err := json.Marshal(items)
	if err != nil {
		return nil, err
	}
	httpClient := &http.Client{Timeout: 30 * time.Second}
	resp, err := httpClient.Post(serverURL+"/fingerprint", "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("server 返回 %d: %s", resp.StatusCode, string(msg))
	}
	var results []model.Fingerprint
	if err := json.NewDecoder(resp.Body).Decode(&results); err != nil {
		return nil, fmt.Errorf("解析 server 响应失败: %w", err)
	}
	return results, nil
}

func printTable(results []model.Fingerprint) {
	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "IP\tPORT\tPROTOCOL\tPRODUCT\tVERSION\tOS_HINT\tCONFIDENCE")
	for _, r := range results {
		fmt.Fprintf(w, "%s\t%d\t%s\t%s\t%s\t%s\t%.2f\n",
			r.IP, r.Port, r.Protocol, r.Product, r.Version, r.OSHint, r.Confidence)
	}
	w.Flush()
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
