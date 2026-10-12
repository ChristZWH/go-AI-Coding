// Banner 指纹识别 server：接收批量 {ip, port, banner} 数据并返回识别结果。
//
// 接口：
//
//	POST /fingerprint  — 批量识别（请求/响应均为 JSON 数组）
//	GET  /health       — 健康检查（供 Docker Compose healthcheck 调用）
//
// 环境变量：
//
//	FP_SERVER_ADDR  监听地址，默认 ":8080"
//	FP_RULES_FILE   外部规则文件路径；不设置则使用内嵌规则（默认）
package main

import (
	"errors"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/ChristZWH/go-AI-Coding/internal/engine"
	"github.com/ChristZWH/go-AI-Coding/internal/httpserver"
)

func main() {
	addr := envOr("FP_SERVER_ADDR", ":8080")
	eng := loadEngine()

	srv := &http.Server{
		Addr:              addr,
		Handler:           httpserver.New(eng),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	log.Printf("[server] listening on %s", addr)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("[server] exit: %v", err)
	}
}

// loadEngine 按优先级加载规则：FP_RULES_FILE 外部规则 > 内嵌默认规则。
// 外部规则加载失败时回退内嵌规则并告警，绝不因此启动失败。
func loadEngine() *engine.Engine {
	if path := os.Getenv("FP_RULES_FILE"); path != "" {
		rs, err := engine.LoadRules(path)
		if err == nil {
			log.Printf("[server] using external rules: %s", path)
			return engine.New(rs)
		}
		log.Printf("[server] load external rules %q failed (%v), fallback to embedded", path, err)
	}
	log.Printf("[server] using embedded default rules")
	return engine.New(engine.DefaultRules())
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
