// Package httpserver 提供 server 的 HTTP 接口层：
//
//	POST /fingerprint — 批量识别（请求/响应均为 JSON 数组）
//	GET  /health      — 健康检查（供 Docker Compose healthcheck 真实调用）
//
// 可靠性设计：panic recover 中间件兜底、请求体大小限制、
// 输出长度与输入长度严格一致（顺序保持、ip/port 原样回显）。
package httpserver

import (
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/ChristZWH/go-AI-Coding/internal/engine"
	"github.com/ChristZWH/go-AI-Coding/internal/model"
)

// maxBodyBytes 限制请求体大小，防止恶意超大请求拖垮服务。
const maxBodyBytes = 8 << 20 // 8 MiB

// New 构造 server 的 HTTP handler。
func New(eng *engine.Engine) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/fingerprint", fingerprintHandler(eng))
	mux.HandleFunc("/health", healthHandler)
	return recoverMiddleware(loggingMiddleware(mux))
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func fingerprintHandler(eng *engine.Engine) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
		var items []model.RawInput
		if err := json.NewDecoder(r.Body).Decode(&items); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body: " + err.Error()})
			return
		}
		// 不变量：输出长度 == 输入长度、顺序一致、ip/port 原样回显；
		// 引擎对单条数据永不失败，因此整批结果必然齐全。
		results := make([]model.Fingerprint, len(items))
		for i, item := range items {
			res := eng.Identify(item.Banner, item.Port)
			results[i] = model.Fingerprint{
				IP:         item.IP,
				Port:       item.Port,
				Protocol:   res.Protocol,
				Product:    res.Product,
				Version:    res.Version,
				OSHint:     res.OSHint,
				Confidence: res.Confidence,
			}
		}
		writeJSON(w, http.StatusOK, results)
	}
}

// recoverMiddleware 兜底任何 panic：单条坏数据最多换来一个 500，
// 服务进程绝不退出。
func recoverMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				log.Printf("[server] recovered from panic: %v", rec)
				writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
			}
		}()
		next.ServeHTTP(w, r)
	})
}

func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		log.Printf("[server] %s %s (%s)", r.Method, r.URL.Path, time.Since(start))
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
