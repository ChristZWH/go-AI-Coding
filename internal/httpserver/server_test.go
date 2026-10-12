package httpserver

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ChristZWH/go-AI-Coding/internal/engine"
	"github.com/ChristZWH/go-AI-Coding/internal/model"
)

func newTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(New(engine.New(engine.DefaultRules())))
	t.Cleanup(srv.Close)
	return srv
}

func postJSON(t *testing.T, url, body string) *http.Response {
	t.Helper()
	resp, err := http.Post(url, "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("POST %s: %v", url, err)
	}
	return resp
}

func TestFingerprintBatch(t *testing.T) {
	srv := newTestServer(t)
	body := `[
		{"ip":"1.2.3.4","port":22,"banner":"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3"},
		{"ip":"1.2.3.23","port":12345,"banner":"QUIT\r\n"}
	]`
	resp := postJSON(t, srv.URL+"/fingerprint", body)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	var results []model.Fingerprint
	if err := json.NewDecoder(resp.Body).Decode(&results); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("len(results) = %d, want 2", len(results))
	}
	got := results[0]
	if got.Protocol != "SSH" || got.Product != "OpenSSH" || got.Version != "8.9p1" || got.OSHint != "Ubuntu" {
		t.Errorf("results[0] = %+v", got)
	}
	if results[1].Protocol != "unknown" {
		t.Errorf("results[1].Protocol = %q, want unknown", results[1].Protocol)
	}
}

func TestFingerprintInvariants(t *testing.T) {
	// 不变量：输出长度 == 输入长度、顺序一致、ip/port 原样回显、单条坏数据不拖垮整批
	srv := newTestServer(t)
	body := `[
		{"ip":"10.0.0.1","port":999,"banner":"whatever"},
		{"ip":"10.0.0.2","port":22,"banner":""},
		{"ip":"10.0.0.3","port":3306,"banner":12345}
	]`
	resp := postJSON(t, srv.URL+"/fingerprint", body)
	defer resp.Body.Close()
	var results []model.Fingerprint
	if err := json.NewDecoder(resp.Body).Decode(&results); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(results) != 3 {
		t.Fatalf("len(results) = %d, want 3", len(results))
	}
	if results[0].IP != "10.0.0.1" || results[0].Port != 999 || results[0].Protocol != "unknown" {
		t.Errorf("results[0] = %+v", results[0])
	}
	// 空 banner + 端口弱信号 → SSH @0.5
	if results[1].Protocol != "SSH" || results[1].Confidence != 0.5 {
		t.Errorf("results[1] = %+v, want SSH@0.5", results[1])
	}
	// 数字 banner 容忍为空串处理（不报错），随后按空 banner 走端口弱信号 → MySQL@0.5
	if results[2].Protocol != "MySQL" || results[2].Confidence != 0.5 {
		t.Errorf("results[2] = %+v, want MySQL@0.5", results[2])
	}
}

func TestFingerprintBadJSON(t *testing.T) {
	srv := newTestServer(t)
	resp := postJSON(t, srv.URL+"/fingerprint", `{not json`)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
}

func TestFingerprintEmptyArray(t *testing.T) {
	srv := newTestServer(t)
	resp := postJSON(t, srv.URL+"/fingerprint", `[]`)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	var results []model.Fingerprint
	if err := json.NewDecoder(resp.Body).Decode(&results); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(results) != 0 {
		t.Fatalf("len = %d, want 0", len(results))
	}
}

func TestHealth(t *testing.T) {
	srv := newTestServer(t)
	resp, err := http.Get(srv.URL + "/health")
	if err != nil {
		t.Fatalf("GET /health: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
}

func TestMethodNotAllowed(t *testing.T) {
	srv := newTestServer(t)
	resp, err := http.Get(srv.URL + "/fingerprint")
	if err != nil {
		t.Fatalf("GET /fingerprint: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", resp.StatusCode)
	}
}
