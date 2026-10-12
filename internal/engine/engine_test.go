package engine

import (
	"os"
	"path/filepath"
	"testing"
)

func TestIdentifySampleBanners(t *testing.T) {
	eng := New(DefaultRules())
	cases := []struct {
		name   string
		banner string
		port   int
		want   Result
	}{
		{"ssh-openssh-ubuntu", "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3", 22,
			Result{Protocol: "SSH", Product: "OpenSSH", Version: "8.9p1", OSHint: "Ubuntu", Confidence: 0.95}},
		{"http-nginx", "HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\nContent-Type: text/html", 80,
			Result{Protocol: "HTTP", Product: "nginx", Version: "1.24.0", Confidence: 0.9}},
		{"http-apache", "HTTP/1.1 200 OK\r\nServer: Apache/2.4.57", 443,
			Result{Protocol: "HTTP", Product: "Apache", Version: "2.4.57", Confidence: 0.9}},
		{"mysql-8", "J\x00\x00\x00\n8.0.32\x00", 3306,
			Result{Protocol: "MySQL", Product: "MySQL", Version: "8.0.32", Confidence: 0.9}},
		{"redis-err", "-ERR wrong number of arguments for 'get' command", 6379,
			Result{Protocol: "Redis", Product: "Redis", Confidence: 0.7}},
		{"ftp-proftpd", "220 ProFTPD 1.3.7 Server (ProFTPD)", 21,
			Result{Protocol: "FTP", Product: "ProFTPD", Version: "1.3.7", Confidence: 0.9}},
		{"http-jetty", "HTTP/1.1 404 Not Found\r\nServer: Jetty/9.4.51", 8080,
			Result{Protocol: "HTTP", Product: "Jetty", Version: "9.4.51", Confidence: 0.9}},
		{"ssh-debian", "SSH-2.0-OpenSSH_9.3 Debian-1", 22,
			Result{Protocol: "SSH", Product: "OpenSSH", Version: "9.3", OSHint: "Debian", Confidence: 0.95}},
		{"http-nginx-ubuntu", "HTTP/1.1 200 OK\r\nServer: nginx/1.18.0 (Ubuntu)", 80,
			Result{Protocol: "HTTP", Product: "nginx", Version: "1.18.0", OSHint: "Ubuntu", Confidence: 0.9}},
		{"http-apache-ubuntu", "HTTP/1.1 200 OK\r\nServer: Apache/2.4.41 (Ubuntu)", 443,
			Result{Protocol: "HTTP", Product: "Apache", Version: "2.4.41", OSHint: "Ubuntu", Confidence: 0.9}},
		{"mysql-5", "J\x00\x00\x00\n5.7.42\x00", 3306,
			Result{Protocol: "MySQL", Product: "MySQL", Version: "5.7.42", Confidence: 0.9}},
		{"redis-pong", "+PONG", 6379,
			Result{Protocol: "Redis", Product: "Redis", Confidence: 0.7}},
		{"ftp-vsftpd", "220 (vsFTPd 3.0.5)", 21,
			Result{Protocol: "FTP", Product: "vsFTPd", Version: "3.0.5", Confidence: 0.9}},
		{"http-nginx-8443", "HTTP/1.1 200 OK\r\nServer: nginx/1.25.3", 8443,
			Result{Protocol: "HTTP", Product: "nginx", Version: "1.25.3", Confidence: 0.9}},
		{"ssh-1.99", "SSH-1.99-OpenSSH_4.3", 22,
			Result{Protocol: "SSH", Product: "OpenSSH", Version: "4.3", Confidence: 0.95}},
		{"tls-handshake", "\x16\x03\x01\x00\xa5\x01\x00\x00\xa1", 9999,
			Result{Protocol: "TLS", Confidence: 0.7}},
		{"http-iis", "HTTP/1.1 200 OK\r\nServer: Microsoft-IIS/10.0", 8888,
			Result{Protocol: "HTTP", Product: "Microsoft-IIS", Version: "10.0", Confidence: 0.9}},
		{"redis-noauth", "-NOAUTH Authentication required.", 6379,
			Result{Protocol: "Redis", Product: "Redis", Confidence: 0.7}},
		{"ftp-pureftpd", "220 Welcome to Pure-FTPd", 21,
			Result{Protocol: "FTP", Product: "Pure-FTPd", Confidence: 0.85}},
		{"unknown-quit", "QUIT\r\n", 12345, Unknown()},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := eng.Identify(tc.banner, tc.port)
			if got != tc.want {
				t.Errorf("Identify(%q, %d) = %+v, want %+v", tc.banner, tc.port, got, tc.want)
			}
		})
	}
}

func TestIdentifyLiteralEscapes(t *testing.T) {
	// 文本直贴形态的转义（JSON 中为 "\\x00" 字面文本）应与真实字节等效
	eng := New(DefaultRules())
	got := eng.Identify(`J\x00\x00\x00\n8.0.32\x00`, 3306)
	if got.Protocol != "MySQL" || got.Product != "MySQL" || got.Version != "8.0.32" {
		t.Errorf("literal escape banner = %+v, want MySQL/8.0.32", got)
	}
	got = eng.Identify(`\x16\x03\x01\x00\xa5\x01\x00\x00\xa1`, 9999)
	if got.Protocol != "TLS" {
		t.Errorf("literal escape banner = %+v, want TLS", got)
	}
}

func TestIdentifyUnknownAndNoPanic(t *testing.T) {
	// 认不出 → unknown，且任何输入都不允许 panic
	eng := New(DefaultRules())
	for _, banner := range []string{"", "   ", "QUIT\r\n", "garbage data", string([]byte{0xff, 0xfe, 0x00})} {
		got := eng.Identify(banner, 12345)
		if got.Protocol != "unknown" {
			t.Errorf("Identify(%q) = %+v, want unknown", banner, got)
		}
	}
}

func TestPortFallback(t *testing.T) {
	// 端口弱信号：仅 banner 为空时生效，低置信
	eng := New(DefaultRules())
	cases := []struct {
		port int
		want Result
	}{
		{22, Result{Protocol: "SSH", Confidence: 0.5}},
		{6379, Result{Protocol: "Redis", Confidence: 0.5}},
		{3306, Result{Protocol: "MySQL", Confidence: 0.5}},
		{21, Result{Protocol: "FTP", Confidence: 0.5}},
		{9999, Unknown()},
	}
	for _, tc := range cases {
		if got := eng.Identify("", tc.port); got != tc.want {
			t.Errorf("Identify(\"\", %d) = %+v, want %+v", tc.port, got, tc.want)
		}
	}
	// banner 非空但未匹配 → 不用端口猜
	if got := eng.Identify("garbage", 22); got.Protocol != "unknown" {
		t.Errorf("non-empty unmatched banner on port 22 = %+v, want unknown", got)
	}
}

func TestExternalRulesOverride(t *testing.T) {
	// 规则与代码解耦：外部规则文件可覆盖内嵌规则、扩展新协议，无需重编译
	dir := t.TempDir()
	path := filepath.Join(dir, "custom.json")
	rules := `{"schema":1,"rules":[
		{"name":"hello","protocol":"XPROTO","pattern":"^HELLO(?:\\s+(\\S+))?","product":{"static":"HelloSrv"},"version":{"group":1},"confidence":0.8},
		{"name":"bad-regex","protocol":"BROKEN","pattern":"([unclosed","confidence":0.9}
	]}`
	if err := os.WriteFile(path, []byte(rules), 0o644); err != nil {
		t.Fatal(err)
	}
	rs, err := LoadRules(path)
	if err != nil {
		t.Fatalf("LoadRules: %v", err)
	}
	eng := New(rs) // 坏正则规则被跳过，不影响其余规则
	got := eng.Identify("HELLO v1.2", 1)
	if got.Protocol != "XPROTO" || got.Product != "HelloSrv" || got.Version != "v1.2" {
		t.Errorf("custom rule = %+v, want XPROTO/HelloSrv/v1.2", got)
	}
}

func TestConfidenceClamped(t *testing.T) {
	rs := RuleSet{Schema: 1, Rules: []Rule{
		{Name: "high", Protocol: "X", Pattern: "^x", Confidence: 1.5},
		{Name: "low", Protocol: "Y", Pattern: "^y", Confidence: -0.5},
	}}
	eng := New(rs)
	if got := eng.Identify("x", 1); got.Confidence != 1 {
		t.Errorf("confidence = %v, want clamped to 1", got.Confidence)
	}
	if got := eng.Identify("y", 1); got.Confidence != 0 {
		t.Errorf("confidence = %v, want clamped to 0", got.Confidence)
	}
}

func TestEmbeddedRulesValid(t *testing.T) {
	// 守护内嵌规则文件：可解析且至少含特征规则与端口规则各一条
	rs := DefaultRules()
	eng := New(rs)
	if len(eng.patternRules) == 0 {
		t.Error("embedded rules contain no pattern rules")
	}
	if len(eng.portRules) == 0 {
		t.Error("embedded rules contain no port rules")
	}
}
