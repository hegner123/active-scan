//go:build windows

package main

import (
	"context"
	"testing"
)

func TestParseProcessOutput(t *testing.T) {
	// wmic process /value format: Key=Value pairs separated by blank lines.
	// Now that wmic returns all processes (not just node.exe), the parser
	// sees non-node binaries too; matchProcessCmd is the gate.
	output := "\r\n" +
		"CommandLine=node -e global[\"!\"] something malicious\r\n" +
		"ProcessId=1234\r\n" +
		"\r\n" +
		"CommandLine=node /usr/local/bin/legit-app\r\n" +
		"ProcessId=5678\r\n" +
		"\r\n" +
		"CommandLine=node app.js _V something =-22 payload\r\n" +
		"ProcessId=9012\r\n" +
		"\r\n" +
		"CommandLine=node server.js Gez(encoded)\r\n" +
		"ProcessId=3456\r\n" +
		"\r\n" +
		"CommandLine=C:\\Tools\\loader.exe -e global[\"!\"] payload\r\n" +
		"ProcessId=4444\r\n" +
		"\r\n"

	hits := parseProcessOutput(output, 99999)

	if len(hits) != 4 {
		t.Fatalf("got %d hits, want 4", len(hits))
	}

	expected := []struct {
		pid    int
		reason string
	}{
		{1234, "eval with global[] access"},
		{9012, "_V=-22 signature in command"},
		{3456, "Gez() call in command"},
		{4444, "eval with global[] access"},
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
	output := "\r\nCommandLine=node -e global[\"!\"] payload\r\nProcessId=1234\r\n\r\n"

	hits := parseProcessOutput(output, 1234)
	if len(hits) != 0 {
		t.Errorf("should skip own PID, got %d hits", len(hits))
	}
}

func TestParseProcessOutputSkipsActiveScan(t *testing.T) {
	output := "\r\nCommandLine=node active-scan --port 9847\r\nProcessId=7777\r\n\r\n"

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
	// netstat -nao format. No longer filtered by nodePIDs; any process
	// connecting to a C2 host is flagged.
	output := `
Active Connections

  Proto  Local Address          Foreign Address        State           PID
  TCP    192.168.1.5:54321      136.0.9.8:8080         ESTABLISHED     1234
  TCP    192.168.1.5:54322      93.184.216.34:443      ESTABLISHED     5678
  TCP    192.168.1.5:54323      trongrid.io:443        ESTABLISHED     9999
`

	hits := parseNetworkOutput(output)

	if len(hits) != 2 {
		t.Fatalf("got %d hits, want 2", len(hits))
	}

	if hits[0].PID != 1234 || hits[0].Host != "136.0.9.8" {
		t.Errorf("hit[0] = {PID:%d Host:%q}, want {PID:1234 Host:136.0.9.8}", hits[0].PID, hits[0].Host)
	}
	if hits[1].PID != 9999 || hits[1].Host != "trongrid" {
		t.Errorf("hit[1] = {PID:%d Host:%q}, want {PID:9999 Host:trongrid}", hits[1].PID, hits[1].Host)
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
