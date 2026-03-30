//go:build windows

package main

import (
	"context"
	"testing"
)

func TestParseProcessOutput(t *testing.T) {
	// wmic process /value format: Key=Value pairs separated by blank lines
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
		"\r\n"

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
	// netstat -nao format
	output := `
Active Connections

  Proto  Local Address          Foreign Address        State           PID
  TCP    192.168.1.5:54321      136.0.9.8:8080         ESTABLISHED     1234
  TCP    192.168.1.5:54322      93.184.216.34:443      ESTABLISHED     5678
  TCP    192.168.1.5:54323      1.2.3.4:443            ESTABLISHED     1234
`

	nodePIDs := map[int]bool{1234: true}
	hits := parseNetworkOutput(output, nodePIDs)

	if len(hits) != 1 {
		t.Fatalf("got %d hits, want 1", len(hits))
	}

	if hits[0].PID != 1234 || hits[0].Host != "136.0.9.8" {
		t.Errorf("hit[0] = {PID:%d Host:%q}, want {PID:1234 Host:136.0.9.8}", hits[0].PID, hits[0].Host)
	}
}

func TestParseNetworkOutputEmpty(t *testing.T) {
	hits := parseNetworkOutput("", nil)
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
