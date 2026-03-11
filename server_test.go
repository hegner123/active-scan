package main

import (
	"bufio"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func newTestServer(t *testing.T) (*http.ServeMux, *State) {
	t.Helper()
	state := NewState(30*time.Second, 0)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		data, _ := uiFS.ReadFile("ui/index.html")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(data)
	})
	mux.HandleFunc("GET /api/status", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(state.Status())
	})
	mux.HandleFunc("GET /api/history", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(state.History(100))
	})
	mux.HandleFunc("POST /api/scan", func(w http.ResponseWriter, r *http.Request) {
		state.TriggerScan()
		w.WriteHeader(http.StatusAccepted)
		json.NewEncoder(w).Encode(map[string]string{"status": "scan triggered"})
	})

	return mux, state
}

func TestDashboardEndpoint(t *testing.T) {
	mux, _ := newTestServer(t)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	ct := rec.Header().Get("Content-Type")
	if !strings.Contains(ct, "text/html") {
		t.Errorf("Content-Type = %q, want text/html", ct)
	}
	if !strings.Contains(rec.Body.String(), "Active Scan") {
		t.Error("dashboard HTML should contain 'Active Scan'")
	}
}

func TestStatusEndpoint(t *testing.T) {
	mux, state := newTestServer(t)

	state.addResult(ScanResult{
		Time:     time.Now(),
		Duration: "5ms",
		Detections: []Detection{
			{Category: "test", Action: "killed"},
		},
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/status", nil)
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}

	var data map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&data); err != nil {
		t.Fatalf("failed to decode: %v", err)
	}

	if data["scanCount"] != float64(1) {
		t.Errorf("scanCount = %v, want 1", data["scanCount"])
	}
	if data["totalKills"] != float64(1) {
		t.Errorf("totalKills = %v, want 1", data["totalKills"])
	}
}

func TestHistoryEndpoint(t *testing.T) {
	mux, state := newTestServer(t)

	for range 5 {
		state.addResult(ScanResult{Time: time.Now(), Duration: "1ms", Clean: true})
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/history", nil)
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}

	var data []ScanResult
	if err := json.NewDecoder(rec.Body).Decode(&data); err != nil {
		t.Fatalf("failed to decode: %v", err)
	}

	if len(data) != 5 {
		t.Errorf("history len = %d, want 5", len(data))
	}
}

func TestHistoryEndpointEmpty(t *testing.T) {
	mux, _ := newTestServer(t)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/history", nil)
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}

	var data []ScanResult
	if err := json.NewDecoder(rec.Body).Decode(&data); err != nil {
		t.Fatalf("failed to decode: %v", err)
	}

	if len(data) != 0 {
		t.Errorf("empty history len = %d, want 0", len(data))
	}
}

func TestScanTriggerEndpoint(t *testing.T) {
	mux, state := newTestServer(t)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/api/scan", nil)
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Errorf("status = %d, want 202", rec.Code)
	}

	// Verify scan was triggered
	select {
	case <-state.scanNow:
	case <-time.After(100 * time.Millisecond):
		t.Error("scan was not triggered")
	}
}

func TestScanTriggerRejectsGET(t *testing.T) {
	mux, _ := newTestServer(t)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/scan", nil)
	mux.ServeHTTP(rec, req)

	if rec.Code == http.StatusAccepted {
		t.Error("GET /api/scan should not trigger scan")
	}
}

func TestSSEEndpoint(t *testing.T) {
	state := NewState(30*time.Second, 0)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/events", func(w http.ResponseWriter, r *http.Request) {
		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "no flusher", 500)
			return
		}

		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")

		statusJSON, _ := json.Marshal(state.Status())
		w.Write([]byte("event: status\ndata: "))
		w.Write(statusJSON)
		w.Write([]byte("\n\n"))
		flusher.Flush()

		ch := state.Subscribe()
		defer state.Unsubscribe(ch)

		for {
			select {
			case <-r.Context().Done():
				return
			case msg, ok := <-ch:
				if !ok {
					return
				}
				w.Write([]byte(msg))
				flusher.Flush()
			}
		}
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	req, _ := http.NewRequestWithContext(ctx, "GET", server.URL+"/api/events", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("SSE request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.Header.Get("Content-Type") != "text/event-stream" {
		t.Errorf("Content-Type = %q, want text/event-stream", resp.Header.Get("Content-Type"))
	}

	scanner := bufio.NewScanner(resp.Body)
	var gotInitialStatus bool
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "event: status") {
			gotInitialStatus = true
			break
		}
	}
	if !gotInitialStatus {
		t.Error("did not receive initial status event")
	}
}
