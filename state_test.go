package main

import (
	"encoding/json"
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestNewState(t *testing.T) {
	s := NewState(30*time.Second, 9847)
	if s.interval != 30*time.Second {
		t.Errorf("interval = %v, want 30s", s.interval)
	}
	if s.port != 9847 {
		t.Errorf("port = %d, want 9847", s.port)
	}
	if s.subscribers == nil {
		t.Error("subscribers map should be initialized")
	}
	if s.scanNow == nil {
		t.Error("scanNow channel should be initialized")
	}
}

func TestTriggerScanNonBlocking(t *testing.T) {
	s := NewState(time.Second, 0)

	// First trigger should succeed
	s.TriggerScan()

	// Second trigger should not block (channel buffered at 1)
	done := make(chan struct{})
	go func() {
		s.TriggerScan()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(100 * time.Millisecond):
		t.Error("TriggerScan blocked on full channel")
	}
}

func TestAddResultAndStatus(t *testing.T) {
	s := NewState(time.Second, 0)

	r := ScanResult{
		Time:     time.Now(),
		Duration: "5ms",
		Detections: []Detection{
			{Category: "process", Action: "killed"},
			{Category: "network", Action: "killed"},
			{Category: "persistence", Action: "notified"},
		},
		Clean: false,
	}
	s.addResult(r)

	status := s.Status()
	if status["scanCount"] != 1 {
		t.Errorf("scanCount = %v, want 1", status["scanCount"])
	}
	if status["totalKills"] != 2 {
		t.Errorf("totalKills = %v, want 2", status["totalKills"])
	}
	if status["totalAlerts"] != 3 {
		t.Errorf("totalAlerts = %v, want 3", status["totalAlerts"])
	}
}

func TestAddResultCleanScan(t *testing.T) {
	s := NewState(time.Second, 0)

	r := ScanResult{
		Time:     time.Now(),
		Duration: "2ms",
		Clean:    true,
	}
	s.addResult(r)

	status := s.Status()
	if status["totalKills"] != 0 {
		t.Errorf("clean scan should have 0 kills")
	}
	if status["totalAlerts"] != 0 {
		t.Errorf("clean scan should have 0 alerts")
	}
}

func TestHistoryCap(t *testing.T) {
	s := NewState(time.Second, 0)

	for i := range 1500 {
		s.addResult(ScanResult{
			Time:     time.Now(),
			Duration: "1ms",
			Detections: []Detection{
				{Category: "test", Detail: fmt.Sprintf("detection %d", i), Action: "notified"},
			},
		})
	}

	history := s.History(0)
	if len(history) != 1000 {
		t.Errorf("history len = %d, want 1000 (capped)", len(history))
	}

	// Most recent should be first
	if history[0].Detections[0].Detail != "detection 1499" {
		t.Errorf("most recent detection = %q, want 'detection 1499'", history[0].Detections[0].Detail)
	}
}

func TestHistoryLimit(t *testing.T) {
	s := NewState(time.Second, 0)

	for range 50 {
		s.addResult(ScanResult{Time: time.Now(), Duration: "1ms", Clean: true})
	}

	h10 := s.History(10)
	if len(h10) != 10 {
		t.Errorf("History(10) len = %d, want 10", len(h10))
	}

	hAll := s.History(0)
	if len(hAll) != 50 {
		t.Errorf("History(0) len = %d, want 50", len(hAll))
	}

	hOver := s.History(999)
	if len(hOver) != 50 {
		t.Errorf("History(999) len = %d, want 50", len(hOver))
	}
}

func TestSubscribeUnsubscribe(t *testing.T) {
	s := NewState(time.Second, 0)

	ch := s.Subscribe()

	s.subMu.RLock()
	count := len(s.subscribers)
	s.subMu.RUnlock()
	if count != 1 {
		t.Errorf("subscriber count = %d, want 1", count)
	}

	s.Unsubscribe(ch)

	s.subMu.RLock()
	count = len(s.subscribers)
	s.subMu.RUnlock()
	if count != 0 {
		t.Errorf("subscriber count after unsubscribe = %d, want 0", count)
	}
}

func TestPublishEvent(t *testing.T) {
	s := NewState(time.Second, 0)
	ch := s.Subscribe()
	defer s.Unsubscribe(ch)

	s.publishEvent("status", map[string]string{"test": "value"})

	select {
	case msg := <-ch:
		if msg == "" {
			t.Error("received empty message")
		}
		// Should contain SSE format
		if len(msg) < 10 {
			t.Errorf("message too short: %q", msg)
		}
	case <-time.After(100 * time.Millisecond):
		t.Error("did not receive published event")
	}
}

func TestPublishDropsSlowSubscriber(t *testing.T) {
	s := NewState(time.Second, 0)
	ch := s.Subscribe()
	defer s.Unsubscribe(ch)

	// Fill the channel buffer (32)
	for range 40 {
		s.publishEvent("test", "data")
	}

	// Should not block or panic
	s.publishEvent("test", "one more")

	// Drain
	drained := 0
	for {
		select {
		case <-ch:
			drained++
		default:
			goto done
		}
	}
done:
	if drained != 32 {
		t.Errorf("drained %d messages, want 32 (buffer size)", drained)
	}
}

func TestStatusSerializesToJSON(t *testing.T) {
	s := NewState(30*time.Second, 9847)
	s.addResult(ScanResult{
		Time:     time.Now(),
		Duration: "3ms",
		Clean:    true,
	})

	status := s.Status()
	data, err := json.Marshal(status)
	if err != nil {
		t.Fatalf("failed to marshal status: %v", err)
	}

	var parsed map[string]any
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("failed to unmarshal status: %v", err)
	}

	if parsed["scanCount"] != float64(1) {
		t.Errorf("scanCount = %v, want 1", parsed["scanCount"])
	}
}

func TestConcurrentStateAccess(t *testing.T) {
	s := NewState(time.Second, 0)
	var wg sync.WaitGroup

	// Writers
	for range 10 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 100 {
				s.addResult(ScanResult{
					Time:     time.Now(),
					Duration: "1ms",
					Detections: []Detection{
						{Category: "test", Action: "notified"},
					},
				})
			}
		}()
	}

	// Readers
	for range 10 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 100 {
				_ = s.Status()
				_ = s.History(10)
			}
		}()
	}

	// Subscribers
	for range 5 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ch := s.Subscribe()
			defer s.Unsubscribe(ch)
			for range 50 {
				select {
				case <-ch:
				case <-time.After(10 * time.Millisecond):
				}
			}
		}()
	}

	wg.Wait()

	status := s.Status()
	if status["scanCount"] != 1000 {
		t.Errorf("scanCount = %v, want 1000", status["scanCount"])
	}
}
