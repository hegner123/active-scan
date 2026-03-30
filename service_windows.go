//go:build windows

package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

const serviceName = "ActiveScan"
const serviceDisplayName = "Active Scan — Malware Monitor"
const serviceDescription = "Monitors for blockchain-related malware processes and C2 connections"

func isWindowsService() bool {
	is, err := svc.IsWindowsService()
	if err != nil {
		return false
	}
	return is
}

// handleServiceCommand processes install/uninstall subcommands.
// Returns true if a command was handled.
func handleServiceCommand(cmd string, args []string) bool {
	switch cmd {
	case "install":
		if err := installService(args); err != nil {
			log.Fatalf("install failed: %v", err)
		}
		fmt.Println("Service installed. Start with: sc start ActiveScan")
		return true
	case "uninstall":
		if err := uninstallService(); err != nil {
			log.Fatalf("uninstall failed: %v", err)
		}
		fmt.Println("Service removed.")
		return true
	}
	return false
}

// runWindowsService blocks until the service is stopped by SCM.
func runWindowsService(ctx context.Context, cancel context.CancelFunc, state *State) {
	if err := svc.Run(serviceName, &activeScanSvc{ctx: ctx, cancel: cancel, state: state}); err != nil {
		log.Fatalf("service run failed: %v", err)
	}
}

type activeScanSvc struct {
	ctx    context.Context
	cancel context.CancelFunc
	state  *State
}

func (s *activeScanSvc) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (bool, uint32) {
	changes <- svc.Status{State: svc.StartPending}

	go RunScanner(s.ctx, s.state)
	go RunServer(s.ctx, s.state)

	changes <- svc.Status{
		State:   svc.Running,
		Accepts: svc.AcceptStop | svc.AcceptShutdown,
	}

	for {
		select {
		case c := <-r:
			switch c.Cmd {
			case svc.Interrogate:
				changes <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				changes <- svc.Status{State: svc.StopPending}
				s.cancel()
				return false, 0
			}
		case <-s.ctx.Done():
			return false, 0
		}
	}
}

func installService(extraArgs []string) error {
	exePath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("resolve executable path: %w", err)
	}

	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect to service manager (run as Administrator): %w", err)
	}
	defer m.Disconnect()

	// Build service binary path with any flags passed after "install"
	binPath := exePath
	if len(extraArgs) > 0 {
		binPath = exePath + " " + strings.Join(extraArgs, " ")
	}

	s, err := m.CreateService(serviceName, binPath, mgr.Config{
		DisplayName: serviceDisplayName,
		Description: serviceDescription,
		StartType:   mgr.StartAutomatic,
	})
	if err != nil {
		return fmt.Errorf("create service: %w", err)
	}
	defer s.Close()

	// Recovery: restart on failure (equivalent to KeepAlive in plist)
	err = s.SetRecoveryActions([]mgr.RecoveryAction{
		{Type: mgr.ServiceRestart, Delay: 5 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 10 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 30 * time.Second},
	}, uint32((24 * time.Hour).Seconds()))
	if err != nil {
		return fmt.Errorf("set recovery actions: %w", err)
	}

	return nil
}

func uninstallService() error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect to service manager (run as Administrator): %w", err)
	}
	defer m.Disconnect()

	s, err := m.OpenService(serviceName)
	if err != nil {
		return fmt.Errorf("open service: %w", err)
	}
	defer s.Close()

	// Stop if running
	s.Control(svc.Stop)
	time.Sleep(2 * time.Second)

	if err := s.Delete(); err != nil {
		return fmt.Errorf("delete service: %w", err)
	}
	return nil
}
