//go:build !windows

package main

import "context"

func isWindowsService() bool { return false }

func handleServiceCommand(_ string, _ []string) bool { return false }

func runWindowsService(_ context.Context, _ context.CancelFunc, _ *State) {}
