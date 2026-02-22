package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

func readStateFile(statePath string) (syncState, error) {
	empty := syncState{Version: 1, Files: map[string]stateEntry{}}

	data, err := os.ReadFile(statePath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return empty, nil
		}
		return empty, fmt.Errorf("unable to read state file: %w", err)
	}

	var state syncState
	if err := json.Unmarshal(data, &state); err != nil {
		return empty, fmt.Errorf("unable to parse state file %s: %w", statePath, err)
	}
	if state.Files == nil {
		state.Files = map[string]stateEntry{}
	}
	if state.Version == 0 {
		state.Version = 1
	}

	return state, nil
}

func writeStateFile(statePath string, localMap map[string]localMeta, remoteMap map[string]remoteMeta) error {
	keys := map[string]struct{}{}
	for key := range localMap {
		keys[key] = struct{}{}
	}
	for key := range remoteMap {
		keys[key] = struct{}{}
	}

	state := syncState{Version: 1, Files: map[string]stateEntry{}}
	now := time.Now().UnixMilli()

	for key := range keys {
		var localSnap *fileSnapshot
		if local, ok := localMap[key]; ok {
			localSnap = fileFingerprint(local.Size, local.MTimeMS)
		}
		var remoteSnap *fileSnapshot
		if remote, ok := remoteMap[key]; ok {
			remoteSnap = fileFingerprint(remote.Size, remote.MTimeMS)
		}
		state.Files[key] = stateEntry{
			Local:    localSnap,
			Remote:   remoteSnap,
			SyncedAt: now,
		}
	}

	b, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("unable to marshal state file: %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(statePath), 0o755); err != nil {
		return fmt.Errorf("unable to create state file directory: %w", err)
	}
	if err := os.WriteFile(statePath, b, 0o600); err != nil {
		return fmt.Errorf("unable to write state file: %w", err)
	}
	return nil
}

func fileFingerprint(size int64, mtimeMS int64) *fileSnapshot {
	return &fileSnapshot{
		Size:    size,
		MTimeMS: roundToSecondsMS(mtimeMS),
	}
}

func sameSnapshot(a *fileSnapshot, b *fileSnapshot) bool {
	if a == nil || b == nil {
		return false
	}
	return a.Size == b.Size && a.MTimeMS == b.MTimeMS
}

func roundToSecondsMS(ms int64) int64 {
	return (ms / 1000) * 1000
}
