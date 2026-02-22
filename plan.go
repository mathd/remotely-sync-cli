package main

import (
	"fmt"
	"sort"
	"strings"
)

func buildPlan(localMap map[string]localMeta, remoteMap map[string]remoteMeta, prev syncState, direction string, conflictAction string, configDir string, remoteDeletions map[string]int64) []plannedAction {
	keysSet := map[string]struct{}{}
	for key := range localMap {
		keysSet[key] = struct{}{}
	}
	for key := range remoteMap {
		keysSet[key] = struct{}{}
	}
	for key := range prev.Files {
		keysSet[key] = struct{}{}
	}

	keys := make([]string, 0, len(keysSet))
	for key := range keysSet {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	actions := make([]plannedAction, 0, len(keys))

	for _, key := range keys {
		local, localExists := localMap[key]
		remote, remoteExists := remoteMap[key]
		prevEntry, hasPrev := prev.Files[key]
		isDir := strings.HasSuffix(key, "/")

		if isDir {
			action := "noop"
			if localExists && !remoteExists {
				action = "push"
			} else if !localExists && remoteExists {
				action = "pull"
			}

			if localExists {
				if remoteDeletionAt, ok := remoteDeletions[key]; ok {
					if remoteDeletionAt >= local.MTimeMS {
						action = "delete_local"
					}
				}
			}

			switch direction {
			case "incremental_push_only":
				if action == "pull" || action == "delete_local" || action == "delete_remote" {
					action = "noop"
				}
			case "incremental_push_and_delete_only":
				if action == "pull" || action == "delete_local" {
					action = "noop"
				}
			case "incremental_pull_only":
				if action == "push" || action == "delete_remote" || action == "delete_local" {
					action = "noop"
				}
			case "incremental_pull_and_delete_only":
				if action == "push" || action == "delete_remote" {
					action = "noop"
				}
			}

			actions = append(actions, plannedAction{Key: key, Action: action})
			continue
		}

		var localFP *fileSnapshot
		if localExists {
			localFP = fileFingerprint(local.Size, local.MTimeMS)
		}
		var remoteFP *fileSnapshot
		if remoteExists {
			remoteFP = fileFingerprint(remote.Size, remote.MTimeMS)
		}

		localUnchanged := sameSnapshot(localFP, prevEntry.Local)
		remoteUnchanged := sameSnapshot(remoteFP, prevEntry.Remote)

		action := "noop"

		if localExists && remoteExists {
			if sameSnapshot(localFP, remoteFP) {
				action = "noop"
			} else if hasPrev && localUnchanged && !remoteUnchanged {
				action = "pull"
			} else if hasPrev && !localUnchanged && remoteUnchanged {
				action = "push"
			} else if direction == "bidirectional" {
				action = resolveConflictAction(local, remote, conflictAction, key, configDir)
			} else if local.MTimeMS >= remote.MTimeMS {
				action = "push"
			} else {
				action = "pull"
			}
		} else if localExists && !remoteExists {
			if hasPrev && localUnchanged && prevEntry.Remote != nil {
				action = "delete_local"
			} else {
				action = "push"
			}
		} else if !localExists && remoteExists {
			if hasPrev && remoteUnchanged && prevEntry.Local != nil {
				action = "delete_remote"
			} else {
				action = "pull"
			}
		}

		if localExists {
			if remoteDeletionAt, ok := remoteDeletions[key]; ok {
				if remoteDeletionAt >= local.MTimeMS {
					action = "delete_local"
				}
			}
		}

		switch direction {
		case "incremental_push_only":
			if action == "pull" || action == "delete_local" || action == "delete_remote" {
				action = "noop"
			}
		case "incremental_push_and_delete_only":
			if action == "pull" || action == "delete_local" {
				action = "noop"
			}
		case "incremental_pull_only":
			if action == "push" || action == "delete_remote" || action == "delete_local" {
				action = "noop"
			}
		case "incremental_pull_and_delete_only":
			if action == "push" || action == "delete_remote" {
				action = "noop"
			}
		}

		actions = append(actions, plannedAction{Key: key, Action: action})
	}

	return actions
}

func resolveConflictAction(local localMeta, remote remoteMeta, conflictAction string, key string, configDir string) string {
	switch conflictAction {
	case "keep_larger":
		if local.Size >= remote.Size {
			return "push"
		}
		return "pull"
	case "smart_conflict":
		if strings.HasPrefix(key, configDir+"/") {
			if local.MTimeMS >= remote.MTimeMS {
				return "push"
			}
			return "pull"
		}
		return "smart_conflict"
	default:
		if local.MTimeMS >= remote.MTimeMS {
			return "push"
		}
		return "pull"
	}
}

func enforceProtectModifyPercentage(actions []plannedAction, localMap map[string]localMeta, remoteMap map[string]remoteMeta, protect int) error {
	if protect < 0 {
		return nil
	}
	allFiles := len(unionKeys(localMap, remoteMap))
	if allFiles == 0 {
		return nil
	}
	risky := 0
	for _, a := range actions {
		switch a.Action {
		case "delete_local", "delete_remote", "smart_conflict":
			risky++
		case "push", "pull":
			_, localExists := localMap[a.Key]
			_, remoteExists := remoteMap[a.Key]
			if localExists && remoteExists {
				risky++
			}
		}
	}
	if risky*100 > allFiles*protect {
		return fmt.Errorf("abort by protect-modify-percentage: risky=%d, total=%d, threshold=%d%%", risky, allFiles, protect)
	}
	return nil
}

func unionKeys(localMap map[string]localMeta, remoteMap map[string]remoteMeta) map[string]struct{} {
	out := map[string]struct{}{}
	for k := range localMap {
		out[k] = struct{}{}
	}
	for k := range remoteMap {
		out[k] = struct{}{}
	}
	return out
}
