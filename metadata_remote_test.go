package main

import "testing"

func TestMetadataPayloadSerializeDeserializeRoundTrip(t *testing.T) {
	t.Parallel()

	in := map[string]int64{
		"notes/a.md": 1700000000000,
		"notes/b.md": 1700000001000,
	}
	b, err := serializeRemoteMetadataPayload(in)
	if err != nil {
		t.Fatalf("serialize metadata payload: %v", err)
	}
	p, err := deserializeRemoteMetadataPayload(b)
	if err != nil {
		t.Fatalf("deserialize metadata payload: %v", err)
	}
	if len(p.Deletions) != 2 {
		t.Fatalf("unexpected deletion count: %d", len(p.Deletions))
	}
	out := map[string]int64{}
	for _, d := range p.Deletions {
		out[d.Key] = d.ActionWhen
	}
	if out["notes/a.md"] != 1700000000000 {
		t.Fatalf("unexpected actionWhen for notes/a.md: %d", out["notes/a.md"])
	}
	if out["notes/b.md"] != 1700000001000 {
		t.Fatalf("unexpected actionWhen for notes/b.md: %d", out["notes/b.md"])
	}
}

func TestBuildPlanHonorsRemoteDeletionHistory(t *testing.T) {
	t.Parallel()

	localMap := map[string]localMeta{
		"notes/file.md": {
			Key:     "notes/file.md",
			MTimeMS: 1000,
			Size:    10,
		},
	}
	remoteMap := map[string]remoteMeta{}
	prev := syncState{Version: 1, Files: map[string]stateEntry{}}

	actions := buildPlan(localMap, remoteMap, prev, "bidirectional", "keep_newer", ".obsidian", map[string]int64{
		"notes/file.md": 2000,
	})
	if len(actions) != 1 {
		t.Fatalf("unexpected action count: %d", len(actions))
	}
	if actions[0].Action != "delete_local" {
		t.Fatalf("expected delete_local, got: %s", actions[0].Action)
	}
}

func TestComputeDeletionActionWhenUsesMaxObservedMtime(t *testing.T) {
	t.Parallel()

	now := int64(1000)
	key := "notes/file.md"
	localBefore := map[string]localMeta{}
	remoteBefore := map[string]remoteMeta{
		key: {Key: key, MTimeMS: 5000},
	}
	prev := syncState{Version: 1, Files: map[string]stateEntry{
		key: {
			Local:  &fileSnapshot{MTimeMS: 4000},
			Remote: &fileSnapshot{MTimeMS: 4500},
		},
	}}

	got := computeDeletionActionWhen(now, key, localBefore, remoteBefore, prev)
	if got != 5001 {
		t.Fatalf("unexpected deletion actionWhen: got=%d want=%d", got, 5001)
	}
}

func TestEvolveDeletionMapFromActionsUsesMonotonicActionWhen(t *testing.T) {
	t.Parallel()

	key := "notes/file.md"
	actions := []plannedAction{{Key: key, Action: "delete_remote"}}
	current := map[string]int64{}
	localBefore := map[string]localMeta{}
	remoteBefore := map[string]remoteMeta{
		key: {Key: key, MTimeMS: 9000},
	}
	prev := syncState{Version: 1, Files: map[string]stateEntry{}}

	updated := evolveDeletionMapFromActions(actions, current, localBefore, remoteBefore, prev)
	if updated[key] < 9001 {
		t.Fatalf("expected deletion timestamp >= 9001, got: %d", updated[key])
	}
}
