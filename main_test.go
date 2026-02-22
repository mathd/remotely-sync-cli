package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func newValidOptionsForTest(localPath string) options {
	return options{
		LocalPath:      localPath,
		Endpoint:       "s3.us-east-1.amazonaws.com",
		Region:         "us-east-1",
		Bucket:         "test-bucket",
		AccessKey:      "test-access-key",
		SecretKey:      "test-secret-key",
		ConfigDir:      ".obsidian",
		Direction:      "bidirectional",
		StateFile:      "",
		ConflictAction: "keep_newer",
	}
}

func TestReadStateFileRejectsCorruptJSON(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	statePath := filepath.Join(dir, "state.json")
	if err := os.WriteFile(statePath, []byte("{not-json"), 0o600); err != nil {
		t.Fatalf("write state file: %v", err)
	}

	_, err := readStateFile(statePath)
	if err == nil {
		t.Fatalf("expected parse error, got nil")
	}
	if !strings.Contains(err.Error(), "unable to parse state file") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestEnforceProtectModifyPercentageAllowsInitialAdds(t *testing.T) {
	t.Parallel()

	actions := []plannedAction{
		{Key: "a.md", Action: "push"},
		{Key: "b.md", Action: "pull"},
	}
	local := map[string]localMeta{
		"a.md": {Key: "a.md"},
	}
	remote := map[string]remoteMeta{
		"b.md": {Key: "b.md"},
	}

	err := enforceProtectModifyPercentage(actions, local, remote, 50)
	if err != nil {
		t.Fatalf("expected nil error, got: %v", err)
	}
}

func TestEnforceProtectModifyPercentageBlocksDeleteHeavyPlan(t *testing.T) {
	t.Parallel()

	actions := []plannedAction{
		{Key: "a.md", Action: "delete_remote"},
		{Key: "b.md", Action: "delete_remote"},
		{Key: "c.md", Action: "noop"},
	}
	local := map[string]localMeta{
		"a.md": {Key: "a.md"},
		"b.md": {Key: "b.md"},
		"c.md": {Key: "c.md"},
	}
	remote := map[string]remoteMeta{
		"a.md": {Key: "a.md"},
		"b.md": {Key: "b.md"},
		"c.md": {Key: "c.md"},
	}

	err := enforceProtectModifyPercentage(actions, local, remote, 50)
	if err == nil {
		t.Fatalf("expected protection error, got nil")
	}
}

func TestEnforceProtectModifyPercentageAllowsEqualThreshold(t *testing.T) {
	t.Parallel()

	actions := []plannedAction{
		{Key: "a.md", Action: "delete_remote"},
		{Key: "b.md", Action: "noop"},
	}
	local := map[string]localMeta{
		"a.md": {Key: "a.md"},
		"b.md": {Key: "b.md"},
	}
	remote := map[string]remoteMeta{
		"a.md": {Key: "a.md"},
		"b.md": {Key: "b.md"},
	}

	err := enforceProtectModifyPercentage(actions, local, remote, 50)
	if err != nil {
		t.Fatalf("expected nil at exact threshold, got: %v", err)
	}
}

func TestIsSpecialFolderNameToSkipMacOSX(t *testing.T) {
	t.Parallel()

	if !isSpecialFolderNameToSkip("__MACOSX") {
		t.Fatalf("expected __MACOSX to be skipped")
	}
	if !isSpecialFolderNameToSkip("folder/__MACOSX/file.txt") {
		t.Fatalf("expected nested __MACOSX path to be skipped")
	}
}

func TestShouldSkipKeyAllowAndIgnorePrecedence(t *testing.T) {
	t.Parallel()

	opts := options{ConfigDir: ".obsidian", SyncUnderscore: true}
	filters := &compiledFilters{
		allow: []*regexp.Regexp{regexp.MustCompile(`^notes/`)},
		ignore: []*regexp.Regexp{
			regexp.MustCompile(`secret`),
		},
	}

	if shouldSkipKey("other/file.md", opts, filters) != true {
		t.Fatalf("expected non-allowed key to be skipped")
	}
	if shouldSkipKey("notes/secret.md", opts, filters) != true {
		t.Fatalf("expected ignored allowed key to be skipped")
	}
	if shouldSkipKey("notes/ok.md", opts, filters) != false {
		t.Fatalf("expected allowed key to be kept")
	}
}

func TestShouldSkipKeyConfigDirRules(t *testing.T) {
	t.Parallel()

	if shouldSkipKey(".obsidian/workspace.json", options{ConfigDir: ".obsidian"}, &compiledFilters{}) != true {
		t.Fatalf("expected config dir file to be skipped by default")
	}
	if shouldSkipKey(".obsidian/workspace.json", options{ConfigDir: ".obsidian", SyncConfigDir: true}, &compiledFilters{}) != false {
		t.Fatalf("expected config dir file to be kept when sync-config-dir is enabled")
	}
	if shouldSkipKey(".obsidian/plugins/remotely-secure/data.json", options{ConfigDir: ".obsidian", SyncConfigDir: true}, &compiledFilters{}) != true {
		t.Fatalf("expected remotely-secure data.json to stay skipped even with sync-config-dir")
	}
	if shouldSkipKey(".obsidian/bookmarks.json", options{ConfigDir: ".obsidian", SyncBookmarks: true}, &compiledFilters{}) != false {
		t.Fatalf("expected bookmarks file to be kept when sync-bookmarks is enabled")
	}
	if shouldSkipKey(".obsidian/workspace.json", options{ConfigDir: ".obsidian", SyncBookmarks: true}, &compiledFilters{}) != true {
		t.Fatalf("expected non-bookmarks config file to be skipped in sync-bookmarks mode")
	}
}

func TestSanitizeRelativeSyncKeyRejectsTraversalAndAmbiguousPaths(t *testing.T) {
	t.Parallel()

	badKeys := []string{
		"",
		"../outside.md",
		"a/../outside.md",
		"/absolute/path.md",
		"a//b.md",
		"a/./b.md",
	}
	for _, key := range badKeys {
		if _, err := sanitizeRelativeSyncKey(key); err == nil {
			t.Fatalf("expected key %q to be rejected", key)
		}
	}
}

func TestSanitizeRelativeSyncKeyAcceptsNormalizedKey(t *testing.T) {
	t.Parallel()

	got, err := sanitizeRelativeSyncKey("notes/daily.md")
	if err != nil {
		t.Fatalf("expected normalized key to pass, got: %v", err)
	}
	if got != "notes/daily.md" {
		t.Fatalf("unexpected normalized key: %q", got)
	}
}

func TestIsRemoteDirectoryMarker(t *testing.T) {
	t.Parallel()

	if !isRemoteDirectoryMarker("folder/sub/") {
		t.Fatalf("expected trailing slash key to be treated as directory marker")
	}
	if isRemoteDirectoryMarker("folder/sub.md") {
		t.Fatalf("expected file key not to be treated as directory marker")
	}
}

func TestValidateRemoteDecodeResultRejectsAllDecodeFailures(t *testing.T) {
	t.Parallel()

	err := validateRemoteDecodeResult(options{Password: "pw", Encryption: "remotely-sync-base64url"}, 0, 2, []string{"a", "b"})
	if err == nil {
		t.Fatalf("expected validation error when no key can be decoded")
	}
	if !strings.Contains(err.Error(), "unable to decode any remote keys") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateRemoteDecodeResultAllowsMixedDecodeResults(t *testing.T) {
	t.Parallel()

	err := validateRemoteDecodeResult(options{Password: "pw", Encryption: "remotely-sync-base64url"}, 3, 2, []string{"a", "b"})
	if err != nil {
		t.Fatalf("expected mixed decode results to be allowed, got: %v", err)
	}
}

func TestLocalPathForKeyRejectsEscapingPath(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	if _, err := localPathForKey(root, "../outside.txt"); err == nil {
		t.Fatalf("expected escaping key to fail")
	}
}

func TestValidateAndNormalizeOptionsRejectsEndpointWithoutHost(t *testing.T) {
	t.Parallel()

	opts := newValidOptionsForTest(t.TempDir())
	opts.Endpoint = "https://"

	err := validateAndNormalizeOptions(&opts)
	if err == nil {
		t.Fatalf("expected endpoint validation error")
	}
	if !strings.Contains(err.Error(), "host is required") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateAndNormalizeOptionsRejectsEndpointPath(t *testing.T) {
	t.Parallel()

	opts := newValidOptionsForTest(t.TempDir())
	opts.Endpoint = "https://example.com/custom"

	err := validateAndNormalizeOptions(&opts)
	if err == nil {
		t.Fatalf("expected endpoint path validation error")
	}
	if !strings.Contains(err.Error(), "path is not allowed") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateAndNormalizeOptionsNormalizesEndpointAndPrefix(t *testing.T) {
	t.Parallel()

	opts := newValidOptionsForTest(t.TempDir())
	opts.Endpoint = "s3.us-east-1.amazonaws.com"
	opts.Prefix = "vault"

	if err := validateAndNormalizeOptions(&opts); err != nil {
		t.Fatalf("expected valid options, got: %v", err)
	}
	if opts.Endpoint != "https://s3.us-east-1.amazonaws.com" {
		t.Fatalf("unexpected endpoint normalization: %s", opts.Endpoint)
	}
	if opts.Prefix != "vault/" {
		t.Fatalf("unexpected prefix normalization: %s", opts.Prefix)
	}
}

func TestValidateAndNormalizeOptionsAcceptsRcloneEncryptionMethod(t *testing.T) {
	t.Parallel()

	opts := newValidOptionsForTest(t.TempDir())
	opts.Password = "pw"
	opts.Encryption = "rclone-base64"

	if err := validateAndNormalizeOptions(&opts); err != nil {
		t.Fatalf("expected rclone method to be accepted, got: %v", err)
	}
}

func TestValidateAndNormalizeOptionsAcceptsAutoEncryptionMethod(t *testing.T) {
	t.Parallel()

	opts := newValidOptionsForTest(t.TempDir())
	opts.Password = "pw"
	opts.Encryption = "auto"

	if err := validateAndNormalizeOptions(&opts); err != nil {
		t.Fatalf("expected auto method to be accepted, got: %v", err)
	}
}

func TestValidateAndNormalizeOptionsAcceptsRemotelySyncEncryptionMethod(t *testing.T) {
	t.Parallel()

	opts := newValidOptionsForTest(t.TempDir())
	opts.Password = "pw"
	opts.Encryption = "remotely-sync-base64url"

	if err := validateAndNormalizeOptions(&opts); err != nil {
		t.Fatalf("expected remotely-sync method to be accepted, got: %v", err)
	}
}

func TestValidateAndNormalizeOptionsDefaultsToRemotelySyncMethodWhenPasswordSet(t *testing.T) {
	t.Parallel()

	opts := newValidOptionsForTest(t.TempDir())
	opts.Password = "pw"
	opts.Encryption = ""

	if err := validateAndNormalizeOptions(&opts); err != nil {
		t.Fatalf("expected valid options, got: %v", err)
	}
	if opts.Encryption != "remotely-sync-base64url" {
		t.Fatalf("unexpected default encryption method: %s", opts.Encryption)
	}
}

func TestValidateAndNormalizeOptionsRejectsUnknownEncryptionMethod(t *testing.T) {
	t.Parallel()

	opts := newValidOptionsForTest(t.TempDir())
	opts.Password = "pw"
	opts.Encryption = "unknown-method"

	err := validateAndNormalizeOptions(&opts)
	if err == nil {
		t.Fatalf("expected unknown encryption method to be rejected")
	}
}

func TestValidateAndNormalizeOptionsKeepsPasswordWhitespace(t *testing.T) {
	t.Parallel()

	opts := newValidOptionsForTest(t.TempDir())
	opts.Password = "  pass-with-spaces  "
	opts.Encryption = "rclone-base64"

	if err := validateAndNormalizeOptions(&opts); err != nil {
		t.Fatalf("expected valid options, got: %v", err)
	}
	if opts.Password != "  pass-with-spaces  " {
		t.Fatalf("password was unexpectedly normalized: %q", opts.Password)
	}
}

func TestValidateAndNormalizeCheckOptionsAcceptsAuto(t *testing.T) {
	t.Parallel()

	opts := options{
		Endpoint:   "s3.us-east-1.amazonaws.com",
		Region:     "us-east-1",
		Bucket:     "test-bucket",
		AccessKey:  "test-access-key",
		SecretKey:  "test-secret-key",
		Password:   "pw",
		Encryption: "auto",
	}

	if err := validateAndNormalizeCheckOptions(&opts); err != nil {
		t.Fatalf("expected valid check options, got: %v", err)
	}
}

func TestValidateAndNormalizeCheckOptionsAcceptsRemotelySyncMethod(t *testing.T) {
	t.Parallel()

	opts := options{
		Endpoint:   "s3.us-east-1.amazonaws.com",
		Region:     "us-east-1",
		Bucket:     "test-bucket",
		AccessKey:  "test-access-key",
		SecretKey:  "test-secret-key",
		Password:   "pw",
		Encryption: "remotely-sync-base64url",
	}

	if err := validateAndNormalizeCheckOptions(&opts); err != nil {
		t.Fatalf("expected valid check options, got: %v", err)
	}
}

func TestValidateAndNormalizeCheckOptionsRequiresPassword(t *testing.T) {
	t.Parallel()

	opts := options{
		Endpoint:  "s3.us-east-1.amazonaws.com",
		Region:    "us-east-1",
		Bucket:    "test-bucket",
		AccessKey: "test-access-key",
		SecretKey: "test-secret-key",
	}

	err := validateAndNormalizeCheckOptions(&opts)
	if err == nil {
		t.Fatalf("expected password requirement error")
	}
}

func TestValidateAndNormalizeCheckOptionsKeepsPasswordWhitespace(t *testing.T) {
	t.Parallel()

	opts := options{
		Endpoint:   "s3.us-east-1.amazonaws.com",
		Region:     "us-east-1",
		Bucket:     "test-bucket",
		AccessKey:  "test-access-key",
		SecretKey:  "test-secret-key",
		Password:   "  pass-with-spaces  ",
		Encryption: "auto",
	}

	if err := validateAndNormalizeCheckOptions(&opts); err != nil {
		t.Fatalf("expected valid check options, got: %v", err)
	}
	if opts.Password != "  pass-with-spaces  " {
		t.Fatalf("password was unexpectedly normalized: %q", opts.Password)
	}
}

func TestMaskSecret(t *testing.T) {
	t.Parallel()

	if got := maskSecret(""); got != "" {
		t.Fatalf("empty secret mismatch: %q", got)
	}
	if got := maskSecret("abcd"); got != "****" {
		t.Fatalf("short secret mismatch: %q", got)
	}
	if got := maskSecret("abcdef"); got != "**cdef" {
		t.Fatalf("mask mismatch: %q", got)
	}
}

func TestEnsureLocalPathReadyAcceptsExistingDirectory(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	if err := ensureLocalPathReady(options{LocalPath: dir}); err != nil {
		t.Fatalf("expected existing directory to pass, got: %v", err)
	}
}

func TestEnsureLocalPathReadyRejectsFilePath(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	filePath := filepath.Join(dir, "file.txt")
	if err := os.WriteFile(filePath, []byte("x"), 0o600); err != nil {
		t.Fatalf("write temp file: %v", err)
	}

	err := ensureLocalPathReady(options{LocalPath: filePath})
	if err == nil {
		t.Fatalf("expected file path to be rejected")
	}
	if !strings.Contains(err.Error(), "not a directory") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestEnsureLocalPathReadyRejectsMissingDirectoryInNonInteractiveMode(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	missingPath := filepath.Join(dir, "missing")

	err := ensureLocalPathReady(options{LocalPath: missingPath})
	if err == nil {
		t.Fatalf("expected missing path to be rejected in non-interactive mode")
	}
	if !strings.Contains(err.Error(), "local path does not exist") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestHasLikelyEncryptedKeysDetectsOpenSSLPrefix(t *testing.T) {
	t.Parallel()

	if !hasLikelyEncryptedKeys([]string{"U2FsdGVkX19abc"}) {
		t.Fatalf("expected openssl-looking key to be detected")
	}
}

func TestHasLikelyEncryptedKeysDetectsRemotelySyncKey(t *testing.T) {
	t.Parallel()

	opts := options{Password: "pw", Encryption: "remotely-sync-base64url"}
	enc, err := encodeRemoteKey(opts, "notes/file.md")
	if err != nil {
		t.Fatalf("encode remote key: %v", err)
	}
	if !hasLikelyEncryptedKeys([]string{enc}) {
		t.Fatalf("expected remotely-sync encrypted key to be detected")
	}
}

func TestHasLikelyEncryptedKeysIgnoresNormalPlainKeys(t *testing.T) {
	t.Parallel()

	if hasLikelyEncryptedKeys([]string{"notes/file.md", "folder/sub/"}) {
		t.Fatalf("expected normal plain keys to not be treated as encrypted")
	}
}

func TestSanitizeRelativeSyncKeyPreservingDirMarker(t *testing.T) {
	t.Parallel()

	got, err := sanitizeRelativeSyncKeyPreservingDirMarker("notes/folder/")
	if err != nil {
		t.Fatalf("expected directory key to pass, got: %v", err)
	}
	if got != "notes/folder/" {
		t.Fatalf("unexpected directory key: %q", got)
	}
}

func TestWalkLocalFilesIncludesDirectoryMarkers(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "notes", "empty"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "notes", "a.md"), []byte("x"), 0o600); err != nil {
		t.Fatalf("write file: %v", err)
	}

	m, err := walkLocalFiles(options{LocalPath: root}, "")
	if err != nil {
		t.Fatalf("walk local files: %v", err)
	}
	if _, ok := m["notes/"]; !ok {
		t.Fatalf("expected notes/ directory marker")
	}
	if _, ok := m["notes/empty/"]; !ok {
		t.Fatalf("expected notes/empty/ directory marker")
	}
	if _, ok := m["notes/a.md"]; !ok {
		t.Fatalf("expected notes/a.md file entry")
	}
}

func TestLocalPathForKeyHandlesDirectoryMarker(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	got, err := localPathForKey(root, "notes/folder/")
	if err != nil {
		t.Fatalf("expected directory marker path to be valid, got: %v", err)
	}
	want := filepath.Join(root, "notes", "folder")
	if got != want {
		t.Fatalf("unexpected local path: got %q want %q", got, want)
	}
}

func TestBuildPlanDirectoryMarkerIgnoresMtimeDrift(t *testing.T) {
	t.Parallel()

	localMap := map[string]localMeta{
		"notes/": {Key: "notes/", MTimeMS: 1000, Size: 0},
	}
	remoteMap := map[string]remoteMeta{
		"notes/": {Key: "notes/", MTimeMS: 999999, Size: 0},
	}
	prev := syncState{Version: 1, Files: map[string]stateEntry{}}

	actions := buildPlan(localMap, remoteMap, prev, "bidirectional", "keep_newer", ".obsidian", map[string]int64{})
	if len(actions) != 1 {
		t.Fatalf("unexpected action count: %d", len(actions))
	}
	if actions[0].Action != "noop" {
		t.Fatalf("expected noop for existing dir marker, got: %s", actions[0].Action)
	}
}

func TestBuildPlanDirectoryMarkerPushWhenRemoteMissing(t *testing.T) {
	t.Parallel()

	localMap := map[string]localMeta{
		"notes/": {Key: "notes/", MTimeMS: 1000, Size: 0},
	}
	remoteMap := map[string]remoteMeta{}
	prev := syncState{Version: 1, Files: map[string]stateEntry{}}

	actions := buildPlan(localMap, remoteMap, prev, "bidirectional", "keep_newer", ".obsidian", map[string]int64{})
	if len(actions) != 1 {
		t.Fatalf("unexpected action count: %d", len(actions))
	}
	if actions[0].Action != "push" {
		t.Fatalf("expected push for local-only dir marker, got: %s", actions[0].Action)
	}
}
