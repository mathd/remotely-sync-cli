package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

const defaultStateFile = ".remotely-save-cli-state.json"

const (
	autoEncryptionProbeSampleLimit  = 512
	checkEncryptionProbeSampleLimit = 1024
)

type options struct {
	LocalPath      string
	Endpoint       string
	Region         string
	Bucket         string
	AccessKey      string
	SecretKey      string
	Prefix         string
	Password       string
	Encryption     string
	StateFile      string
	Direction      string
	ForcePathStyle bool
	DryRun         bool
	CheckJSON      bool
	SyncConfigDir  bool
	SyncBookmarks  bool
	SyncUnderscore bool
	ConfigDir      string
	ConflictAction string
	AccurateMTime  bool
	ProtectPercent int
	DisableS3Meta  bool
	IgnorePaths    multiFlag
	AllowPaths     multiFlag
	rcloneCipher   rcloneCipher
}

type multiFlag []string

func (m *multiFlag) String() string {
	return strings.Join(*m, ",")
}

func (m *multiFlag) Set(value string) error {
	v := strings.TrimSpace(value)
	if v != "" {
		*m = append(*m, v)
	}
	return nil
}

type fileSnapshot struct {
	Size    int64 `json:"size"`
	MTimeMS int64 `json:"mtimeMs"`
}

type stateEntry struct {
	Local    *fileSnapshot `json:"local"`
	Remote   *fileSnapshot `json:"remote"`
	SyncedAt int64         `json:"syncedAt"`
}

type syncState struct {
	Version int                   `json:"version"`
	Files   map[string]stateEntry `json:"files"`
}

type localMeta struct {
	Key      string
	FullPath string
	Size     int64
	MTimeMS  int64
	CTimeMS  int64
}

type remoteMeta struct {
	Key       string
	RemoteKey string
	Size      int64
	MTimeMS   int64
}

type plannedAction struct {
	Key    string
	Action string
}

type cliExitError struct {
	Code int
	Msg  string
}

func (e *cliExitError) Error() string {
	return e.Msg
}

func (e *cliExitError) ExitCode() int {
	return e.Code
}

func newCLIExitError(code int, msg string) error {
	return &cliExitError{Code: code, Msg: msg}
}

type checkResult struct {
	Status  string `json:"status"`
	Method  string `json:"method,omitempty"`
	Message string `json:"message"`
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		var exitErr *cliExitError
		if errors.As(err, &exitErr) {
			os.Exit(exitErr.ExitCode())
		}
		os.Exit(1)
	}
}

func run() error {
	persisted, hasPersisted, err := loadPersistedOptions()
	if err != nil {
		return err
	}

	command := "sync"
	if len(os.Args) > 1 && !strings.HasPrefix(os.Args[1], "-") {
		command = os.Args[1]
	}

	if command == "check-encryption" {
		opts, showHelp, _, err := parseCheckFlags(command, persisted)
		if err != nil {
			return err
		}
		if showHelp {
			return nil
		}
		if err := validateAndNormalizeCheckOptions(&opts); err != nil {
			return err
		}

		ctx := context.Background()
		client, err := newS3Client(ctx, opts)
		if err != nil {
			return err
		}

		rawKeys, err := sampleRemoteRelativeKeys(ctx, client, opts, checkEncryptionProbeSampleLimit)
		if err != nil {
			return err
		}
		if len(rawKeys) == 0 {
			printCheckResult(opts, checkResult{
				Status:  "empty",
				Method:  "rclone-base64",
				Message: "remote appears empty; suggested method is rclone-base64",
			})
			return nil
		}

		if opts.Encryption == "auto" {
			method, err := detectEncryptionMethodFromKeys(opts.Password, rawKeys)
			if err != nil {
				printCheckResult(opts, checkResult{
					Status:  "mismatch",
					Message: "password does not match remotely-sync-base64url, openssl-base64, or rclone-base64 for this remote",
				})
				return newCLIExitError(2, "encryption check mismatch")
			}
			printCheckResult(opts, checkResult{
				Status:  "match",
				Method:  method,
				Message: fmt.Sprintf("password matches method %s", method),
			})
			return nil
		}

		if err := prepareEncryption(&opts); err != nil {
			return err
		}
		matched := 0
		for _, raw := range rawKeys {
			if shouldSkipEncryptionProbeKey(raw) {
				continue
			}
			decoded, err := decodeRemoteKey(opts, raw)
			if err != nil {
				continue
			}
			if _, err := sanitizeRelativeSyncKey(decoded); err != nil {
				continue
			}
			matched++
		}
		if matched == 0 {
			printCheckResult(opts, checkResult{
				Status:  "mismatch",
				Method:  opts.Encryption,
				Message: fmt.Sprintf("password or method mismatch for %s", opts.Encryption),
			})
			return newCLIExitError(2, "encryption check mismatch")
		}
		printCheckResult(opts, checkResult{
			Status:  "match",
			Method:  opts.Encryption,
			Message: fmt.Sprintf("password matches method %s", opts.Encryption),
		})
		return nil
	}

	if command == "config" {
		action, args := parseConfigCommandArgs()
		switch action {
		case "show":
			showJSON, showSecrets, showHelp, err := parseConfigShowFlags(args)
			if err != nil {
				return err
			}
			if showHelp {
				return nil
			}
			if !hasPersisted {
				fmt.Println("No saved config found.")
				return nil
			}
			printConfig(persisted, showJSON, showSecrets)
			return nil
		case "path":
			cfgPath, err := configFilePath()
			if err != nil {
				return err
			}
			fmt.Println(cfgPath)
			return nil
		case "edit":
			opts := optionsFromPersisted(persisted)
			prompted, err := completeSyncOptionsInteractively(&opts, true)
			if err != nil {
				return err
			}
			if !prompted {
				return fmt.Errorf("config edit requires an interactive terminal")
			}
			if err := validateAndNormalizeOptions(&opts); err != nil {
				return err
			}
			if err := savePersistedOptions(opts); err != nil {
				return err
			}
			cfgPath, _ := configFilePath()
			fmt.Printf("Saved config: %s\n", cfgPath)
			return nil
		case "reset":
			force, showHelp, err := parseConfigResetFlags(args)
			if err != nil {
				return err
			}
			if showHelp {
				return nil
			}
			if !force {
				if !hasInteractiveInput() {
					return fmt.Errorf("config reset requires --yes in non-interactive mode")
				}
				ok, err := promptConfirm("Delete saved config? [y/N]: ")
				if err != nil {
					return err
				}
				if !ok {
					fmt.Println("Cancelled.")
					return nil
				}
			}
			if err := deletePersistedOptions(); err != nil {
				return err
			}
			fmt.Println("Saved config removed.")
			return nil
		case "export":
			filePath, includeSecrets, showHelp, err := parseConfigExportFlags(args)
			if err != nil {
				return err
			}
			if showHelp {
				return nil
			}
			if !hasPersisted {
				return fmt.Errorf("no saved config found")
			}
			if strings.TrimSpace(filePath) == "" {
				return fmt.Errorf("missing required option: --file")
			}
			exported := buildExportedConfig(persisted, includeSecrets)
			b, err := json.MarshalIndent(exported, "", "  ")
			if err != nil {
				return fmt.Errorf("unable to serialize config export: %w", err)
			}
			absFile, err := filepath.Abs(filePath)
			if err != nil {
				return fmt.Errorf("unable to resolve export file path: %w", err)
			}
			if err := os.WriteFile(absFile, b, 0o600); err != nil {
				return fmt.Errorf("unable to write export file: %w", err)
			}
			fmt.Printf("Exported config: %s\n", absFile)
			if !includeSecrets {
				fmt.Println("Note: secrets are masked. Use --include-secrets to export full credentials.")
			}
			return nil
		case "import":
			filePath, showHelp, err := parseConfigImportFlags(args)
			if err != nil {
				return err
			}
			if showHelp {
				return nil
			}
			if strings.TrimSpace(filePath) == "" {
				return fmt.Errorf("missing required option: --file")
			}
			absFile, err := filepath.Abs(filePath)
			if err != nil {
				return fmt.Errorf("unable to resolve import file path: %w", err)
			}
			b, err := os.ReadFile(absFile)
			if err != nil {
				return fmt.Errorf("unable to read import file: %w", err)
			}
			var imported exportedConfig
			if err := json.Unmarshal(b, &imported); err != nil {
				return fmt.Errorf("unable to parse import file: %w", err)
			}
			if imported.Version == 0 {
				imported.Version = 1
			}
			if imported.Version != 1 {
				return fmt.Errorf("unsupported import version: %d", imported.Version)
			}
			if !imported.ContainsSecrets || hasMaskedSecrets(imported.Config) {
				return fmt.Errorf("import file does not contain usable secrets; export with --include-secrets")
			}
			candidate := optionsFromPersisted(imported.Config)
			if err := validateAndNormalizeOptions(&candidate); err != nil {
				return fmt.Errorf("imported config is invalid: %w", err)
			}
			if err := savePersistedOptions(candidate); err != nil {
				return err
			}
			cfgPath, _ := configFilePath()
			fmt.Printf("Imported config into: %s\n", cfgPath)
			return nil
		default:
			return fmt.Errorf("unsupported config command: %s", action)
		}
	}

	if command != "sync" {
		return fmt.Errorf("unsupported command: %s", command)
	}

	opts, showHelp, hasExplicit, err := parseSyncFlags(command, persisted)
	if err != nil {
		return err
	}
	if showHelp {
		return nil
	}
	prompted, err := completeSyncOptionsInteractively(&opts, !hasExplicit && !hasPersisted)
	if err != nil {
		return err
	}

	if err := validateAndNormalizeOptions(&opts); err != nil {
		return err
	}
	if err := ensureLocalPathReady(opts); err != nil {
		return err
	}
	if prompted {
		if err := savePersistedOptions(opts); err != nil {
			return err
		}
		if cfgPath, pErr := configFilePath(); pErr == nil {
			fmt.Printf("Saved config: %s\n", cfgPath)
		}
	}

	ctx := context.Background()
	client, err := newS3Client(ctx, opts)
	if err != nil {
		return err
	}
	if err := resolveAutoEncryption(ctx, client, &opts); err != nil {
		return err
	}
	if err := prepareEncryption(&opts); err != nil {
		return err
	}
	if err := runPasswordCompatibilityCheck(ctx, client, opts); err != nil {
		return err
	}

	fmt.Printf("Local root: %s\n", opts.LocalPath)
	fmt.Printf("Bucket: s3://%s/%s\n", opts.Bucket, opts.Prefix)
	fmt.Printf("Direction: %s\n", opts.Direction)
	fmt.Printf("State file: %s\n", opts.StateFile)
	if encryptionEnabled(opts) {
		fmt.Printf("Encryption: %s\n", opts.Encryption)
	}
	if opts.DryRun {
		fmt.Println("Mode: dry-run")
	}

	stateRel, err := filepath.Rel(opts.LocalPath, opts.StateFile)
	if err != nil {
		return fmt.Errorf("unable to get state file relative path: %w", err)
	}
	stateRel = filepath.ToSlash(stateRel)

	filters, err := compileFilters(opts.IgnorePaths, opts.AllowPaths)
	if err != nil {
		return err
	}

	localMap, err := walkLocalFiles(opts, stateRel)
	if err != nil {
		return err
	}
	remoteMapRaw, err := listRemoteFiles(ctx, client, opts)
	if err != nil {
		return err
	}
	remoteDeletions, err := readRemoteDeletionMetadata(ctx, client, opts, remoteMapRaw)
	if err != nil {
		return err
	}
	localMap = filterLocalMap(localMap, opts, filters)
	remoteMap := filterRemoteMap(remoteMapRaw, opts, filters)
	prevState, err := readStateFile(opts.StateFile)
	if err != nil {
		return err
	}
	prevState = filterState(prevState, opts, filters)

	actions := buildPlan(localMap, remoteMap, prevState, opts.Direction, opts.ConflictAction, opts.ConfigDir, remoteDeletions)
	if err := enforceProtectModifyPercentage(actions, localMap, remoteMap, opts.ProtectPercent); err != nil {
		return err
	}
	counters, err := runPlan(ctx, client, opts, actions, localMap, remoteMap)
	if err != nil {
		return err
	}

	if !opts.DryRun {
		localAfter, err := walkLocalFiles(opts, stateRel)
		if err != nil {
			return err
		}
		remoteAfterRaw, err := listRemoteFiles(ctx, client, opts)
		if err != nil {
			return err
		}
		if err := syncRemoteDeletionMetadata(ctx, client, opts, actions, remoteDeletions, remoteAfterRaw, localMap, remoteMap, prevState); err != nil {
			return err
		}
		remoteAfterRaw, err = listRemoteFiles(ctx, client, opts)
		if err != nil {
			return err
		}
		localAfter = filterLocalMap(localAfter, opts, filters)
		remoteAfter := filterRemoteMap(remoteAfterRaw, opts, filters)
		if err := writeStateFile(opts.StateFile, localAfter, remoteAfter); err != nil {
			return err
		}
	}

	fmt.Println("Done.")
	fmt.Printf(
		"push=%d pull=%d delete_local=%d delete_remote=%d smart_conflict=%d noop=%d\n",
		counters["push"],
		counters["pull"],
		counters["delete_local"],
		counters["delete_remote"],
		counters["smart_conflict"],
		counters["noop"],
	)
	return nil
}

func parseSyncFlags(command string, persisted persistedOptions) (options, bool, bool, error) {
	var opts options

	args := os.Args[1:]
	if command == "sync" && len(args) > 0 && args[0] == "sync" {
		args = args[1:]
	}

	fs := flag.NewFlagSet("sync", flag.ContinueOnError)
	fs.SetOutput(os.Stdout)
	fs.StringVar(&opts.LocalPath, "local", getenv("RS_LOCAL_PATH", persisted.LocalPath), "Local folder")
	fs.StringVar(&opts.Endpoint, "endpoint", getenv("RS_S3_ENDPOINT", persisted.Endpoint), "S3 endpoint")
	fs.StringVar(&opts.Region, "region", getenv("RS_S3_REGION", persisted.Region), "S3 region")
	fs.StringVar(&opts.Bucket, "bucket", getenv("RS_S3_BUCKET", persisted.Bucket), "S3 bucket")
	fs.StringVar(&opts.AccessKey, "access-key", "", "S3 access key id")
	fs.StringVar(&opts.SecretKey, "secret-key", "", "S3 secret access key")
	fs.StringVar(&opts.Prefix, "prefix", getenv("RS_S3_PREFIX", persisted.Prefix), "Remote key prefix")
	fs.StringVar(&opts.Password, "encryption-password", "", "Password for E2E encryption")
	encryptionDefault := pickDefault(persisted.Encryption, "remotely-sync-base64url")
	fs.StringVar(&opts.Encryption, "encryption-method", getenv("RS_ENCRYPTION_METHOD", encryptionDefault), "Encryption method (openssl-base64 | rclone-base64 | remotely-sync-base64url | auto)")
	fs.StringVar(&opts.StateFile, "state-file", persisted.StateFile, "State file path")
	fs.StringVar(&opts.Direction, "direction", pickDefault(persisted.Direction, "bidirectional"), "bidirectional | incremental_pull_only | incremental_push_only | incremental_pull_and_delete_only | incremental_push_and_delete_only")
	fs.BoolVar(&opts.ForcePathStyle, "force-path-style", persisted.ForcePathStyle, "Use path-style S3 URL")
	fs.BoolVar(&opts.DryRun, "dry-run", false, "Print actions only")
	fs.BoolVar(&opts.SyncConfigDir, "sync-config-dir", persisted.SyncConfigDir, "Sync full config dir")
	fs.BoolVar(&opts.SyncBookmarks, "sync-bookmarks", persisted.SyncBookmarks, "Sync only .obsidian/bookmarks.json when config dir sync is off")
	fs.BoolVar(&opts.SyncUnderscore, "sync-underscore-items", persisted.SyncUnderscore, "Sync _hidden files/folders")
	fs.StringVar(&opts.ConfigDir, "config-dir", pickDefault(persisted.ConfigDir, ".obsidian"), "Config directory name")
	fs.StringVar(&opts.ConflictAction, "conflict-action", pickDefault(persisted.ConflictAction, "keep_newer"), "keep_newer | keep_larger | smart_conflict")
	fs.BoolVar(&opts.AccurateMTime, "accurate-mtime", persisted.AccurateMTime, "Read MTime from object metadata with HeadObject")
	fs.BoolVar(&opts.DisableS3Meta, "disable-s3-metadata-sync", persisted.DisableS3Meta, "Do not write S3 object metadata (modification_time)")
	fs.IntVar(&opts.ProtectPercent, "protect-modify-percentage", pickDefaultInt(persisted.ProtectPercent, 50), "Abort if too many files are modified/deleted")
	fs.Var(&opts.IgnorePaths, "ignore-path", "Regex path to ignore (repeatable)")
	fs.Var(&opts.AllowPaths, "allow-path", "Regex path to allow (repeatable)")

	fs.Usage = func() {
		fmt.Println("remotely-sync standalone S3 sync (Go)")
		fmt.Println()
		fmt.Println("Usage:")
		fmt.Println("  s3sync-go sync [options]")
		fmt.Println()
		fmt.Println("Required:")
		fmt.Println("  --local <path>")
		fmt.Println("  --endpoint <host-or-url>")
		fmt.Println("  --region <region>")
		fmt.Println("  --bucket <name>")
		fmt.Println("  --access-key <key>")
		fmt.Println("  --secret-key <key>")
		fmt.Println()
		fmt.Println("Optional:")
		fs.PrintDefaults()
		fmt.Println()
		fmt.Println("Environment fallbacks:")
		fmt.Println("  RS_LOCAL_PATH, RS_S3_ENDPOINT, RS_S3_REGION, RS_S3_BUCKET,")
		fmt.Println("  RS_S3_ACCESS_KEY, RS_S3_SECRET_KEY, RS_S3_PREFIX,")
		fmt.Println("  RS_ENCRYPTION_PASSWORD, RS_ENCRYPTION_METHOD")
	}

	err := fs.Parse(args)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return opts, true, false, nil
		}
		return opts, false, false, err
	}
	hasExplicit := false
	visited := map[string]bool{}
	fs.Visit(func(*flag.Flag) {
		hasExplicit = true
	})
	fs.Visit(func(f *flag.Flag) {
		visited[f.Name] = true
	})

	if !visited["access-key"] {
		opts.AccessKey = getenv("RS_S3_ACCESS_KEY", persisted.AccessKey)
	}
	if !visited["secret-key"] {
		opts.SecretKey = getenv("RS_S3_SECRET_KEY", persisted.SecretKey)
	}
	if !visited["encryption-password"] {
		opts.Password = getenv("RS_ENCRYPTION_PASSWORD", persisted.Password)
	}

	return opts, false, hasExplicit, nil
}

func parseCheckFlags(command string, persisted persistedOptions) (options, bool, bool, error) {
	var opts options

	args := os.Args[1:]
	if command == "check-encryption" && len(args) > 0 && args[0] == "check-encryption" {
		args = args[1:]
	}

	fs := flag.NewFlagSet("check-encryption", flag.ContinueOnError)
	fs.SetOutput(os.Stdout)
	fs.StringVar(&opts.Endpoint, "endpoint", getenv("RS_S3_ENDPOINT", persisted.Endpoint), "S3 endpoint")
	fs.StringVar(&opts.Region, "region", getenv("RS_S3_REGION", persisted.Region), "S3 region")
	fs.StringVar(&opts.Bucket, "bucket", getenv("RS_S3_BUCKET", persisted.Bucket), "S3 bucket")
	fs.StringVar(&opts.AccessKey, "access-key", "", "S3 access key id")
	fs.StringVar(&opts.SecretKey, "secret-key", "", "S3 secret access key")
	fs.StringVar(&opts.Prefix, "prefix", getenv("RS_S3_PREFIX", persisted.Prefix), "Remote key prefix")
	fs.StringVar(&opts.Password, "encryption-password", "", "Password for E2E encryption")
	encryptionDefault := pickDefault(persisted.Encryption, "auto")
	fs.StringVar(&opts.Encryption, "encryption-method", getenv("RS_ENCRYPTION_METHOD", encryptionDefault), "Encryption method (auto | openssl-base64 | rclone-base64 | remotely-sync-base64url)")
	fs.BoolVar(&opts.CheckJSON, "json", false, "Output result as JSON")
	fs.BoolVar(&opts.ForcePathStyle, "force-path-style", persisted.ForcePathStyle, "Use path-style S3 URL")

	fs.Usage = func() {
		fmt.Println("remotely-sync standalone S3 encryption check (Go)")
		fmt.Println()
		fmt.Println("Usage:")
		fmt.Println("  s3sync-go check-encryption [options]")
		fmt.Println()
		fmt.Println("Required:")
		fmt.Println("  --endpoint <host-or-url>")
		fmt.Println("  --region <region>")
		fmt.Println("  --bucket <name>")
		fmt.Println("  --access-key <key>")
		fmt.Println("  --secret-key <key>")
		fmt.Println("  --encryption-password <password>")
		fmt.Println()
		fmt.Println("Optional:")
		fs.PrintDefaults()
	}

	err := fs.Parse(args)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return opts, true, false, nil
		}
		return opts, false, false, err
	}
	hasExplicit := false
	visited := map[string]bool{}
	fs.Visit(func(*flag.Flag) {
		hasExplicit = true
	})
	fs.Visit(func(f *flag.Flag) {
		visited[f.Name] = true
	})

	if !visited["access-key"] {
		opts.AccessKey = getenv("RS_S3_ACCESS_KEY", persisted.AccessKey)
	}
	if !visited["secret-key"] {
		opts.SecretKey = getenv("RS_S3_SECRET_KEY", persisted.SecretKey)
	}
	if !visited["encryption-password"] {
		opts.Password = getenv("RS_ENCRYPTION_PASSWORD", persisted.Password)
	}

	return opts, false, hasExplicit, nil
}

func printCheckResult(opts options, result checkResult) {
	if opts.CheckJSON {
		b, _ := json.Marshal(result)
		fmt.Println(string(b))
		return
	}
	if result.Method != "" {
		fmt.Printf("Encryption check: %s (%s)\n", result.Message, result.Method)
		return
	}
	fmt.Printf("Encryption check: %s\n", result.Message)
}

func parseConfigCommandArgs() (string, []string) {
	args := os.Args[1:]
	if len(args) > 0 && args[0] == "config" {
		args = args[1:]
	}
	action := "show"
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		action = strings.ToLower(strings.TrimSpace(args[0]))
		args = args[1:]
	}
	return action, args
}

func parseConfigShowFlags(args []string) (bool, bool, bool, error) {
	showJSON := false
	showSecrets := false
	fs := flag.NewFlagSet("config show", flag.ContinueOnError)
	fs.SetOutput(os.Stdout)
	fs.BoolVar(&showJSON, "json", false, "Output config as JSON")
	fs.BoolVar(&showSecrets, "show-secrets", false, "Show full secret values")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return false, false, true, nil
		}
		return false, false, false, err
	}
	return showJSON, showSecrets, false, nil
}

func parseConfigResetFlags(args []string) (bool, bool, error) {
	force := false
	fs := flag.NewFlagSet("config reset", flag.ContinueOnError)
	fs.SetOutput(os.Stdout)
	fs.BoolVar(&force, "yes", false, "Skip confirmation prompt")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return false, true, nil
		}
		return false, false, err
	}
	return force, false, nil
}

func parseConfigExportFlags(args []string) (string, bool, bool, error) {
	filePath := ""
	includeSecrets := false
	fs := flag.NewFlagSet("config export", flag.ContinueOnError)
	fs.SetOutput(os.Stdout)
	fs.StringVar(&filePath, "file", "", "Destination JSON file path")
	fs.BoolVar(&includeSecrets, "include-secrets", false, "Include full secrets in export")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return "", false, true, nil
		}
		return "", false, false, err
	}
	return filePath, includeSecrets, false, nil
}

func parseConfigImportFlags(args []string) (string, bool, error) {
	filePath := ""
	fs := flag.NewFlagSet("config import", flag.ContinueOnError)
	fs.SetOutput(os.Stdout)
	fs.StringVar(&filePath, "file", "", "Source JSON file path")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return "", true, nil
		}
		return "", false, err
	}
	return filePath, false, nil
}

func promptConfirm(msg string) (bool, error) {
	fmt.Print(msg)
	var in string
	if _, err := fmt.Scanln(&in); err != nil {
		if errors.Is(err, os.ErrInvalid) {
			return false, nil
		}
		if err.Error() == "unexpected newline" {
			return false, nil
		}
	}
	in = strings.ToLower(strings.TrimSpace(in))
	return in == "y" || in == "yes", nil
}

func maskSecret(s string) string {
	if s == "" {
		return ""
	}
	if len(s) <= 4 {
		return "****"
	}
	return strings.Repeat("*", len(s)-4) + s[len(s)-4:]
}

func printConfig(p persistedOptions, asJSON bool, showSecrets bool) {
	secretKey := p.SecretKey
	accessKey := p.AccessKey
	password := p.Password
	if !showSecrets {
		secretKey = maskSecret(secretKey)
		accessKey = maskSecret(accessKey)
		password = maskSecret(password)
	}
	if asJSON {
		out := map[string]any{
			"localPath":      p.LocalPath,
			"endpoint":       p.Endpoint,
			"region":         p.Region,
			"bucket":         p.Bucket,
			"accessKey":      accessKey,
			"secretKey":      secretKey,
			"prefix":         p.Prefix,
			"password":       password,
			"encryption":     p.Encryption,
			"stateFile":      p.StateFile,
			"direction":      p.Direction,
			"forcePathStyle": p.ForcePathStyle,
			"syncConfigDir":  p.SyncConfigDir,
			"syncBookmarks":  p.SyncBookmarks,
			"syncUnderscore": p.SyncUnderscore,
			"configDir":      p.ConfigDir,
			"conflictAction": p.ConflictAction,
			"accurateMTime":  p.AccurateMTime,
			"disableS3Meta":  p.DisableS3Meta,
			"protectPercent": p.ProtectPercent,
		}
		b, _ := json.MarshalIndent(out, "", "  ")
		fmt.Println(string(b))
		return
	}
	fmt.Printf("Local path: %s\n", p.LocalPath)
	fmt.Printf("Endpoint: %s\n", p.Endpoint)
	fmt.Printf("Region: %s\n", p.Region)
	fmt.Printf("Bucket: %s\n", p.Bucket)
	fmt.Printf("Access key: %s\n", accessKey)
	fmt.Printf("Secret key: %s\n", secretKey)
	fmt.Printf("Prefix: %s\n", p.Prefix)
	fmt.Printf("Encryption password: %s\n", password)
	fmt.Printf("Encryption method: %s\n", p.Encryption)
	fmt.Printf("State file: %s\n", p.StateFile)
	fmt.Printf("Direction: %s\n", p.Direction)
	fmt.Printf("Disable S3 metadata sync: %t\n", p.DisableS3Meta)
}

func validateAndNormalizeOptions(opts *options) error {
	required := map[string]string{
		"--local":      opts.LocalPath,
		"--endpoint":   opts.Endpoint,
		"--region":     opts.Region,
		"--bucket":     opts.Bucket,
		"--access-key": opts.AccessKey,
		"--secret-key": opts.SecretKey,
	}
	for key, value := range required {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("missing required option: %s", key)
		}
	}

	absLocal, err := filepath.Abs(opts.LocalPath)
	if err != nil {
		return fmt.Errorf("unable to resolve local path: %w", err)
	}
	opts.LocalPath = absLocal

	endpoint := strings.TrimSpace(opts.Endpoint)
	if !strings.HasPrefix(endpoint, "http://") && !strings.HasPrefix(endpoint, "https://") {
		endpoint = "https://" + endpoint
	}
	parsedEndpoint, err := url.Parse(endpoint)
	if err != nil {
		return fmt.Errorf("invalid endpoint: %w", err)
	}
	if parsedEndpoint.Scheme != "http" && parsedEndpoint.Scheme != "https" {
		return fmt.Errorf("invalid endpoint: scheme must be http or https")
	}
	if strings.TrimSpace(parsedEndpoint.Host) == "" {
		return fmt.Errorf("invalid endpoint: host is required")
	}
	if parsedEndpoint.Path != "" && parsedEndpoint.Path != "/" {
		return fmt.Errorf("invalid endpoint: path is not allowed")
	}
	if parsedEndpoint.RawQuery != "" || parsedEndpoint.Fragment != "" || parsedEndpoint.User != nil {
		return fmt.Errorf("invalid endpoint: query, fragment, and user info are not allowed")
	}
	opts.Endpoint = endpoint

	opts.Prefix = normalizePrefix(opts.Prefix)
	opts.Encryption = strings.ToLower(strings.TrimSpace(opts.Encryption))
	if opts.Password == "" {
		opts.Encryption = ""
	} else if opts.Encryption == "" {
		opts.Encryption = "remotely-sync-base64url"
	}
	if opts.Encryption != "" && opts.Encryption != "openssl-base64" && opts.Encryption != "rclone-base64" && opts.Encryption != "remotely-sync-base64url" && opts.Encryption != "auto" {
		return fmt.Errorf("invalid --encryption-method: %s (supported: openssl-base64, rclone-base64, remotely-sync-base64url, auto)", opts.Encryption)
	}

	direction := strings.ToLower(strings.TrimSpace(opts.Direction))
	if direction != "bidirectional" &&
		direction != "incremental_pull_only" &&
		direction != "incremental_push_only" &&
		direction != "incremental_pull_and_delete_only" &&
		direction != "incremental_push_and_delete_only" {
		return fmt.Errorf("invalid --direction: %s", opts.Direction)
	}
	opts.Direction = direction

	if !strings.HasPrefix(opts.ConfigDir, ".") {
		return fmt.Errorf("--config-dir must start with '.', got: %s", opts.ConfigDir)
	}

	opts.ConflictAction = strings.ToLower(strings.TrimSpace(opts.ConflictAction))
	if opts.ConflictAction != "keep_newer" && opts.ConflictAction != "keep_larger" && opts.ConflictAction != "smart_conflict" {
		return fmt.Errorf("invalid --conflict-action: %s", opts.ConflictAction)
	}

	if opts.ProtectPercent < -1 || opts.ProtectPercent > 100 {
		return fmt.Errorf("--protect-modify-percentage must be in [-1,100]")
	}

	if strings.TrimSpace(opts.StateFile) == "" {
		opts.StateFile = filepath.Join(opts.LocalPath, defaultStateFile)
	}
	absState, err := filepath.Abs(opts.StateFile)
	if err != nil {
		return fmt.Errorf("unable to resolve state file: %w", err)
	}
	opts.StateFile = absState

	return nil
}

func ensureLocalPathReady(opts options) error {
	info, err := os.Stat(opts.LocalPath)
	if err == nil {
		if !info.IsDir() {
			return fmt.Errorf("local path exists but is not a directory: %s", opts.LocalPath)
		}
		return nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("unable to inspect local path: %w", err)
	}
	if !hasInteractiveInput() {
		return fmt.Errorf("local path does not exist: %s", opts.LocalPath)
	}

	ok, err := promptConfirm(fmt.Sprintf("Local folder does not exist: %s. Create it? [y/N]: ", opts.LocalPath))
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("local path does not exist: %s", opts.LocalPath)
	}
	if err := os.MkdirAll(opts.LocalPath, 0o755); err != nil {
		return fmt.Errorf("unable to create local folder: %w", err)
	}
	return nil
}

func validateAndNormalizeCheckOptions(opts *options) error {
	required := map[string]string{
		"--endpoint":            opts.Endpoint,
		"--region":              opts.Region,
		"--bucket":              opts.Bucket,
		"--access-key":          opts.AccessKey,
		"--secret-key":          opts.SecretKey,
		"--encryption-password": opts.Password,
	}
	for key, value := range required {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("missing required option: %s", key)
		}
	}

	endpoint := strings.TrimSpace(opts.Endpoint)
	if !strings.HasPrefix(endpoint, "http://") && !strings.HasPrefix(endpoint, "https://") {
		endpoint = "https://" + endpoint
	}
	parsedEndpoint, err := url.Parse(endpoint)
	if err != nil {
		return fmt.Errorf("invalid endpoint: %w", err)
	}
	if parsedEndpoint.Scheme != "http" && parsedEndpoint.Scheme != "https" {
		return fmt.Errorf("invalid endpoint: scheme must be http or https")
	}
	if strings.TrimSpace(parsedEndpoint.Host) == "" {
		return fmt.Errorf("invalid endpoint: host is required")
	}
	if parsedEndpoint.Path != "" && parsedEndpoint.Path != "/" {
		return fmt.Errorf("invalid endpoint: path is not allowed")
	}
	if parsedEndpoint.RawQuery != "" || parsedEndpoint.Fragment != "" || parsedEndpoint.User != nil {
		return fmt.Errorf("invalid endpoint: query, fragment, and user info are not allowed")
	}
	opts.Endpoint = endpoint

	opts.Prefix = normalizePrefix(opts.Prefix)
	opts.Encryption = strings.ToLower(strings.TrimSpace(opts.Encryption))
	if opts.Encryption == "" {
		opts.Encryption = "auto"
	}
	if opts.Encryption != "auto" && opts.Encryption != "openssl-base64" && opts.Encryption != "rclone-base64" && opts.Encryption != "remotely-sync-base64url" {
		return fmt.Errorf("invalid --encryption-method: %s (supported: auto, openssl-base64, rclone-base64, remotely-sync-base64url)", opts.Encryption)
	}

	return nil
}

func resolveAutoEncryption(ctx context.Context, client *s3.Client, opts *options) error {
	if !encryptionEnabled(*opts) || opts.Encryption != "auto" {
		return nil
	}

	rawKeys, err := sampleRemoteRelativeKeys(ctx, client, *opts, autoEncryptionProbeSampleLimit)
	if err != nil {
		return err
	}
	if len(rawKeys) == 0 {
		opts.Encryption = "rclone-base64"
		fmt.Println("Encryption auto: remote empty, selected rclone-base64")
		return nil
	}

	method, err := detectEncryptionMethodFromKeys(opts.Password, rawKeys)
	if err != nil {
		return err
	}
	opts.Encryption = method
	fmt.Printf("Encryption auto: selected %s\n", method)
	return nil
}

func runPasswordCompatibilityCheck(ctx context.Context, client *s3.Client, opts options) error {
	rawKeys, err := sampleRemoteRelativeKeys(ctx, client, opts, autoEncryptionProbeSampleLimit)
	if err != nil {
		return err
	}
	if len(rawKeys) == 0 {
		return nil
	}

	if strings.TrimSpace(opts.Password) == "" {
		if hasLikelyEncryptedKeys(rawKeys) {
			return fmt.Errorf("remote appears encrypted but --encryption-password is empty; provide password and --encryption-method (or run check-encryption)")
		}
		return nil
	}

	matched := 0
	for _, raw := range rawKeys {
		if shouldSkipEncryptionProbeKey(raw) {
			continue
		}
		decoded, decErr := decodeRemoteKey(opts, raw)
		if decErr != nil {
			continue
		}
		if _, sanErr := sanitizeRelativeSyncKeyPreservingDirMarker(decoded); sanErr != nil {
			continue
		}
		matched++
	}
	if matched == 0 {
		return fmt.Errorf("password or encryption method mismatch for remote keys (method=%s); run check-encryption to verify", opts.Encryption)
	}
	return nil
}

func hasLikelyEncryptedKeys(rawKeys []string) bool {
	for _, raw := range rawKeys {
		if shouldSkipEncryptionProbeKey(raw) {
			continue
		}
		if strings.HasPrefix(raw, "U2FsdGVkX") {
			return true
		}
		if strings.Contains(raw, "/") {
			continue
		}
		if strings.Contains(raw, ".") {
			continue
		}
		b, err := base64.RawURLEncoding.DecodeString(raw)
		if err != nil {
			continue
		}
		if len(b) >= 16 && string(b[:8]) == "Salted__" {
			return true
		}
		if len(b) >= 44 {
			return true
		}
	}
	return false
}

func sampleRemoteRelativeKeys(ctx context.Context, client *s3.Client, opts options, limit int) ([]string, error) {
	out := make([]string, 0, limit)
	input := &s3.ListObjectsV2Input{Bucket: aws.String(opts.Bucket)}
	if opts.Prefix != "" {
		input.Prefix = aws.String(opts.Prefix)
	}
	paginator := s3.NewListObjectsV2Paginator(client, input)
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("unable to list remote files for encryption auto-detect: %w", err)
		}
		for _, item := range page.Contents {
			if item.Key == nil {
				continue
			}
			fullKey := *item.Key
			if strings.HasSuffix(fullKey, "/") || !strings.HasPrefix(fullKey, opts.Prefix) {
				continue
			}
			out = append(out, strings.TrimPrefix(fullKey, opts.Prefix))
			if len(out) >= limit {
				return out, nil
			}
		}
	}
	return out, nil
}

func newS3Client(ctx context.Context, opts options) (*s3.Client, error) {
	cfg, err := config.LoadDefaultConfig(
		ctx,
		config.WithRegion(opts.Region),
		config.WithCredentialsProvider(
			credentials.NewStaticCredentialsProvider(opts.AccessKey, opts.SecretKey, ""),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("unable to initialize aws config: %w", err)
	}

	client := s3.NewFromConfig(cfg, func(o *s3.Options) {
		o.UsePathStyle = opts.ForcePathStyle
		o.BaseEndpoint = aws.String(opts.Endpoint)
	})
	return client, nil
}

func normalizePrefix(prefix string) string {
	p := strings.TrimSpace(strings.ReplaceAll(prefix, "\\", "/"))
	if p == "" || p == "/" || p == "." {
		return ""
	}
	p = strings.TrimPrefix(p, "/")
	if !strings.HasSuffix(p, "/") {
		p += "/"
	}
	return p
}

func getenv(key string, fallback string) string {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	return value
}
