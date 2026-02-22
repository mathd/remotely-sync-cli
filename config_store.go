package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

type persistedOptions struct {
	LocalPath      string `json:"localPath"`
	Endpoint       string `json:"endpoint"`
	Region         string `json:"region"`
	Bucket         string `json:"bucket"`
	AccessKey      string `json:"accessKey"`
	SecretKey      string `json:"secretKey"`
	Prefix         string `json:"prefix"`
	Password       string `json:"password"`
	Encryption     string `json:"encryption"`
	StateFile      string `json:"stateFile"`
	Direction      string `json:"direction"`
	ForcePathStyle bool   `json:"forcePathStyle"`
	SyncConfigDir  bool   `json:"syncConfigDir"`
	SyncBookmarks  bool   `json:"syncBookmarks"`
	SyncUnderscore bool   `json:"syncUnderscore"`
	ConfigDir      string `json:"configDir"`
	ConflictAction string `json:"conflictAction"`
	AccurateMTime  bool   `json:"accurateMTime"`
	DisableS3Meta  bool   `json:"disableS3Meta"`
	ProtectPercent int    `json:"protectPercent"`
}

type exportedConfig struct {
	Version         int              `json:"version"`
	ContainsSecrets bool             `json:"containsSecrets"`
	Config          persistedOptions `json:"config"`
}

func configFilePath() (string, error) {
	base, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("unable to resolve config directory: %w", err)
	}
	return filepath.Join(base, "s3sync-go", "config.json"), nil
}

func loadPersistedOptions() (persistedOptions, bool, error) {
	var out persistedOptions
	path, err := configFilePath()
	if err != nil {
		return out, false, err
	}
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return out, false, nil
		}
		return out, false, fmt.Errorf("unable to read config file: %w", err)
	}
	if err := json.Unmarshal(b, &out); err != nil {
		return out, false, fmt.Errorf("unable to parse config file %s: %w", path, err)
	}
	return out, true, nil
}

func savePersistedOptions(opts options) error {
	path, err := configFilePath()
	if err != nil {
		return err
	}
	out := persistedOptions{
		LocalPath:      opts.LocalPath,
		Endpoint:       opts.Endpoint,
		Region:         opts.Region,
		Bucket:         opts.Bucket,
		AccessKey:      opts.AccessKey,
		SecretKey:      opts.SecretKey,
		Prefix:         opts.Prefix,
		Password:       opts.Password,
		Encryption:     opts.Encryption,
		StateFile:      opts.StateFile,
		Direction:      opts.Direction,
		ForcePathStyle: opts.ForcePathStyle,
		SyncConfigDir:  opts.SyncConfigDir,
		SyncBookmarks:  opts.SyncBookmarks,
		SyncUnderscore: opts.SyncUnderscore,
		ConfigDir:      opts.ConfigDir,
		ConflictAction: opts.ConflictAction,
		AccurateMTime:  opts.AccurateMTime,
		DisableS3Meta:  opts.DisableS3Meta,
		ProtectPercent: opts.ProtectPercent,
	}
	b, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return fmt.Errorf("unable to marshal config: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("unable to create config directory: %w", err)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		return fmt.Errorf("unable to write config file: %w", err)
	}
	return nil
}

func deletePersistedOptions() error {
	path, err := configFilePath()
	if err != nil {
		return err
	}
	err = os.Remove(path)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("unable to remove config file: %w", err)
	}
	return nil
}

func optionsFromPersisted(p persistedOptions) options {
	return options{
		LocalPath:      p.LocalPath,
		Endpoint:       p.Endpoint,
		Region:         p.Region,
		Bucket:         p.Bucket,
		AccessKey:      p.AccessKey,
		SecretKey:      p.SecretKey,
		Prefix:         p.Prefix,
		Password:       p.Password,
		Encryption:     p.Encryption,
		StateFile:      p.StateFile,
		Direction:      p.Direction,
		ForcePathStyle: p.ForcePathStyle,
		SyncConfigDir:  p.SyncConfigDir,
		SyncBookmarks:  p.SyncBookmarks,
		SyncUnderscore: p.SyncUnderscore,
		ConfigDir:      p.ConfigDir,
		ConflictAction: p.ConflictAction,
		AccurateMTime:  p.AccurateMTime,
		DisableS3Meta:  p.DisableS3Meta,
		ProtectPercent: p.ProtectPercent,
	}
}

func buildExportedConfig(p persistedOptions, includeSecrets bool) exportedConfig {
	copyCfg := p
	if !includeSecrets {
		copyCfg.AccessKey = maskSecret(copyCfg.AccessKey)
		copyCfg.SecretKey = maskSecret(copyCfg.SecretKey)
		copyCfg.Password = maskSecret(copyCfg.Password)
	}
	return exportedConfig{
		Version:         1,
		ContainsSecrets: includeSecrets,
		Config:          copyCfg,
	}
}

func hasMaskedSecrets(p persistedOptions) bool {
	return strings.Contains(p.AccessKey, "*") || strings.Contains(p.SecretKey, "*") || strings.Contains(p.Password, "*")
}

func hasInteractiveInput() bool {
	fi, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return (fi.Mode() & os.ModeCharDevice) != 0
}

func completeSyncOptionsInteractively(opts *options, fullWizard bool) (bool, error) {
	if !hasInteractiveInput() {
		return false, nil
	}

	requiredMissing := strings.TrimSpace(opts.LocalPath) == "" ||
		strings.TrimSpace(opts.Endpoint) == "" ||
		strings.TrimSpace(opts.Region) == "" ||
		strings.TrimSpace(opts.Bucket) == "" ||
		strings.TrimSpace(opts.AccessKey) == "" ||
		strings.TrimSpace(opts.SecretKey) == ""

	if !fullWizard && !requiredMissing {
		return false, nil
	}

	fmt.Println("Interactive setup for s3sync-go")
	reader := bufio.NewReader(os.Stdin)

	var err error
	opts.LocalPath, err = promptString(reader, "Local folder", opts.LocalPath, true)
	if err != nil {
		return false, err
	}
	opts.Endpoint, err = promptString(reader, "S3 endpoint", opts.Endpoint, true)
	if err != nil {
		return false, err
	}
	opts.Region, err = promptString(reader, "S3 region", opts.Region, true)
	if err != nil {
		return false, err
	}
	opts.Bucket, err = promptString(reader, "S3 bucket", opts.Bucket, true)
	if err != nil {
		return false, err
	}
	opts.AccessKey, err = promptString(reader, "S3 access key", opts.AccessKey, true)
	if err != nil {
		return false, err
	}
	opts.SecretKey, err = promptString(reader, "S3 secret key", opts.SecretKey, true)
	if err != nil {
		return false, err
	}

	if fullWizard {
		opts.Prefix, err = promptString(reader, "S3 prefix", opts.Prefix, false)
		if err != nil {
			return false, err
		}
		opts.Password, err = promptString(reader, "Encryption password (empty for none)", opts.Password, false)
		if err != nil {
			return false, err
		}
		if strings.TrimSpace(opts.Password) != "" {
			defaultMethod := opts.Encryption
			if defaultMethod == "" {
				defaultMethod = "remotely-sync-base64url"
			}
			opts.Encryption, err = promptString(reader, "Encryption method (auto|openssl-base64|rclone-base64|remotely-sync-base64url)", defaultMethod, true)
			if err != nil {
				return false, err
			}
		} else {
			opts.Encryption = ""
		}
		opts.Direction, err = promptString(reader, "Direction", pickDefault(opts.Direction, "bidirectional"), true)
		if err != nil {
			return false, err
		}
		opts.ConfigDir, err = promptString(reader, "Config dir", pickDefault(opts.ConfigDir, ".obsidian"), true)
		if err != nil {
			return false, err
		}
		opts.ConflictAction, err = promptString(reader, "Conflict action", pickDefault(opts.ConflictAction, "keep_newer"), true)
		if err != nil {
			return false, err
		}
		opts.ForcePathStyle, err = promptBool(reader, "Force path style", opts.ForcePathStyle)
		if err != nil {
			return false, err
		}
		opts.SyncConfigDir, err = promptBool(reader, "Sync config dir", opts.SyncConfigDir)
		if err != nil {
			return false, err
		}
		opts.SyncBookmarks, err = promptBool(reader, "Sync bookmarks", opts.SyncBookmarks)
		if err != nil {
			return false, err
		}
		opts.SyncUnderscore, err = promptBool(reader, "Sync underscore items", opts.SyncUnderscore)
		if err != nil {
			return false, err
		}
		opts.AccurateMTime, err = promptBool(reader, "Accurate mtime", opts.AccurateMTime)
		if err != nil {
			return false, err
		}
		opts.DisableS3Meta, err = promptBool(reader, "Disable S3 metadata sync", opts.DisableS3Meta)
		if err != nil {
			return false, err
		}
		opts.ProtectPercent, err = promptInt(reader, "Protect modify percentage", pickDefaultInt(opts.ProtectPercent, 50))
		if err != nil {
			return false, err
		}
	}

	return true, nil
}

func promptString(reader *bufio.Reader, label, current string, required bool) (string, error) {
	for {
		if strings.TrimSpace(current) == "" {
			fmt.Printf("%s: ", label)
		} else {
			fmt.Printf("%s [%s]: ", label, current)
		}
		line, err := reader.ReadString('\n')
		if err != nil {
			return "", err
		}
		line = strings.TrimSpace(line)
		if line != "" {
			return line, nil
		}
		if strings.TrimSpace(current) != "" {
			return current, nil
		}
		if !required {
			return "", nil
		}
		fmt.Println("This value is required.")
	}
}

func promptBool(reader *bufio.Reader, label string, current bool) (bool, error) {
	defaultValue := "n"
	if current {
		defaultValue = "y"
	}
	for {
		fmt.Printf("%s [y/n, default=%s]: ", label, defaultValue)
		line, err := reader.ReadString('\n')
		if err != nil {
			return false, err
		}
		line = strings.ToLower(strings.TrimSpace(line))
		if line == "" {
			return current, nil
		}
		if line == "y" || line == "yes" || line == "true" {
			return true, nil
		}
		if line == "n" || line == "no" || line == "false" {
			return false, nil
		}
		fmt.Println("Please enter y or n.")
	}
}

func promptInt(reader *bufio.Reader, label string, current int) (int, error) {
	for {
		fmt.Printf("%s [%d]: ", label, current)
		line, err := reader.ReadString('\n')
		if err != nil {
			return 0, err
		}
		line = strings.TrimSpace(line)
		if line == "" {
			return current, nil
		}
		v, err := strconv.Atoi(line)
		if err == nil {
			return v, nil
		}
		fmt.Println("Please enter an integer.")
	}
}

func pickDefault(v string, fallback string) string {
	if strings.TrimSpace(v) == "" {
		return fallback
	}
	return v
}

func pickDefaultInt(v int, fallback int) int {
	if v == 0 {
		return fallback
	}
	return v
}
