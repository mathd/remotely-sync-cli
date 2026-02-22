package main

import (
	"fmt"
	"path"
	"regexp"
	"strings"
)

type compiledFilters struct {
	ignore []*regexp.Regexp
	allow  []*regexp.Regexp
}

func compileFilters(ignore multiFlag, allow multiFlag) (*compiledFilters, error) {
	f := &compiledFilters{}
	for _, r := range ignore {
		re, err := regexp.Compile(r)
		if err != nil {
			return nil, fmt.Errorf("invalid --ignore-path regex %q: %w", r, err)
		}
		f.ignore = append(f.ignore, re)
	}
	for _, r := range allow {
		re, err := regexp.Compile(r)
		if err != nil {
			return nil, fmt.Errorf("invalid --allow-path regex %q: %w", r, err)
		}
		f.allow = append(f.allow, re)
	}
	return f, nil
}

func filterLocalMap(in map[string]localMeta, opts options, filters *compiledFilters) map[string]localMeta {
	out := map[string]localMeta{}
	for k, v := range in {
		if shouldSkipKey(k, opts, filters) {
			continue
		}
		out[k] = v
	}
	return out
}

func filterRemoteMap(in map[string]remoteMeta, opts options, filters *compiledFilters) map[string]remoteMeta {
	out := map[string]remoteMeta{}
	for k, v := range in {
		if shouldSkipKey(k, opts, filters) {
			continue
		}
		out[k] = v
	}
	return out
}

func filterState(in syncState, opts options, filters *compiledFilters) syncState {
	out := syncState{Version: in.Version, Files: map[string]stateEntry{}}
	for k, v := range in.Files {
		if shouldSkipKey(k, opts, filters) {
			continue
		}
		out.Files[k] = v
	}
	return out
}

func shouldSkipKey(key string, opts options, filters *compiledFilters) bool {
	if key == "" || key == "/" {
		return true
	}

	if keyExcludedByAllowRegex(key, filters) {
		return true
	}
	if keyExcludedByIgnoreRegex(key, filters) {
		return true
	}
	if decision, decided := keyDecisionByConfigDirRules(key, opts); decided {
		return decision
	}
	if isSpecialFolderNameToSkip(key) {
		return true
	}
	return keyExcludedByHiddenRules(key, opts)
}

func keyExcludedByAllowRegex(key string, filters *compiledFilters) bool {
	if filters == nil || len(filters.allow) == 0 {
		return false
	}
	for _, re := range filters.allow {
		if re.MatchString(key) {
			return false
		}
	}
	return true
}

func keyExcludedByIgnoreRegex(key string, filters *compiledFilters) bool {
	if filters == nil || len(filters.ignore) == 0 {
		return false
	}
	for _, re := range filters.ignore {
		if re.MatchString(key) {
			return true
		}
	}
	return false
}

func keyDecisionByConfigDirRules(key string, opts options) (bool, bool) {
	if opts.SyncConfigDir {
		if key == opts.ConfigDir+"/plugins/remotely-secure/data.json" {
			return true, true
		}
		if isInsideConfigDir(key, opts.ConfigDir) {
			return false, true
		}
		return false, false
	}

	if opts.SyncBookmarks {
		if key == opts.ConfigDir+"/bookmarks.json" {
			return false, true
		}
		if isInsideConfigDir(key, opts.ConfigDir) {
			return true, true
		}
		return false, false
	}

	if isInsideConfigDir(key, opts.ConfigDir) {
		return true, true
	}
	return false, false
}

func keyExcludedByHiddenRules(key string, opts options) bool {
	if isHiddenPath(key, true, false) {
		return true
	}
	if !opts.SyncUnderscore && isHiddenPath(key, false, true) {
		return true
	}
	return key == "_remotely-save-metadata-on-remote.json" ||
		key == "_remotely-save-metadata-on-remote.bin" ||
		key == "_remotely-secure-metadata-on-remote.json" ||
		key == "_remotely-secure-metadata-on-remote.bin"
}

func isInsideConfigDir(key string, configDir string) bool {
	return key == configDir || strings.HasPrefix(key, configDir+"/")
}

func isHiddenPath(item string, dot bool, underscore bool) bool {
	if !(dot || underscore) {
		return false
	}
	parts := strings.Split(path.Clean(strings.ReplaceAll(item, "\\", "/")), "/")
	for _, p := range parts {
		if p == "" || p == "." || p == ".." {
			continue
		}
		if dot && strings.HasPrefix(p, ".") {
			return true
		}
		if underscore && strings.HasPrefix(p, "_") {
			return true
		}
	}
	return false
}

func isSpecialFolderNameToSkip(x string) bool {
	special := []string{
		".git", ".github", ".gitlab", ".svn", "node_modules", ".DS_Store", "__MACOSX", "Icon\r", "desktop.ini", "Desktop.ini", "thumbs.db", "Thumbs.db",
	}
	parts := strings.Split(path.Clean(strings.ReplaceAll(x, "\\", "/")), "/")
	for _, p := range parts {
		for _, it := range special {
			if p == it {
				return true
			}
		}
	}
	base := path.Base(x)
	if strings.HasPrefix(base, "~$") {
		suffixes := []string{".doc", ".docx", ".ppt", ".pptx", ".xls", ".xlsx"}
		for _, s := range suffixes {
			if strings.HasSuffix(strings.ToLower(base), s) {
				return true
			}
		}
	}
	return false
}
