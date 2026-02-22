package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

func resolveSmartConflict(ctx context.Context, client *s3.Client, opts options, key string, localMap map[string]localMeta, remoteMap map[string]remoteMeta) error {
	local, lok := localMap[key]
	remote, rok := remoteMap[key]
	if !lok || !rok {
		return fmt.Errorf("smart conflict target disappeared: %s", key)
	}

	localBytes, err := os.ReadFile(local.FullPath)
	if err != nil {
		return fmt.Errorf("unable to read local file for smart conflict %s: %w", key, err)
	}
	rsp, err := client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(opts.Bucket),
		Key:    aws.String(remote.RemoteKey),
	})
	if err != nil {
		return fmt.Errorf("unable to read remote file for smart conflict %s: %w", key, err)
	}
	defer rsp.Body.Close()
	remoteBytes, err := io.ReadAll(rsp.Body)
	if err != nil {
		return fmt.Errorf("unable to read remote body for smart conflict %s: %w", key, err)
	}
	remoteBytes, err = decryptContent(opts, remoteBytes)
	if err != nil {
		return fmt.Errorf("unable to decrypt remote body for smart conflict %s: %w", key, err)
	}

	if bytes.Equal(localBytes, remoteBytes) {
		return nil
	}

	if isMergeableKey(key) {
		merged := buildConflictMerged(localBytes, remoteBytes)
		if err := os.WriteFile(local.FullPath, merged, 0o644); err != nil {
			return fmt.Errorf("unable to write merged conflict file %s: %w", key, err)
		}
		st, err := os.Stat(local.FullPath)
		if err != nil {
			return err
		}
		meta := localMeta{
			Key:      key,
			FullPath: local.FullPath,
			Size:     st.Size(),
			MTimeMS:  st.ModTime().UnixMilli(),
			CTimeMS:  st.ModTime().UnixMilli(),
		}
		return uploadFile(ctx, client, opts, meta, &remote)
	}

	conflictKey := conflictCopyName(key, "remote")
	conflictPath, err := localPathForKey(opts.LocalPath, conflictKey)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(conflictPath), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(conflictPath, remoteBytes, 0o644); err != nil {
		return fmt.Errorf("unable to write remote conflict copy %s: %w", conflictPath, err)
	}

	if err := uploadFile(ctx, client, opts, local, &remote); err != nil {
		return err
	}
	st, err := os.Stat(conflictPath)
	if err != nil {
		return err
	}
	conflictMeta := localMeta{
		Key:      conflictKey,
		FullPath: conflictPath,
		Size:     st.Size(),
		MTimeMS:  st.ModTime().UnixMilli(),
		CTimeMS:  st.ModTime().UnixMilli(),
	}
	if err := uploadFile(ctx, client, opts, conflictMeta, nil); err != nil {
		return err
	}
	return nil
}

func isMergeableKey(key string) bool {
	ext := strings.ToLower(path.Ext(key))
	if ext == ".md" || ext == ".txt" || ext == ".json" || ext == ".canvas" || ext == ".csv" || ext == ".yaml" || ext == ".yml" {
		return true
	}
	return false
}

func buildConflictMerged(local []byte, remote []byte) []byte {
	if bytes.Equal(local, remote) {
		return local
	}
	stamp := time.Now().Format(time.RFC3339)
	merged := "<<<<<<< LOCAL\n" + string(local) + "\n=======\n" + string(remote) + "\n>>>>>>> REMOTE " + stamp + "\n"
	return []byte(merged)
}

func conflictCopyName(key string, side string) string {
	ext := path.Ext(key)
	base := strings.TrimSuffix(key, ext)
	ts := time.Now().Format("20060102-150405")
	if ext == "" {
		return fmt.Sprintf("%s (%s-conflict %s)", base, side, ts)
	}
	return fmt.Sprintf("%s (%s-conflict %s)%s", base, side, ts, ext)
}
