package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"mime"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

func walkLocalFiles(opts options, ignoreRel string) (map[string]localMeta, error) {
	out := map[string]localMeta{}

	err := filepath.WalkDir(opts.LocalPath, func(fullPath string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}

		rel, err := filepath.Rel(opts.LocalPath, fullPath)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if rel == "." {
			return nil
		}

		if d.IsDir() {
			info, err := d.Info()
			if err != nil {
				return err
			}
			dirKey := rel
			if !strings.HasSuffix(dirKey, "/") {
				dirKey += "/"
			}
			mtime := info.ModTime().UnixMilli()
			out[dirKey] = localMeta{
				Key:      dirKey,
				FullPath: fullPath,
				Size:     0,
				MTimeMS:  mtime,
				CTimeMS:  mtime,
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		if rel == ignoreRel {
			return nil
		}

		info, err := d.Info()
		if err != nil {
			return err
		}

		mtime := info.ModTime().UnixMilli()
		out[rel] = localMeta{
			Key:      rel,
			FullPath: fullPath,
			Size:     localSizeForSync(opts, info.Size()),
			MTimeMS:  mtime,
			CTimeMS:  mtime,
		}
		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("unable to walk local files: %w", err)
	}
	return out, nil
}

func listRemoteFiles(ctx context.Context, client *s3.Client, opts options) (map[string]remoteMeta, error) {
	out := map[string]remoteMeta{}
	decodedCount := 0
	decodeFailureCount := 0
	decodeFailureSamples := make([]string, 0, 3)
	input := &s3.ListObjectsV2Input{Bucket: aws.String(opts.Bucket)}
	if opts.Prefix != "" {
		input.Prefix = aws.String(opts.Prefix)
	}

	paginator := s3.NewListObjectsV2Paginator(client, input)
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("unable to list remote files: %w", err)
		}
		for _, item := range page.Contents {
			if item.Key == nil {
				continue
			}
			fullKey := *item.Key
			if !strings.HasPrefix(fullKey, opts.Prefix) {
				continue
			}

			rawRel := strings.TrimPrefix(fullKey, opts.Prefix)
			decodedRel, err := decodeRemoteKey(opts, rawRel)
			if err != nil {
				if !encryptionEnabled(opts) {
					return nil, fmt.Errorf("unable to decode remote key %q: %w", fullKey, err)
				}
				decodeFailureCount++
				if len(decodeFailureSamples) < cap(decodeFailureSamples) {
					decodeFailureSamples = append(decodeFailureSamples, fullKey)
				}
				continue
			}
			rel, err := sanitizeRelativeSyncKeyPreservingDirMarker(decodedRel)
			if err != nil {
				if !encryptionEnabled(opts) {
					return nil, fmt.Errorf("unsafe decoded remote key %q from %q: %w", decodedRel, fullKey, err)
				}
				decodeFailureCount++
				if len(decodeFailureSamples) < cap(decodeFailureSamples) {
					decodeFailureSamples = append(decodeFailureSamples, fullKey)
				}
				continue
			}
			decodedCount++
			mtime := int64(0)
			if item.LastModified != nil {
				mtime = item.LastModified.UnixMilli()
			}
			if opts.AccurateMTime {
				head, err := client.HeadObject(ctx, &s3.HeadObjectInput{
					Bucket: aws.String(opts.Bucket),
					Key:    aws.String(fullKey),
				})
				if err != nil {
					fmt.Fprintf(os.Stderr, "warning: unable to head object for mtime %s: %v\n", fullKey, err)
				} else if head.Metadata != nil {
					if mRaw, ok := head.Metadata["modification_time"]; ok {
						if mParsed, pErr := parseMetadataTime(mRaw); pErr == nil {
							mtime = mParsed
						}
					} else if mRaw, ok := head.Metadata["mtime"]; ok {
						if mParsed, pErr := parseMetadataTime(mRaw); pErr == nil {
							mtime = mParsed
						}
					} else if mRaw, ok2 := head.Metadata["MTime"]; ok2 {
						if mParsed, pErr := parseMetadataTime(mRaw); pErr == nil {
							mtime = mParsed
						}
					}
				}
			}
			size := int64(0)
			if item.Size != nil {
				size = *item.Size
			}

			prev, exists := out[rel]
			if exists && prev.MTimeMS > mtime {
				continue
			}
			out[rel] = remoteMeta{
				Key:       rel,
				RemoteKey: fullKey,
				Size:      size,
				MTimeMS:   mtime,
			}
		}
	}
	if err := validateRemoteDecodeResult(opts, decodedCount, decodeFailureCount, decodeFailureSamples); err != nil {
		return nil, err
	}

	return out, nil
}

func validateRemoteDecodeResult(opts options, decodedCount int, decodeFailureCount int, decodeFailureSamples []string) error {
	if !encryptionEnabled(opts) || decodeFailureCount == 0 {
		return nil
	}
	if decodedCount == 0 {
		return fmt.Errorf("unable to decode any remote keys with encryption method %q; verify password/method or set a dedicated prefix (sample keys: %s)", opts.Encryption, strings.Join(decodeFailureSamples, ", "))
	}
	fmt.Fprintf(os.Stderr, "warning: skipped %d remote keys that could not be decoded with %s (samples: %s)\n", decodeFailureCount, opts.Encryption, strings.Join(decodeFailureSamples, ", "))
	return nil
}

func isRemoteDirectoryMarker(decodedKey string) bool {
	return strings.HasSuffix(decodedKey, "/")
}

func runPlan(
	ctx context.Context,
	client *s3.Client,
	opts options,
	actions []plannedAction,
	localMap map[string]localMeta,
	remoteMap map[string]remoteMeta,
) (map[string]int, error) {
	counters := map[string]int{
		"push":           0,
		"pull":           0,
		"delete_local":   0,
		"delete_remote":  0,
		"smart_conflict": 0,
		"noop":           0,
	}

	for _, step := range actions {
		counters[step.Action] += 1

		if step.Action == "noop" {
			continue
		}

		fmt.Printf("%-12s %s\n", step.Action, step.Key)
		if opts.DryRun {
			continue
		}

		switch step.Action {
		case "push":
			local, ok := localMap[step.Key]
			if !ok {
				return nil, fmt.Errorf("push target disappeared: %s", step.Key)
			}
			var existing *remoteMeta
			if remote, ok := remoteMap[step.Key]; ok {
				existing = &remote
			}
			if err := uploadFile(ctx, client, opts, local, existing); err != nil {
				return nil, err
			}
		case "pull":
			remote, ok := remoteMap[step.Key]
			if !ok {
				return nil, fmt.Errorf("pull target disappeared: %s", step.Key)
			}
			if err := downloadFile(ctx, client, opts, remote); err != nil {
				return nil, err
			}
		case "delete_local":
			fullPath, err := localPathForKey(opts.LocalPath, step.Key)
			if err != nil {
				return nil, err
			}
			if strings.HasSuffix(step.Key, "/") {
				if err := os.RemoveAll(fullPath); err != nil && !errors.Is(err, os.ErrNotExist) {
					return nil, fmt.Errorf("unable to delete local directory %s: %w", fullPath, err)
				}
			} else {
				if err := os.Remove(fullPath); err != nil && !errors.Is(err, os.ErrNotExist) {
					return nil, fmt.Errorf("unable to delete local file %s: %w", fullPath, err)
				}
			}
		case "delete_remote":
			remote, ok := remoteMap[step.Key]
			if !ok {
				return nil, fmt.Errorf("remote key disappeared before delete: %s", step.Key)
			}
			if strings.HasSuffix(step.Key, "/") && !encryptionEnabled(opts) {
				prefix := remote.RemoteKey
				listIn := &s3.ListObjectsV2Input{Bucket: aws.String(opts.Bucket), Prefix: aws.String(prefix)}
				p := s3.NewListObjectsV2Paginator(client, listIn)
				for p.HasMorePages() {
					page, pErr := p.NextPage(ctx)
					if pErr != nil {
						return nil, fmt.Errorf("unable to list remote directory %s for delete: %w", prefix, pErr)
					}
					for _, item := range page.Contents {
						if item.Key == nil {
							continue
						}
						_, delErr := client.DeleteObject(ctx, &s3.DeleteObjectInput{
							Bucket: aws.String(opts.Bucket),
							Key:    item.Key,
						})
						if delErr != nil {
							return nil, fmt.Errorf("unable to delete remote file %s: %w", *item.Key, delErr)
						}
					}
				}
			} else {
				remoteKey := remote.RemoteKey
				_, err := client.DeleteObject(ctx, &s3.DeleteObjectInput{
					Bucket: aws.String(opts.Bucket),
					Key:    aws.String(remoteKey),
				})
				if err != nil {
					return nil, fmt.Errorf("unable to delete remote file %s: %w", remoteKey, err)
				}
			}
		case "smart_conflict":
			if err := resolveSmartConflict(ctx, client, opts, step.Key, localMap, remoteMap); err != nil {
				return nil, err
			}
		default:
			return nil, fmt.Errorf("unknown action: %s", step.Action)
		}
	}

	return counters, nil
}

func uploadFile(ctx context.Context, client *s3.Client, opts options, local localMeta, existingRemote *remoteMeta) error {
	if strings.HasSuffix(local.Key, "/") {
		remoteKey := ""
		if existingRemote != nil {
			remoteKey = existingRemote.RemoteKey
		} else {
			encKey, err := encodeRemoteKey(opts, local.Key)
			if err != nil {
				return err
			}
			remoteKey = opts.Prefix + encKey
		}
		_, err := client.PutObject(ctx, &s3.PutObjectInput{
			Bucket:      aws.String(opts.Bucket),
			Key:         aws.String(remoteKey),
			Body:        bytes.NewReader(nil),
			ContentType: aws.String("application/octet-stream"),
		})
		if err != nil {
			return fmt.Errorf("unable to upload folder marker %s: %w", local.Key, err)
		}
		return nil
	}

	content, err := os.ReadFile(local.FullPath)
	if err != nil {
		return fmt.Errorf("unable to read local file %s: %w", local.FullPath, err)
	}
	body, err := encryptContent(opts, content)
	if err != nil {
		return fmt.Errorf("unable to encrypt file %s: %w", local.Key, err)
	}

	contentType := mime.TypeByExtension(path.Ext(local.Key))
	if contentType == "" || encryptionEnabled(opts) {
		contentType = "application/octet-stream"
	}

	remoteKey := ""
	if existingRemote != nil {
		remoteKey = existingRemote.RemoteKey
	} else {
		encKey, err := encodeRemoteKey(opts, local.Key)
		if err != nil {
			return err
		}
		remoteKey = opts.Prefix + encKey
	}
	putIn := &s3.PutObjectInput{
		Bucket:      aws.String(opts.Bucket),
		Key:         aws.String(remoteKey),
		Body:        bytes.NewReader(body),
		ContentType: aws.String(contentType),
	}
	if !opts.DisableS3Meta {
		putIn.Metadata = map[string]string{
			"modification_time": fmt.Sprintf("%d", local.MTimeMS),
			"mtime":             fmt.Sprintf("%.3f", float64(local.MTimeMS)/1000),
			"ctime":             fmt.Sprintf("%.3f", float64(local.CTimeMS)/1000),
		}
	}
	_, err = client.PutObject(ctx, putIn)
	if err != nil {
		return fmt.Errorf("unable to upload %s: %w", local.Key, err)
	}
	return nil
}

func downloadFile(ctx context.Context, client *s3.Client, opts options, remote remoteMeta) error {
	fullPath, err := localPathForKey(opts.LocalPath, remote.Key)
	if err != nil {
		return err
	}
	if strings.HasSuffix(remote.Key, "/") {
		if err := os.MkdirAll(fullPath, 0o755); err != nil {
			return fmt.Errorf("unable to create local directory %s: %w", fullPath, err)
		}
		ts := time.Now()
		if remote.MTimeMS > 0 {
			ts = time.UnixMilli(remote.MTimeMS)
		}
		if err := os.Chtimes(fullPath, ts, ts); err != nil {
			return fmt.Errorf("unable to set mtime for %s: %w", fullPath, err)
		}
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(fullPath), 0o755); err != nil {
		return fmt.Errorf("unable to create directory for %s: %w", fullPath, err)
	}

	rsp, err := client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(opts.Bucket),
		Key:    aws.String(remote.RemoteKey),
	})
	if err != nil {
		return fmt.Errorf("unable to download %s: %w", remote.Key, err)
	}
	defer rsp.Body.Close()
	data, err := io.ReadAll(rsp.Body)
	if err != nil {
		return fmt.Errorf("unable to read remote body for %s: %w", remote.Key, err)
	}
	plain, err := decryptContent(opts, data)
	if err != nil {
		return fmt.Errorf("unable to decrypt downloaded data for %s: %w", remote.Key, err)
	}

	f, err := os.OpenFile(fullPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("unable to open local file for download %s: %w", fullPath, err)
	}
	defer f.Close()

	if _, err := f.Write(plain); err != nil {
		return fmt.Errorf("unable to write downloaded data for %s: %w", remote.Key, err)
	}

	ts := time.Now()
	if remote.MTimeMS > 0 {
		ts = time.UnixMilli(remote.MTimeMS)
	}
	if err := os.Chtimes(fullPath, ts, ts); err != nil {
		return fmt.Errorf("unable to set mtime for %s: %w", fullPath, err)
	}
	return nil
}

func parseMetadataTime(raw string) (int64, error) {
	v := strings.TrimSpace(raw)
	if v == "" {
		return 0, fmt.Errorf("empty")
	}
	var f float64
	_, err := fmt.Sscanf(v, "%f", &f)
	if err != nil {
		return 0, err
	}
	if f > 1000000000000 {
		return int64(f), nil
	}
	return int64(f * 1000), nil
}

func sanitizeRelativeSyncKey(raw string) (string, error) {
	key := strings.ReplaceAll(strings.TrimSpace(raw), "\\", "/")
	if key == "" {
		return "", fmt.Errorf("empty key")
	}
	if strings.HasPrefix(key, "/") {
		return "", fmt.Errorf("absolute paths are not allowed")
	}

	cleaned := path.Clean(key)
	if cleaned == "." || cleaned == ".." || strings.HasPrefix(cleaned, "../") {
		return "", fmt.Errorf("path traversal is not allowed")
	}
	if cleaned != key {
		return "", fmt.Errorf("key must be normalized")
	}

	for _, segment := range strings.Split(cleaned, "/") {
		if segment == "" || segment == "." || segment == ".." {
			return "", fmt.Errorf("invalid path segment")
		}
	}

	return cleaned, nil
}

func sanitizeRelativeSyncKeyPreservingDirMarker(raw string) (string, error) {
	key := strings.ReplaceAll(strings.TrimSpace(raw), "\\", "/")
	isDir := strings.HasSuffix(key, "/")
	if isDir {
		key = strings.TrimSuffix(key, "/")
	}

	safe, err := sanitizeRelativeSyncKey(key)
	if err != nil {
		return "", err
	}
	if isDir {
		return safe + "/", nil
	}
	return safe, nil
}

func localPathForKey(localRoot string, key string) (string, error) {
	pathKey := strings.TrimSuffix(key, "/")
	cleanKey, err := sanitizeRelativeSyncKey(pathKey)
	if err != nil {
		return "", fmt.Errorf("unsafe local key %q: %w", key, err)
	}

	fullPath := filepath.Join(localRoot, filepath.FromSlash(cleanKey))
	relToRoot, err := filepath.Rel(localRoot, fullPath)
	if err != nil {
		return "", fmt.Errorf("unable to resolve local path for %q: %w", key, err)
	}
	relToRoot = filepath.Clean(relToRoot)
	if relToRoot == ".." || strings.HasPrefix(relToRoot, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("local path escapes root for key %q", key)
	}

	return fullPath, nil
}
