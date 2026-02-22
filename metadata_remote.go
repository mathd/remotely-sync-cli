package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

const (
	secureMetadataFileJSON = "_remotely-secure-metadata-on-remote.json"
	secureMetadataFileBIN  = "_remotely-secure-metadata-on-remote.bin"
	saveMetadataFileJSON   = "_remotely-save-metadata-on-remote.json"
	saveMetadataFileBIN    = "_remotely-save-metadata-on-remote.bin"

	defaultMetadataReadme  = "Do NOT edit or delete the file manually. This file is for the plugin remotely-sync to store some necessary meta data on the remote services. Its content is slightly obfuscated."
	defaultMetadataVersion = "20220220"
)

type remoteDeletionRecord struct {
	Key        string `json:"key"`
	ActionWhen int64  `json:"actionWhen"`
}

type remoteMetadataPayload struct {
	Version       string                 `json:"version,omitempty"`
	GeneratedWhen int64                  `json:"generatedWhen,omitempty"`
	Deletions     []remoteDeletionRecord `json:"deletions"`
}

type remoteMetadataEnvelope struct {
	Readme string `json:"readme"`
	D      string `json:"d"`
}

func readRemoteDeletionMetadata(ctx context.Context, client *s3.Client, opts options, remoteMapRaw map[string]remoteMeta) (map[string]int64, error) {
	candidates := findRemoteMetadataCandidates(remoteMapRaw)
	if len(candidates) == 0 {
		return map[string]int64{}, nil
	}

	latest := candidates[0]
	for _, c := range candidates[1:] {
		if c.MTimeMS > latest.MTimeMS {
			latest = c
		}
	}

	b, err := readRemoteObjectBytes(ctx, client, opts, latest.RemoteKey)
	if err != nil {
		return nil, fmt.Errorf("unable to read remote metadata file: %w", err)
	}

	payload, err := deserializeRemoteMetadataPayload(b)
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: unable to parse remote metadata %s: %v\n", latest.Key, err)
		return map[string]int64{}, nil
	}

	out := map[string]int64{}
	for _, d := range payload.Deletions {
		if strings.TrimSpace(d.Key) == "" || d.ActionWhen <= 0 {
			continue
		}
		if strings.HasSuffix(d.Key, "/") {
			continue
		}
		if _, err := sanitizeRelativeSyncKey(d.Key); err != nil {
			continue
		}
		if prev, ok := out[d.Key]; !ok || d.ActionWhen > prev {
			out[d.Key] = d.ActionWhen
		}
	}
	return out, nil
}

func syncRemoteDeletionMetadata(
	ctx context.Context,
	client *s3.Client,
	opts options,
	actions []plannedAction,
	current map[string]int64,
	remoteMapRaw map[string]remoteMeta,
	localBefore map[string]localMeta,
	remoteBefore map[string]remoteMeta,
	prev syncState,
) error {
	updated := evolveDeletionMapFromActions(actions, current, localBefore, remoteBefore, prev)
	candidates := findRemoteMetadataCandidates(remoteMapRaw)

	keepRemoteKey := ""
	if len(candidates) > 0 {
		latest := candidates[0]
		for _, c := range candidates[1:] {
			if c.MTimeMS > latest.MTimeMS {
				latest = c
			}
		}
		keepRemoteKey = latest.RemoteKey
	}

	if keepRemoteKey == "" {
		encKey, err := encodeRemoteKey(opts, secureMetadataFileJSON)
		if err != nil {
			return fmt.Errorf("unable to encode remote metadata key: %w", err)
		}
		keepRemoteKey = opts.Prefix + encKey
	}

	body, err := serializeRemoteMetadataPayload(updated)
	if err != nil {
		return err
	}
	body, err = encryptContent(opts, body)
	if err != nil {
		return fmt.Errorf("unable to encrypt remote metadata payload: %w", err)
	}

	contentType := "application/json"
	if encryptionEnabled(opts) {
		contentType = "application/octet-stream"
	}

	_, err = client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:      aws.String(opts.Bucket),
		Key:         aws.String(keepRemoteKey),
		Body:        bytes.NewReader(body),
		ContentType: aws.String(contentType),
	})
	if err != nil {
		return fmt.Errorf("unable to upload remote metadata file: %w", err)
	}

	for _, c := range candidates {
		if c.RemoteKey == keepRemoteKey {
			continue
		}
		_, delErr := client.DeleteObject(ctx, &s3.DeleteObjectInput{
			Bucket: aws.String(opts.Bucket),
			Key:    aws.String(c.RemoteKey),
		})
		if delErr != nil {
			fmt.Fprintf(os.Stderr, "warning: unable to remove duplicate metadata object %s: %v\n", c.RemoteKey, delErr)
		}
	}

	return nil
}

func evolveDeletionMapFromActions(
	actions []plannedAction,
	current map[string]int64,
	localBefore map[string]localMeta,
	remoteBefore map[string]remoteMeta,
	prev syncState,
) map[string]int64 {
	now := time.Now().UnixMilli()
	out := map[string]int64{}
	for k, v := range current {
		out[k] = v
	}
	for _, a := range actions {
		actionWhen := computeDeletionActionWhen(now, a.Key, localBefore, remoteBefore, prev)
		switch a.Action {
		case "delete_remote":
			out[a.Key] = actionWhen
		case "delete_local":
			if _, ok := out[a.Key]; !ok {
				out[a.Key] = actionWhen
			}
		case "push", "pull", "smart_conflict":
			delete(out, a.Key)
		}
	}
	return out
}

func computeDeletionActionWhen(
	now int64,
	key string,
	localBefore map[string]localMeta,
	remoteBefore map[string]remoteMeta,
	prev syncState,
) int64 {
	maxSeen := now
	if l, ok := localBefore[key]; ok && l.MTimeMS > maxSeen {
		maxSeen = l.MTimeMS
	}
	if r, ok := remoteBefore[key]; ok && r.MTimeMS > maxSeen {
		maxSeen = r.MTimeMS
	}
	if p, ok := prev.Files[key]; ok {
		if p.Local != nil && p.Local.MTimeMS > maxSeen {
			maxSeen = p.Local.MTimeMS
		}
		if p.Remote != nil && p.Remote.MTimeMS > maxSeen {
			maxSeen = p.Remote.MTimeMS
		}
	}
	return maxSeen + 1
}

func serializeRemoteMetadataPayload(deletions map[string]int64) ([]byte, error) {
	recs := make([]remoteDeletionRecord, 0, len(deletions))
	keys := make([]string, 0, len(deletions))
	for k := range deletions {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		recs = append(recs, remoteDeletionRecord{Key: k, ActionWhen: deletions[k]})
	}

	p := remoteMetadataPayload{
		Version:       defaultMetadataVersion,
		GeneratedWhen: time.Now().UnixMilli(),
		Deletions:     recs,
	}
	pRaw, err := json.Marshal(p)
	if err != nil {
		return nil, fmt.Errorf("unable to marshal metadata payload: %w", err)
	}

	env := remoteMetadataEnvelope{
		Readme: defaultMetadataReadme,
		D:      reverseText(base64.RawURLEncoding.EncodeToString(pRaw)),
	}
	b, err := json.MarshalIndent(env, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("unable to marshal metadata envelope: %w", err)
	}
	return b, nil
}

func deserializeRemoteMetadataPayload(b []byte) (remoteMetadataPayload, error) {
	var env remoteMetadataEnvelope
	if err := json.Unmarshal(b, &env); err != nil {
		return remoteMetadataPayload{}, err
	}
	if strings.TrimSpace(env.D) == "" {
		return remoteMetadataPayload{}, fmt.Errorf("invalid metadata envelope: empty d")
	}
	raw, err := base64.RawURLEncoding.DecodeString(reverseText(env.D))
	if err != nil {
		return remoteMetadataPayload{}, err
	}
	var p remoteMetadataPayload
	if err := json.Unmarshal(raw, &p); err != nil {
		return remoteMetadataPayload{}, err
	}
	if p.Deletions == nil {
		p.Deletions = []remoteDeletionRecord{}
	}
	return p, nil
}

func findRemoteMetadataCandidates(remoteMapRaw map[string]remoteMeta) []remoteMeta {
	out := make([]remoteMeta, 0, 2)
	for _, v := range remoteMapRaw {
		switch v.Key {
		case secureMetadataFileJSON, secureMetadataFileBIN, saveMetadataFileJSON, saveMetadataFileBIN:
			out = append(out, v)
		}
	}
	return out
}

func readRemoteObjectBytes(ctx context.Context, client *s3.Client, opts options, remoteKey string) ([]byte, error) {
	rsp, err := client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(opts.Bucket),
		Key:    aws.String(remoteKey),
	})
	if err != nil {
		return nil, err
	}
	defer rsp.Body.Close()
	b, err := io.ReadAll(rsp.Body)
	if err != nil {
		return nil, err
	}
	return decryptContent(opts, b)
}

func reverseText(s string) string {
	r := []rune(s)
	for i, j := 0, len(r)-1; i < j; i, j = i+1, j-1 {
		r[i], r[j] = r[j], r[i]
	}
	return string(r)
}
