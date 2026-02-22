package main

import (
	"strings"
	"testing"
)

func TestEncryptDecryptContentRoundTrip(t *testing.T) {
	t.Parallel()

	opts := options{Password: "somepassword", Encryption: "openssl-base64"}
	plain := []byte("hello remotely-save")

	enc, err := encryptContent(opts, plain)
	if err != nil {
		t.Fatalf("encrypt content: %v", err)
	}
	if string(enc) == string(plain) {
		t.Fatalf("expected encrypted content to differ from plain content")
	}

	dec, err := decryptContent(opts, enc)
	if err != nil {
		t.Fatalf("decrypt content: %v", err)
	}
	if string(dec) != string(plain) {
		t.Fatalf("roundtrip mismatch: got %q want %q", string(dec), string(plain))
	}
}

func TestEncodeDecodeRemoteKeyRoundTrip(t *testing.T) {
	t.Parallel()

	opts := options{Password: "somepassword", Encryption: "openssl-base64"}
	key := "folder/name.md"

	enc, err := encodeRemoteKey(opts, key)
	if err != nil {
		t.Fatalf("encode key: %v", err)
	}
	if !strings.HasPrefix(enc, "U2FsdGVkX") {
		t.Fatalf("expected openssl encoded key prefix, got: %s", enc)
	}

	dec, err := decodeRemoteKey(opts, enc)
	if err != nil {
		t.Fatalf("decode key: %v", err)
	}
	if dec != key {
		t.Fatalf("roundtrip key mismatch: got %q want %q", dec, key)
	}
}

func TestRcloneEncodeDecodeAndContentRoundTrip(t *testing.T) {
	t.Parallel()

	opts := options{Password: "somepassword", Encryption: "rclone-base64"}
	if err := prepareEncryption(&opts); err != nil {
		t.Fatalf("prepare encryption: %v", err)
	}

	key := "folder/name.md"
	encKey, err := encodeRemoteKey(opts, key)
	if err != nil {
		t.Fatalf("encode key: %v", err)
	}
	if encKey == key {
		t.Fatalf("expected encrypted key to differ")
	}
	if strings.HasSuffix(encKey, ".bin") {
		t.Fatalf("expected remotely-save compatible key without .bin suffix, got: %s", encKey)
	}
	decKey, err := decodeRemoteKey(opts, encKey)
	if err != nil {
		t.Fatalf("decode key: %v", err)
	}
	if decKey != key {
		t.Fatalf("key mismatch: got %q want %q", decKey, key)
	}

	plain := []byte("hello rclone crypt")
	encContent, err := encryptContent(opts, plain)
	if err != nil {
		t.Fatalf("encrypt content: %v", err)
	}
	if string(encContent) == string(plain) {
		t.Fatalf("expected encrypted content to differ")
	}
	decContent, err := decryptContent(opts, encContent)
	if err != nil {
		t.Fatalf("decrypt content: %v", err)
	}
	if string(decContent) != string(plain) {
		t.Fatalf("content mismatch: got %q want %q", string(decContent), string(plain))
	}
}

func TestRemotelySyncEncodeDecodeAndContentRoundTrip(t *testing.T) {
	t.Parallel()

	opts := options{Password: "somepassword", Encryption: "remotely-sync-base64url"}

	key := "folder/name.md"
	encKey, err := encodeRemoteKey(opts, key)
	if err != nil {
		t.Fatalf("encode key: %v", err)
	}
	if encKey == key {
		t.Fatalf("expected encrypted key to differ")
	}
	decKey, err := decodeRemoteKey(opts, encKey)
	if err != nil {
		t.Fatalf("decode key: %v", err)
	}
	if decKey != key {
		t.Fatalf("key mismatch: got %q want %q", decKey, key)
	}

	plain := []byte("hello remotely-sync")
	encContent, err := encryptContent(opts, plain)
	if err != nil {
		t.Fatalf("encrypt content: %v", err)
	}
	if string(encContent) == string(plain) {
		t.Fatalf("expected encrypted content to differ")
	}
	decContent, err := decryptContent(opts, encContent)
	if err != nil {
		t.Fatalf("decrypt content: %v", err)
	}
	if string(decContent) != string(plain) {
		t.Fatalf("content mismatch: got %q want %q", string(decContent), string(plain))
	}
}

func TestDecodeRemoteKeyWithoutPasswordRejectsEncryptedName(t *testing.T) {
	t.Parallel()

	_, err := decodeRemoteKey(options{}, "U2FsdGVkX19whatever")
	if err == nil {
		t.Fatalf("expected error for encrypted-looking key with empty password")
	}
}

func TestDetectEncryptionMethodFromKeys(t *testing.T) {
	t.Parallel()

	opts := options{Password: "somepassword", Encryption: "rclone-base64"}
	if err := prepareEncryption(&opts); err != nil {
		t.Fatalf("prepare rclone cipher: %v", err)
	}
	rcloneKey, err := encodeRemoteKey(opts, "folder/file.md")
	if err != nil {
		t.Fatalf("encode rclone key: %v", err)
	}

	method, err := detectEncryptionMethodFromKeys("somepassword", []string{rcloneKey})
	if err != nil {
		t.Fatalf("detect method: %v", err)
	}
	if method != "rclone-base64" {
		t.Fatalf("unexpected method: %s", method)
	}
}

func TestDetectEncryptionMethodFromKeysIgnoresMetadataMarkerFile(t *testing.T) {
	t.Parallel()

	opts := options{Password: "somepassword", Encryption: "rclone-base64"}
	if err := prepareEncryption(&opts); err != nil {
		t.Fatalf("prepare rclone cipher: %v", err)
	}
	rcloneKey, err := encodeRemoteKey(opts, "folder/file.md")
	if err != nil {
		t.Fatalf("encode rclone key: %v", err)
	}

	method, err := detectEncryptionMethodFromKeys("somepassword", []string{"_remotely-save-metadata-on-remote.json", "_remotely-secure-metadata-on-remote.json", rcloneKey})
	if err != nil {
		t.Fatalf("detect method: %v", err)
	}
	if method != "rclone-base64" {
		t.Fatalf("unexpected method: %s", method)
	}
}

func TestRcloneCipherConfigUsesDotBinSuffix(t *testing.T) {
	t.Parallel()

	cfg, err := rcloneCipherConfig("somepassword")
	if err != nil {
		t.Fatalf("build rclone config: %v", err)
	}
	if cfg["suffix"] != ".bin" {
		t.Fatalf("unexpected suffix: got %q want %q", cfg["suffix"], ".bin")
	}
}
