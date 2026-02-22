package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"strings"
	"unicode/utf8"

	rclonecrypt "github.com/rclone/rclone/backend/crypt"
	"github.com/rclone/rclone/fs/config/configmap"
	"github.com/rclone/rclone/fs/config/obscure"
	"golang.org/x/crypto/pbkdf2"
)

const (
	opensslMagicPrefix = "Salted__"
	opensslRounds      = 20000
	remotelySyncRounds = 20000
	remotelySyncSalt   = 16
	remotelySyncNonce  = 12
)

func encryptionEnabled(opts options) bool {
	return opts.Password != "" && opts.Encryption != ""
}

type rcloneCipher interface {
	EncryptFileName(in string) string
	DecryptFileName(in string) (string, error)
	EncryptData(in io.Reader) (io.Reader, error)
	DecryptData(rc io.ReadCloser) (io.ReadCloser, error)
	EncryptedSize(size int64) int64
}

func prepareEncryption(opts *options) error {
	if !encryptionEnabled(*opts) {
		return nil
	}
	if opts.Encryption == "auto" {
		return fmt.Errorf("--encryption-method auto must be resolved before encryption is prepared")
	}
	if opts.Encryption != "rclone-base64" {
		return nil
	}
	c, err := newRcloneCipher(opts.Password)
	if err != nil {
		return err
	}
	opts.rcloneCipher = c
	return nil
}

func newRcloneCipher(password string) (*rclonecrypt.Cipher, error) {
	m, err := rcloneCipherConfig(password)
	if err != nil {
		return nil, err
	}
	c, err := rclonecrypt.NewCipher(m)
	if err != nil {
		return nil, fmt.Errorf("unable to initialize rclone cipher: %w", err)
	}
	return c, nil
}

func rcloneCipherConfig(password string) (configmap.Simple, error) {
	obscuredPassword, err := obscure.Obscure(password)
	if err != nil {
		return nil, fmt.Errorf("unable to prepare rclone password: %w", err)
	}
	m := configmap.Simple{
		"filename_encryption":       "standard",
		"directory_name_encryption": "true",
		"filename_encoding":         "base64",
		"suffix":                    ".bin",
		"password":                  obscuredPassword,
	}
	return m, nil
}

func detectEncryptionMethodFromKeys(password string, rawKeys []string) (string, error) {
	if len(rawKeys) == 0 {
		return "", fmt.Errorf("no remote keys to detect encryption method")
	}

	candidates := []string{"remotely-sync-base64url", "rclone-base64", "openssl-base64"}
	matches := make([]string, 0, len(candidates))
	for _, method := range candidates {
		testOpts := options{Password: password, Encryption: method}
		if err := prepareEncryption(&testOpts); err != nil {
			continue
		}
		success := 0
		for _, rawKey := range rawKeys {
			if shouldSkipEncryptionProbeKey(rawKey) {
				continue
			}
			decoded, err := decodeRemoteKey(testOpts, rawKey)
			if err != nil {
				continue
			}
			if _, err := sanitizeRelativeSyncKey(decoded); err != nil {
				continue
			}
			success++
		}
		if success > 0 {
			matches = append(matches, method)
		}
	}

	if len(matches) == 1 {
		return matches[0], nil
	}
	if len(matches) > 1 {
		return "rclone-base64", nil
	}
	return "", fmt.Errorf("unable to auto-detect encryption method from remote keys; verify password and whether remote data is encrypted")
}

func shouldSkipEncryptionProbeKey(rawKey string) bool {
	if strings.HasPrefix(rawKey, "_remotely-save-metadata-on-remote.") ||
		strings.HasPrefix(rawKey, "_remotely-secure-metadata-on-remote.") {
		return true
	}
	return false
}

func isLikelyOpenSSLEncryptedName(name string) bool {
	return strings.HasPrefix(name, "U2FsdGVkX")
}

func localSizeForSync(opts options, plainSize int64) int64 {
	if !encryptionEnabled(opts) {
		return plainSize
	}
	if opts.Encryption == "rclone-base64" {
		return opts.rcloneCipher.EncryptedSize(plainSize)
	}
	if opts.Encryption == "remotely-sync-base64url" {
		if plainSize < 0 {
			return plainSize
		}
		return plainSize + remotelySyncSalt + remotelySyncNonce + 16
	}
	return opensslEncryptedSizeFromPlain(plainSize)
}

func encodeRemoteKey(opts options, plainKey string) (string, error) {
	if !encryptionEnabled(opts) {
		return plainKey, nil
	}
	if opts.Encryption == "rclone-base64" {
		enc := opts.rcloneCipher.EncryptFileName(plainKey)
		return strings.TrimSuffix(enc, ".bin"), nil
	}
	if opts.Encryption == "remotely-sync-base64url" {
		enc, err := encryptRemotelySyncBytes([]byte(plainKey), opts.Password)
		if err != nil {
			return "", fmt.Errorf("unable to encrypt key %q: %w", plainKey, err)
		}
		return base64.RawURLEncoding.EncodeToString(enc), nil
	}
	if opts.Encryption != "openssl-base64" {
		return "", fmt.Errorf("unsupported encryption method: %s", opts.Encryption)
	}
	enc, err := encryptOpenSSLBytes([]byte(plainKey), opts.Password)
	if err != nil {
		return "", fmt.Errorf("unable to encrypt key %q: %w", plainKey, err)
	}
	return base64.RawURLEncoding.EncodeToString(enc), nil
}

func decodeRemoteKey(opts options, encKey string) (string, error) {
	if !encryptionEnabled(opts) {
		if isLikelyOpenSSLEncryptedName(encKey) {
			return "", fmt.Errorf("remote appears encrypted but --encryption-password is empty")
		}
		return encKey, nil
	}
	if opts.Encryption == "rclone-base64" {
		dec, err := opts.rcloneCipher.DecryptFileName(encKey)
		if err != nil && !strings.HasSuffix(encKey, ".bin") {
			dec, err = opts.rcloneCipher.DecryptFileName(encKey + ".bin")
		}
		if err != nil {
			return "", fmt.Errorf("unable to decrypt key (password or method mismatch)")
		}
		if strings.TrimSpace(dec) == "" {
			return "", fmt.Errorf("decrypted key is empty")
		}
		return dec, nil
	}
	if opts.Encryption == "remotely-sync-base64url" {
		raw, err := base64.RawURLEncoding.DecodeString(encKey)
		if err != nil {
			return "", fmt.Errorf("invalid encrypted key encoding")
		}
		dec, err := decryptRemotelySyncBytes(raw, opts.Password)
		if err != nil {
			return "", fmt.Errorf("unable to decrypt key (password or method mismatch)")
		}
		if !utf8.Valid(dec) {
			return "", fmt.Errorf("decrypted key is not valid UTF-8")
		}
		plain := string(dec)
		if strings.TrimSpace(plain) == "" {
			return "", fmt.Errorf("decrypted key is empty")
		}
		return plain, nil
	}
	if opts.Encryption != "openssl-base64" {
		return "", fmt.Errorf("unsupported encryption method: %s", opts.Encryption)
	}
	raw, err := base64.RawURLEncoding.DecodeString(encKey)
	if err != nil {
		return "", fmt.Errorf("invalid encrypted key encoding")
	}
	dec, err := decryptOpenSSLBytes(raw, opts.Password)
	if err != nil {
		return "", fmt.Errorf("unable to decrypt key (password or method mismatch)")
	}
	if !utf8.Valid(dec) {
		return "", fmt.Errorf("decrypted key is not valid UTF-8")
	}
	plain := string(dec)
	if strings.TrimSpace(plain) == "" {
		return "", fmt.Errorf("decrypted key is empty")
	}
	return plain, nil
}

func encryptContent(opts options, plain []byte) ([]byte, error) {
	if !encryptionEnabled(opts) {
		return plain, nil
	}
	if opts.Encryption == "rclone-base64" {
		reader, err := opts.rcloneCipher.EncryptData(bytes.NewReader(plain))
		if err != nil {
			return nil, fmt.Errorf("unable to encrypt content: %w", err)
		}
		return io.ReadAll(reader)
	}
	if opts.Encryption == "remotely-sync-base64url" {
		return encryptRemotelySyncBytes(plain, opts.Password)
	}
	if opts.Encryption != "openssl-base64" {
		return nil, fmt.Errorf("unsupported encryption method: %s", opts.Encryption)
	}
	return encryptOpenSSLBytes(plain, opts.Password)
}

func decryptContent(opts options, enc []byte) ([]byte, error) {
	if !encryptionEnabled(opts) {
		return enc, nil
	}
	if opts.Encryption == "rclone-base64" {
		reader, err := opts.rcloneCipher.DecryptData(io.NopCloser(bytes.NewReader(enc)))
		if err != nil {
			return nil, fmt.Errorf("unable to decrypt content (password or method mismatch): %w", err)
		}
		defer reader.Close()
		return io.ReadAll(reader)
	}
	if opts.Encryption == "remotely-sync-base64url" {
		plain, err := decryptRemotelySyncBytes(enc, opts.Password)
		if err != nil {
			return nil, fmt.Errorf("unable to decrypt content (password or method mismatch): %w", err)
		}
		return plain, nil
	}
	if opts.Encryption != "openssl-base64" {
		return nil, fmt.Errorf("unsupported encryption method: %s", opts.Encryption)
	}
	plain, err := decryptOpenSSLBytes(enc, opts.Password)
	if err != nil {
		return nil, fmt.Errorf("unable to decrypt content (password or method mismatch): %w", err)
	}
	return plain, nil
}

func encryptOpenSSLBytes(plain []byte, password string) ([]byte, error) {
	salt := make([]byte, 8)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, err
	}
	key, iv := deriveKeyIV(password, salt)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	padded := pkcs7Pad(plain, aes.BlockSize)
	ciphertext := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ciphertext, padded)

	out := make([]byte, 0, len(opensslMagicPrefix)+len(salt)+len(ciphertext))
	out = append(out, []byte(opensslMagicPrefix)...)
	out = append(out, salt...)
	out = append(out, ciphertext...)
	return out, nil
}

func decryptOpenSSLBytes(enc []byte, password string) ([]byte, error) {
	if len(enc) < 16 {
		return nil, fmt.Errorf("encrypted payload too short")
	}
	if !bytes.Equal(enc[:8], []byte(opensslMagicPrefix)) {
		return nil, fmt.Errorf("missing openssl magic prefix")
	}

	salt := enc[8:16]
	ciphertext := enc[16:]
	if len(ciphertext) == 0 || len(ciphertext)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("invalid ciphertext size")
	}

	key, iv := deriveKeyIV(password, salt)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	plainPadded := make([]byte, len(ciphertext))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(plainPadded, ciphertext)

	plain, err := pkcs7Unpad(plainPadded, aes.BlockSize)
	if err != nil {
		return nil, err
	}
	return plain, nil
}

func deriveKeyIV(password string, salt []byte) ([]byte, []byte) {
	derived := pbkdf2.Key([]byte(password), salt, opensslRounds, 48, sha256.New)
	key := make([]byte, 32)
	iv := make([]byte, 16)
	copy(key, derived[:32])
	copy(iv, derived[32:48])
	return key, iv
}

func pkcs7Pad(in []byte, blockSize int) []byte {
	padLen := blockSize - (len(in) % blockSize)
	if padLen == 0 {
		padLen = blockSize
	}
	out := make([]byte, len(in)+padLen)
	copy(out, in)
	for i := len(in); i < len(out); i++ {
		out[i] = byte(padLen)
	}
	return out
}

func pkcs7Unpad(in []byte, blockSize int) ([]byte, error) {
	if len(in) == 0 || len(in)%blockSize != 0 {
		return nil, fmt.Errorf("invalid padded data length")
	}
	padLen := int(in[len(in)-1])
	if padLen <= 0 || padLen > blockSize || padLen > len(in) {
		return nil, fmt.Errorf("invalid padding")
	}
	for i := len(in) - padLen; i < len(in); i++ {
		if int(in[i]) != padLen {
			return nil, fmt.Errorf("invalid padding")
		}
	}
	return in[:len(in)-padLen], nil
}

func opensslEncryptedSizeFromPlain(plain int64) int64 {
	if plain < 0 {
		return plain
	}
	return ((plain/16)+1)*16 + 16
}

func encryptRemotelySyncBytes(plain []byte, password string) ([]byte, error) {
	salt := make([]byte, remotelySyncSalt)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, err
	}
	nonce := make([]byte, remotelySyncNonce)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	key := pbkdf2.Key([]byte(password), salt, remotelySyncRounds, 32, sha256.New)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	ciphertext := gcm.Seal(nil, nonce, plain, nil)
	out := make([]byte, 0, len(salt)+len(nonce)+len(ciphertext))
	out = append(out, salt...)
	out = append(out, nonce...)
	out = append(out, ciphertext...)
	return out, nil
}

func decryptRemotelySyncBytes(enc []byte, password string) ([]byte, error) {
	if len(enc) < remotelySyncSalt+remotelySyncNonce+16 {
		return nil, fmt.Errorf("encrypted payload too short")
	}
	salt := enc[:remotelySyncSalt]
	nonce := enc[remotelySyncSalt : remotelySyncSalt+remotelySyncNonce]
	ciphertext := enc[remotelySyncSalt+remotelySyncNonce:]
	key := pbkdf2.Key([]byte(password), salt, remotelySyncRounds, 32, sha256.New)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	plain, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}
	return plain, nil
}
