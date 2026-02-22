# s3sync-go

`s3sync-go` is a standalone CLI to sync a local folder with an S3-compatible bucket.

It is a Go reimplementation of the sync model used by the TypeScript Obsidian plugin **Remotely Sync** (forked from Remotely Save), built for cases where you want Obsidian-compatible file sync **without running Obsidian itself**.

My use case is giving an agentic program (OpenClaw in this case) direct access to an Obsidian vault through S3 while preserving the same file format and key layout.

## Why this project exists

- Reuse the same bucket data format as Remotely Sync / Obsidian workflows.
- Run sync as a plain CLI in servers, WSL, CI, containers, or headless machines.
- Keep vault data plain by default (optional E2E encryption supported).

## Compatibility scope

This tool intentionally keeps S3 object layout compatible with common Remotely Sync S3 usage:

- plain object keys under the configured prefix (or encrypted keys when E2E is enabled)
- object metadata field `modification_time` on upload (plus legacy `mtime`/`ctime` for interoperability)
- plugin-like filtering and direction modes

This project is **not affiliated** with the Remotely Save maintainers; it is an independent reimplementation for CLI usage.

## Architecture

The codebase is split by responsibility to keep sync behavior easier to reason about and test:

- `main.go`: CLI entrypoint, flag parsing/validation, high-level sync flow.
- `filters.go`: path filtering rules (`allow`, `ignore`, config-dir and hidden-file behavior).
- `state.go`: state file persistence and snapshot helpers.
- `plan.go`: action planning and safety protection threshold logic.
- `s3io.go`: local file walking, S3 listing, transfer operations, and plan execution.
- `conflict.go`: smart-conflict merge/copy behavior.

## Build

```bash
make tidy
make build
```

## Quick start

```bash
./s3sync-go sync \
  --local /path/to/vault \
  --endpoint s3.us-east-1.amazonaws.com \
  --region us-east-1 \
  --bucket your-bucket \
  --access-key YOUR_ACCESS_KEY \
  --secret-key YOUR_SECRET_KEY \
  --prefix your-prefix/ \
  --dry-run
```

Remove `--dry-run` to apply changes.

## Interactive setup and saved defaults

If required sync options are missing and you run from a terminal, `s3sync-go` starts an interactive setup prompt.

- First-time run with no CLI flags: it asks for full sync settings.
- It saves settings to your OS config directory (for example on Linux: `~/.config/s3sync-go/config.json`).
- Later runs automatically reuse saved settings when flags are not explicitly provided.
- Any explicit CLI flags still override saved values.

Config file permissions are restricted to the current user. The file contains credentials and (if set) encryption password, so protect your machine account accordingly.

## Config management commands

You can manage saved defaults directly:

- `s3sync-go config show`: show saved config (secrets masked)
- `s3sync-go config show --json`: show saved config as JSON
- `s3sync-go config show --show-secrets`: show unmasked secrets
- `s3sync-go config edit`: interactive edit and save
- `s3sync-go config reset`: remove saved config (asks confirmation)
- `s3sync-go config reset --yes`: remove saved config without prompt
- `s3sync-go config path`: print config file location
- `s3sync-go config export --file ./s3sync-config.json`: export config with masked secrets
- `s3sync-go config export --file ./s3sync-config.json --include-secrets`: export full config (contains credentials)
- `s3sync-go config import --file ./s3sync-config.json`: import config (requires unmasked secrets)

## Check encryption/password

Use this command to verify which encryption method matches your remote with a given password:

```bash
./s3sync-go check-encryption \
  --endpoint s3.us-east-1.amazonaws.com \
  --region us-east-1 \
  --bucket your-bucket \
  --access-key YOUR_ACCESS_KEY \
  --secret-key YOUR_SECRET_KEY \
  --prefix your-prefix/ \
  --encryption-password "your-password" \
  --encryption-method auto \
  --json
```

`auto` will probe remote keys and report whether the password matches `remotely-sync-base64url`, `rclone-base64`, or `openssl-base64`.

`check-encryption` exit codes:

- `0`: match (or remote empty)
- `2`: password/method mismatch
- `1`: other errors (network, auth, invalid flags, etc.)

## Sync modes

- `bidirectional`
- `incremental_pull_only`
- `incremental_push_only`
- `incremental_pull_and_delete_only`
- `incremental_push_and_delete_only`

## Conflict strategies

Use `--conflict-action` in bidirectional mode:

- `keep_newer` (default): prefer the side with newer mtime.
- `keep_larger`: prefer the side with larger size.
- `smart_conflict`: for text-like files, write conflict markers and sync merged result; for non-text files, keep local file and store a remote conflict copy with a suffixed name.

## Important flags

- `--dry-run`: print planned actions only
- `--state-file`: override local sync state path
- `--force-path-style`: for S3-compatible providers that need path style
- `--ignore-path` / `--allow-path`: repeatable regex filters
- `--sync-config-dir`, `--sync-bookmarks`, `--sync-underscore-items`: Obsidian-like path behavior
- `--accurate-mtime`: read `MTime` via `HeadObject`
- `--disable-s3-metadata-sync`: do not write S3 object metadata (`modification_time`, legacy `mtime`/`ctime`)
- `--protect-modify-percentage`: blocks plans when risky actions exceed threshold (`-1` disables)
- `--encryption-password`: enables end-to-end encryption
- `--encryption-method`: `openssl-base64`, `rclone-base64`, `remotely-sync-base64url`, or `auto`

`--protect-modify-percentage` now measures risky operations (deletes, smart conflicts, and overwrite-style push/pull where both sides already exist). Initial one-way adds are not counted as risky.

## Environment variables

- `RS_LOCAL_PATH`
- `RS_S3_ENDPOINT`
- `RS_S3_REGION`
- `RS_S3_BUCKET`
- `RS_S3_ACCESS_KEY`
- `RS_S3_SECRET_KEY`
- `RS_S3_PREFIX`
- `RS_ENCRYPTION_PASSWORD`
- `RS_ENCRYPTION_METHOD`

## End-to-end encryption

When `--encryption-password` is set, `s3sync-go` encrypts both object keys and file content before upload, and decrypts on download.

- `openssl-base64`: compatible with Remotely Save OpenSSL mode (`Salted__` + AES-256-CBC + PBKDF2-SHA256 20k rounds)
- `rclone-base64`: compatible with Remotely Save rclone mode using rclone crypt naming/content format with base64 filename encoding
- `remotely-sync-base64url`: compatible with Remotely Sync / Remotely Secure format (AES-256-GCM + PBKDF2-SHA256 20k; object keys encoded as base64url)
- `auto`: probes existing remote keys and picks the matching method (defaults to `rclone-base64` when remote is empty)
- If your remote is encrypted, you must set the same password to sync

Important: changing password or encryption method requires manually clearing/rebuilding the remote vault data to avoid conflicts.

## Safety notes

- Start with `--dry-run`.
- Use a dedicated test prefix before touching production data.
- Rotate credentials if they are ever exposed in logs or chat history.

## Compatibility matrix runner

You can run an interoperability matrix against a real bucket:

```bash
chmod +x ./scripts/run-compat-matrix.sh
RS_S3_ENDPOINT=... \
RS_S3_REGION=... \
RS_S3_BUCKET=... \
RS_S3_ACCESS_KEY=... \
RS_S3_SECRET_KEY=... \
./scripts/run-compat-matrix.sh
```

Optional envs:

- `S3SYNC_MATRIX_PREFIX`: remote prefix to isolate test data
- `S3SYNC_MATRIX_PASSWORD`: password for encrypted scenario

## License

Apache-2.0 (see `LICENSE`).
