# Contributing

## Local dev

```bash
make tidy
make fmt
make test
make build
make help
```

## Guidelines

- Keep behavior compatible with existing S3 data produced by Remotely Save workflows.
- Prefer explicit flags over hidden defaults for destructive behavior.
- Add tests when introducing sync decision logic changes.
