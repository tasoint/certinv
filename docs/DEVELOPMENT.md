# Development

Go 1.25 or later is required. Run these commands from the repository root.

## Installing the command

```sh
go install ./cmd/certinv
```

If `GOBIN` is unset, the binary is normally built in `GOPATH/bin` (typically
`~/go/bin`). Add that directory to `PATH`, or create a symlink in a directory
already on `PATH` such as `~/.local/bin`, to run `certinv scan`, `certinv serve`,
and `certinv check` directly.

## Verification

```sh
go test ./...
go vet ./...
gofmt -l .
```

`gofmt -l .` がファイルを出力した場合は、`gofmt -w` で整形してから再実行します。
