# Development

## Verification

Go 1.25 以降を使用し、リポジトリのルートで次の確認を実行します。

```sh
go test ./...
go vet ./...
gofmt -l .
```

`gofmt -l .` がファイルを出力した場合は、`gofmt -w` で整形してから再実行します。
