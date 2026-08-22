module github.com/tasoint/certinv

go 1.25.0

// 依存は実装時に `go get` / `go mod tidy` で追加する。
// 想定している依存は CLAUDE.md を参照。

require (
	golang.org/x/net v0.58.0
	gopkg.in/yaml.v3 v3.0.1
)
