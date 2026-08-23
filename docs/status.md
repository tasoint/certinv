# certinv 実装状況

最終確認日: 2026-08-23

この文書は、`master` と現在オープン中の PR の関係を整理するための開発メモである。
PR がマージされたら、該当行は更新または削除する。

## ブランチと PR

| PR | ブランチ | base | 内容 | 状態 |
|---|---|---|---|---|
| #1 | `work/github-actions-setup` | `master` | GitHub Actions / staticcheck 設定修正 | Copilot担当。ここでは触らない |
| #2 | `work/v0.3-serve` | `master` | `serve` モード、scheduler、Prometheus exporter | open |
| #3 | `work/v0.4-zonefile` | `master` | DNS zone file discovery、自動化推定レポート | open |
| #4 | `docs/web-ui-design` | `master` | Web UI 設計追記 | open |
| #5 | `work/v0.6-web-ui` | `work/v0.3-serve` | 読み取り専用 Web UI | open。PR #2 に依存する stacked PR |

## `master` で利用できる機能

- `scan` コマンド
- `crtname` / `manual` discovery source
- DNS 解決による生存確認
- TLS probe と証明書メタデータ収集
- SQLite 保存
- 残存率ベースの評価
- events と状態遷移管理
- Slack / Webhook 通知
- 通知失敗時の retry
- renewal 検出

## 未マージ PR の機能

PR #2:

- `serve` コマンド
- scan scheduler
- Prometheus `/metrics`

PR #3:

- `discovery.sources: [zone]`
- `discovery.zone.files`
- zone file の `$ORIGIN` と A / AAAA / CNAME owner name 取り込み
- 自動化推定: `likely_auto` / `likely_manual` / `unknown`

PR #5:

- `serve` の HTTP サーバに `/ui` を追加
- `/` から `/ui` に redirect
- host / certificate / state / issuer / SAN / last probe などの読み取り専用一覧
- Go 標準ライブラリの `net/http` と `html/template` のみを使用

## 検証コマンド

```sh
go test ./...
go vet ./...
gofmt -l .
```

このリポジトリは秘密鍵を扱わない。テスト用証明書が必要な場合も、秘密鍵フィクスチャは
コミットせず、テスト実行時に動的生成する。
