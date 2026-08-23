# certinv 実装状況

最終確認日: 2026-08-23

この文書は、`master` の実装状況を整理するための開発メモである。

## ブランチと PR

現時点でこの文書に追跡中の未マージPRはない。

## `master` で利用できる機能

- `scan` コマンド
- `crtname` / `manual` / `zone` discovery source
- DNS 解決による生存確認
- TLS probe と証明書メタデータ収集
- SQLite 保存
- 残存率ベースの評価
- events と状態遷移管理
- Slack / Webhook 通知
- 通知失敗時の retry
- renewal 検出
- 自動化推定レポート
- `check` コマンドによる単発FQDN証明書確認（apexスコープ内のみ）
- `serve` コマンド
- scan scheduler
- Prometheus `/metrics`
- `serve` HTTPサーバの任意Basic認証
- `/ui` のインベントリ表示
- `/ui/export.csv` によるインベントリCSV export
- `/ui/scan` によるUIからの手動scan即時実行（二重起動防止あり）
- UIからのDB管理apex/manual hostオーバーレイ追加・削除（config.yaml由来は変更しない）

## 実装済みの追加機能

- UIに未確認の warn / alert イベント一覧を表示
- Basic認証で保護されたPOSTエンドポイントからイベントを acknowledged に変更
- 確認状態は `events.acknowledged_at` / `acknowledged_by` に保存し、証明書情報は変更しない

## 検証コマンド

```sh
go test ./...
go vet ./...
gofmt -l .
```

このリポジトリは秘密鍵を扱わない。テスト用証明書が必要な場合も、秘密鍵フィクスチャは
コミットせず、テスト実行時に動的生成する。
