# certinv

**所有ドメインのTLS証明書インベントリツール**

Certificate Transparency 由来のサブドメイン一覧から到達可能なホストを絞り込み、
証明書を収集して有効期限を追跡し、期限切れ前に通知します。

> **開発中です。** `master` では `scan` と通知イベント管理まで動作します。
> `serve` / Prometheus exporter / Web UI / zone file discovery は未マージPRで実装中です。
> 詳細は [docs/status.md](docs/status.md) と [docs/design.md](docs/design.md) を参照してください。

## 背景

CA/Browser Forum の Ballot SC-081v3 により、公開TLS証明書の最大有効期間は
2026年3月に200日、2027年3月に100日、2029年3月に47日へと段階的に短縮されます。

更新サイクルが年1回から年8回になると、まず問題になるのは更新作業そのものではなく
**「自組織にどれだけの証明書が存在するのか把握できていない」** ことです。
certinv はその棚卸しを自動化します。

## スコープ

certinv は **自分が所有・管理するドメイン** の棚卸しに使うツールです。

- 処理対象は設定ファイルに明示的に登録した apex ドメインのみです
- 任意のドメインをコマンドライン引数だけで指定することはできません
- プローブの並列度とレートは保守的なデフォルト値になっています

第三者のドメインに対する調査目的での利用は想定していません。

## 現在の主な機能

- 設定ファイルに登録された apex ドメインだけを処理
- discovery source:
  - `crtname`: crt.name API から候補ホスト名を取得
  - `manual`: 設定ファイルの手動登録ホストを取得
  - `zone`: DNS zone file から取得（PR #3）
- DNS 解決による生存確認
- TLS probe と証明書メタデータ収集
- SQLite への host / certificate / event 保存
- 残存率ベースの warn / alert / expired / misconfigured 判定
- Slack / Webhook 通知（状態遷移時のみ）
- `serve` モード、Prometheus `/metrics`、読み取り専用 Web UI（PR #2 / #5）

## 使い方

Go 1.25 以降が必要です。

```sh
go test ./...
go vet ./...
gofmt -l .
```

単発 scan:

```sh
go run ./cmd/certinv scan --config config.example.yaml
```

常駐モード（PR #2）:

```sh
go run ./cmd/certinv serve --config config.example.yaml
```

`serve` では Prometheus metrics を `/metrics` で提供します。Web UI 実装ブランチでは
`/ui` で読み取り専用のインベントリ一覧を表示し、`/` は `/ui` にリダイレクトします。

## やらないこと

- 証明書の発行・更新（certbot / lego / cert-manager をお使いください）
- 秘密鍵の取り扱い。certinv は読み取り専用です

## ライセンス

TODO: ライセンスを選択してください（Apache-2.0 または MIT を推奨）
