# certinv

**所有ドメインのTLS証明書インベントリツール**

Certificate Transparency 由来のサブドメイン一覧から到達可能なホストを絞り込み、
証明書を収集して有効期限を追跡し、期限切れ前に通知します。

> **開発中です。** 現在は `scan` / `serve` / `check` コマンドを実装しています。
> `serve` では Prometheus exporter とインベントリ確認・限定的な運用操作を行う Web UI を提供します。
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
  - `zone`: DNS zone file から取得
- DNS 解決による生存確認
- TLS probe と証明書メタデータ収集
- SQLite への host / certificate / event 保存
- 残存率ベースの warn / alert / expired / misconfigured 判定
- Slack / Webhook 通知（状態遷移時のみ）
- `serve` モード、Prometheus `/metrics`、インベントリ確認・限定的な運用操作を行う Web UI

## 使い方

Go 1.25 以降が必要です。

### クイックスタート

初めて使う場合は、次の手順で設定から常駐運用まで進められます。

1. 設定ファイルの例をコピーします。

   ```sh
   cp config.example.yaml config.yaml
   ```

2. `config.yaml` の `apexes` を、自分が所有・管理するドメインに書き換えます。
   `apexes` に登録したドメインだけが処理対象です。

3. 単発スキャンを実行します。

   ```sh
   go run ./cmd/certinv scan --config config.yaml
   ```

4. 常駐モードを起動します。定期スキャンに加えて Web UI と Prometheus metrics を提供します。

   ```sh
   go run ./cmd/certinv serve --config config.yaml
   ```

5. ブラウザで http://localhost:9101/ui を開き、インベントリを確認します。

### コマンド別の使い方

開発時の確認には、次のコマンドを使います。

```sh
go test ./...
go vet ./...
gofmt -l .
```

単発 `scan`:

```sh
go run ./cmd/certinv scan --config config.yaml
```

常駐 `serve`:

```sh
go run ./cmd/certinv serve --config config.yaml
```

`serve` では Prometheus metrics を `/metrics` で提供します。`/ui` でインベントリ一覧と
限定的な運用操作を提供し、`/` は `/ui` にリダイレクトします。UIから手動scanの実行、
イベント／アラートの確認済み化、apex／manual hostの登録内容管理を行える設計です。
`/ui/export.csv` では、UIのインベントリ一覧と同等の証明書メタデータをCSVで
ダウンロードできます。
`/ui` の `Run scan now` ボタンから、設定済みapexを対象にしたscanを即時実行できます。
既にscan実行中の場合は新しい実行は拒否されます。

`exporter.basic_auth.username` と `exporter.basic_auth.password` の両方を設定すると、
`/metrics` と `/ui` はBasic認証で保護されます。両方空の場合は認証なしで動作し、
既存設定との後方互換を維持します。

```yaml
exporter:
  listen: :9101
  basic_auth:
    username: operator
    password: change-me
```

`serve` のHTTPサーバを外部公開する場合は、TLS終端とアクセス制御を行うリバースプロキシ
配下に置くことを推奨します。

単発FQDNチェック:

```sh
go run ./cmd/certinv check --config config.example.yaml www.example.com
go run ./cmd/certinv check --config config.example.yaml --port 8443 app.example.com
```

`check` で指定できるFQDNは設定ファイルの `apexes` 配下だけです。apex外の任意ドメインは
拒否されます。`check` は読み取り専用で、証明書メタデータを標準出力に表示します。
DBへの永続化や設定変更は行いません。

## やらないこと

- 証明書の発行・更新（certbot / lego / cert-manager をお使いください）
- 秘密鍵の取り扱い。UIの運用操作を含め、秘密鍵を読み込む・生成する・保存することはありません

## ライセンス

TODO: ライセンスを選択してください（Apache-2.0 または MIT を推奨）
