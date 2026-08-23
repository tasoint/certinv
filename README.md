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
- 設定時のみHTTPS GETを行い、ホストのHTTPステータスコードを記録
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

`serve` では Prometheus metrics を `/metrics` で提供します。`/ui` は
`Inventory` と `Sources & Targets` のタブに分かれており、`/` は `/ui` にリダイレクトします。
UIから手動scanの実行、イベント／アラートの確認済み化、apex／manual hostの登録内容管理を行えます。
インベントリ行の `Suppress` でホストを一覧と次回以降のscan対象から除外でき、
`Suppressed hosts` セクションの `Unsuppress` で復元できます。`Purge` はsuppressed hostの
host記録と証明書紐付けを完全削除しますが、証明書メタデータ本体は削除しません。
`All clear` は現在表示されている全ホストをまとめてsuppressし、`Purge all` は
suppressed hostの記録をまとめて完全削除します。
未確認の warn / alert イベントは `/ui` から確認済みにできます。証明書の発行・更新や
秘密鍵の操作は行いません。
`/ui/export.csv` では、UIのインベントリ一覧と同等の証明書メタデータをCSVで
ダウンロードできます。
`/ui` の `Run scan now` ボタンから、設定済みapexを対象にしたscanを即時実行できます。
横の `Include crt.name` は今回の手動scanだけに適用され、保存済み設定は変更しません。
既にscan実行中の場合は新しい実行は拒否されます。手動scan受付後は `/ui/scan/status` を
短時間ポーリングし、完了後にUIを再読み込みします。
UIではapex/manual hostをDB管理のオーバーレイとして追加・削除できます。DB管理の
manual hostはhostnameを固定したままportを編集できます。`config.yaml` の
`apexes` / `manual_hosts` は引き続き真のbaseとして扱われ、UIから変更・削除されません。
apexはcrt.name discovery有効時にCTログ上のサブドメインを自動発見するスコープであり、
manual hostはCTログに現れないホストを追加するためのものです。manual hostはapex discoveryの
絞り込み条件ではありません。
crt.nameの有効/無効とendpoint、zone fileの追加もDB管理のオーバーレイとして保存されます。
`Sources & Targets` タブでは、設定済みのcrt.name endpointに対して現在のapex一覧
（config + DB管理apex）から選んだ1つのapexでlookupを実行し、取得したサブドメイン候補を選択して
managed manual host（port 443）としてTargetsへ追加できます。このlookupは候補取得のみで、
DNS解決やTLS probeは行いません。Lookup nowは画面上のenabled/endpoint入力値をその場で使い、
保存は行いません。Save crt.nameで保存した設定は次回以降のscheduled scanやRun scan nowに使われ、
UI上にも現在の保存設定として表示されます。既にmanual hostとして登録済みのhostnameは候補から除外され、
候補一覧はホスト名で絞り込み、全選択／全解除できます。
zone fileのUI追加を使う場合は、`discovery.zone.allowed_dir` に許可ディレクトリを設定し、
UIからはその配下に実在するファイルだけを選択します。

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
