# certinv

Read this in English: [README.en.md](README.en.md)

**所有ドメインのTLS証明書インベントリツール**

Certificate Transparency 由来のサブドメイン一覧から到達可能なホストを絞り込み、
証明書を収集して有効期限を追跡し、期限切れ前に通知します。

> **開発中です。** 現在は `scan` / `serve` / `check` コマンドを実装しています。
> `serve` では Prometheus exporter とインベントリ確認・限定的な運用操作を行う Web UI を提供します。
> 詳細は [docs/status.md](docs/status.md) と [docs/design.md](docs/design.md) を参照してください。
> 開発者向けの検証手順は [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md) を参照してください。
> 設定項目の詳細は [docs/CONFIGURATION.md](docs/CONFIGURATION.md) を参照してください。

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

### インストール

次のコマンドで `certinv` をインストールします。

```sh
go install ./cmd/certinv
```

`GOBIN` を設定していない場合は通常 `GOPATH/bin`（一般的には `~/go/bin`）に
ビルドされます。そのディレクトリを `PATH` に追加するか、`~/.local/bin` など
すでに `PATH` が通っているディレクトリへシンボリックリンクを作成すると、
`certinv scan` / `certinv serve` / `certinv check` をそのまま実行できます。
ソースから直接実行する場合は、各コマンドの前に `go run ./cmd/certinv` を付けます。

### クイックスタート

初めて使う場合は、次の手順で設定から常駐運用まで進められます。

1. 設定ファイルの例をコピーします。

   ```sh
   cp config.example.yaml config.yaml
   ```

2. `config.yaml` の `apexes` を、自分が所有・管理するドメインに書き換えます。
   `apexes` に登録したドメインだけが処理対象です。
   `example.com` はCertificate Transparencyログ上で世界中のテスト・プレースホルダー証明書に
   非常に多く使われているため、書き換えずにcrt.name discoveryを有効にしてscanすると、
   数千件規模の無関係なホストが発見される可能性があります。必ず自分が所有・管理する
   実際のドメインに書き換えてからscanしてください。

3. 単発スキャンを実行します。

   ```sh
   certinv scan --config config.yaml
   ```

4. 常駐モードを起動します。定期スキャンに加えて Web UI と Prometheus metrics を提供します。

   ```sh
   certinv serve --config config.yaml
   ```

5. ブラウザで http://localhost:9101/ui を開き、インベントリを確認します。

### コマンド別の使い方

単発 `scan`:

```sh
certinv scan --config config.yaml
```

常駐 `serve`:

```sh
certinv serve --config config.yaml
```

`serve` では Prometheus metrics を `/metrics` で提供します。`/ui` は
`Inventory` と `Sources & Targets` のタブに分かれており、`/` は `/ui` にリダイレクトします。

### Inventory タブ

- UIはOS/ブラウザのダークモード設定に自動追従します。ヘッダーの `Light / Dark` ボタンで手動切り替えもできます。
- 手動scanを実行し、イベント／アラートを確認済みにできます。手動scanとscheduled scanはいずれも保存済みのdiscovery設定を使い、実行ごとの一時上書きは行いません。
- `Run scan now` は設定済みapexを対象に即時実行します。実行中は新しい実行を拒否し、Scanning表示とボタン無効化を行います。60秒経過時は手動リロードを案内します。
- 現在crt.name discovery対象として有効なapex一覧を表示します。
- インベントリ行の `Suppress` でホストを一覧と次回以降のscan対象から除外し、`Suppressed hosts` の `Unsuppress` で復元できます。
- `All clear` は表示中の全ホストをまとめてsuppressします。
- `Purge` / `Purge all` はsuppressed hostのhost記録と証明書紐付けを完全削除しますが、証明書メタデータ本体は削除しません。
- `/ui/export.csv` でインベントリ一覧と同等の証明書メタデータをCSVダウンロードできます。Inventoryテーブルはホスト名検索、証明書状態、鍵アルゴリズム、チェーン完全性、ページサイズで表示を絞り込めます。Cert Stateごとの件数サマリーをクリックすると、その状態で絞り込めます。
- Inventory、CSV、Prometheus metricsには証明書メタデータから推定した自動更新区分（`likely_auto` / `likely_manual` / `unknown`）も表示されます。UIでは読みやすいラベルと判定理由のツールチップで表示し、CSV/metricsでは外部連携用の値を維持します。
- 証明書の発行・更新や秘密鍵の操作は行いません。

### Sources & Targets タブ

- apex/manual hostをDB管理のオーバーレイとして追加・削除できます。DB管理のmanual hostはhostnameを固定したままportを編集できます。
- `config.yaml` の `apexes` / `manual_hosts` は真のbaseとして扱われ、UIから変更・削除されません。
- apexはcrt.name discovery有効時にCTログ上のサブドメインを自動発見するスコープで、manual hostはCTログに現れないホストを追加するためのものです。manual hostはapex discoveryの絞り込み条件ではありません。
- crt.nameの有効/無効とendpoint、apexごとのcrt.name有効/無効、zone fileの追加をDB管理のオーバーレイとして保存できます。crt.nameの全体設定はマスタースイッチで、OFFの場合はapexごとの設定に関わらず全体が無効です。apexごとの設定はデフォルトONです。
- 設定済みのcrt.name endpointに対し、現在のapex一覧（config + DB管理apex）から選んだ1つのapexでlookupを実行できます。候補を選択してmanaged manual host（port 443）としてTargetsへ追加できます。
- lookupは候補取得のみで、DNS解決やTLS probeは行いません。Lookup nowは画面上のenabled/endpoint入力値をその場で使い、保存は行いません。Save crt.nameで保存した全体設定は次回以降のscheduled scanやRun scan nowに使われ、UI上にも表示されます。
- 既にmanual hostとして登録済みのhostnameは候補から除外され、候補一覧はホスト名で絞り込み、全選択／全解除できます。
- zone fileのUI追加では、`discovery.zone.allowed_dir` 配下に実在するファイルだけを選択します。

### 認証

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

### Grafanaダッシュボード

Prometheusで`/metrics`を取り込む場合にインポートできるサンプルを
[dashboards/certinv.json](dashboards/certinv.json)として配布しています。
certinv自体はGrafanaを実行・管理せず、このJSONはインポート用テンプレートです。

単発FQDNチェック:

```sh
certinv check --config config.example.yaml www.example.com
certinv check --config config.example.yaml --port 8443 app.example.com
```

`check` で指定できるFQDNは設定ファイルの `apexes` 配下だけです。apex外の任意ドメインは
拒否されます。`check` は読み取り専用で、証明書メタデータを標準出力に表示します。
DBへの永続化や設定変更は行いません。

## やらないこと

- 証明書の発行・更新（certbot / lego / cert-manager をお使いください）
- 秘密鍵の取り扱い。UIの運用操作を含め、秘密鍵を読み込む・生成する・保存することはありません

## ライセンス

MIT License ([LICENSE](LICENSE))
