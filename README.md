# certinv

**所有ドメインのTLS証明書インベントリツール**

Certificate Transparency 由来のサブドメイン一覧から到達可能なホストを絞り込み、
証明書を収集して有効期限を追跡し、期限切れ前に通知します。

> **開発中です。** 現在は `scan` / `serve` / `check` コマンドを実装しています。
> 設計は [docs/design.md](docs/design.md) を参照してください。

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

## 使い方

設定例をコピーして、所有・管理している apex ドメインだけを登録します。

```sh
cp config.example.yaml config.yaml
```

棚卸しスキャンを1回実行します。

```sh
certinv scan --config config.yaml
```

定期スキャンと Prometheus exporter を起動します。

```sh
certinv serve --config config.yaml
```

単発でFQDNのTLS証明書を確認します。指定できるFQDNは `config.yaml` の
`apexes` 配下だけです。apex外の任意ドメインは拒否されます。

```sh
certinv check --config config.yaml www.example.com
certinv check --config config.yaml --port 8443 app.example.com
```

`check` は読み取り専用で、証明書メタデータを標準出力に表示します。
DBへの永続化や設定変更は行いません。

## やらないこと

- 証明書の発行・更新（certbot / lego / cert-manager をお使いください）
- 秘密鍵の取り扱い。certinv は読み取り専用です

## ライセンス

TODO: ライセンスを選択してください（Apache-2.0 または MIT を推奨）
