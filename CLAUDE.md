# certinv

TLS証明書のインベントリツール。Certificate Transparency 由来のサブドメイン一覧から
到達可能なホストを絞り込み、証明書を収集して有効期限を追跡し、期限切れ前に通知する。

背景と全体設計は `docs/design.md` を参照すること。実装前に必ず読むこと。

---

## 絶対ルール

以下は例外なく守る。違反しそうな実装になったら、実装を進めずに指摘すること。

1. **秘密鍵を扱わない。** 証明書処理は読み取り専用であり、秘密鍵を読み込む・生成する・保存する
   コードパスを作らない。TLSクライアントとして接続する際もクライアント証明書は使わない。
   UIにはスキャン実行、イベント確認、apex／manual host管理の操作を追加するが、証明書や秘密鍵は変更しない。
2. **証明書の生DER/PEMをログに出さない。** SAN・CN・発行者・有効期限などのメタデータは
   出力してよいが、証明書そのものをログやエラーメッセージに含めない。
3. **暗号処理を自前実装しない。** `crypto/x509`, `crypto/tls` の標準ライブラリのみを使う。
   独自のASN.1パーサや署名検証を書かない。
4. **テストフィクスチャに秘密鍵をコミットしない。** テスト用の証明書は
   `crypto/x509.CreateCertificate` でテスト実行時に動的生成する。
   CI に `BEGIN ... PRIVATE KEY` を検出するガードがあるため、コミットすると落ちる。
5. **スコープ外のドメインを処理しない。** 設定ファイルの `apexes` に登録されていない
   ドメインに対しては discovery も probe も実行しない。任意ドメインを引数で渡せる
   インターフェースを作らない（`certinv check` の単一ホスト確認を除く）。
   apex登録自体は所有権を技術的に検証していないため抜け道はあるが、この制約は意図しない
   第三者ドメインの調査を防ぐ歯止めとして維持している。ロックを外す提案があれば、まず
   GitHub issueで議論してから判断すること。

## アーキテクチャ

```
cmd/certinv/          エントリポイント。CLIパースのみ。ロジックを置かない
internal/config/      設定ファイルのロードと検証
internal/discover/    ホスト名の発見。Source インターフェースの実装群
  ├── crtname/        crt.name API クライアント
  └── manual/         設定ファイルからの手動登録
internal/resolve/     DNS解決による生存確認
internal/probe/       TLSハンドシェイクと証明書取得
internal/cert/        証明書のパース・フィンガープリント・検証ロジック
internal/store/       Store インターフェースと SQLite 実装
internal/evaluate/    閾値判定とイベント生成
internal/notify/      Notifier インターフェースと Slack / Webhook 実装
internal/exporter/    Prometheus メトリクス
internal/core/        パイプライン全体のオーケストレーション
```

`cmd` と `internal/core` の関係が重要。`scan`（単発実行）と `serve`（常駐）は
どちらも `core.Run(ctx, cfg)` を呼ぶだけにする。`serve` はそこにスケジューラと
HTTPサーバを被せる。ロジックを二重に持たない。

## インターフェース設計

以下は最初から interface として定義する。後付けが困難なため。

- `discover.Source` — ホスト名の発見元。crt.name / manual / 将来のゾーンファイル
- `store.Store` — 永続化。SQLite から始めるが実装を差し替えられるように
- `notify.Notifier` — 通知先。Slack / Webhook / 将来のPagerDuty等
- `probe.Prober` — TLS接続。テストでモック可能にするため

外部通信を行うコードは必ずインターフェース越しにする。テストで実ネットワークに
出る実装を書かない。

## 設計上の重要な判断（変更する場合は必ず相談すること）

- **インベントリの主キーは証明書であってホスト名ではない。**
  SAN証明書1枚が数十ホストに紐づくため、`certificates` と `hosts` は多対多。
  証明書の同一性は DER の SHA-256 で判定する。
- **閾値は残存日数ではなく残存率ベース。**
  `threshold = max(floor_days, lifetime_days * ratio)`。
  有効期間が47日に短縮される流れの中で、固定日数の閾値は機能しないため。
- **probe は `InsecureSkipVerify: true` で接続し、検証は自前で行う。**
  期限切れ・自己署名の証明書こそが検知対象なので、標準検証で接続を落としてはいけない。
  これは唯一の例外的な `InsecureSkipVerify` 使用箇所であり、他では使わない。
- **通知は状態遷移時のみ発火する。** 毎回の実行で条件合致するもの全てを通知しない。
- **DNS解決に失敗しても即座に台帳から消さない。** `retire_after_days` 連続で
  失敗した場合にのみ `retired` へ遷移させる。

## 開発コマンド

```sh
go build ./...
go test ./...
go test -race ./...
go vet ./...
gofmt -l .                     # 出力が空であること

go run ./cmd/certinv scan --config config.yaml
go run ./cmd/certinv serve --config config.yaml
```

## コーディング規約

- Go 1.25 以降。標準の `gofmt` に従う
- エラーは `fmt.Errorf("...: %w", err)` でラップし、コンテキストを付けて返す。
  ライブラリコード内で `log.Fatal` や `os.Exit` を呼ばない
- ログは `log/slog` を使う。構造化ログとし、`printf` 系のログを書かない
- 外部プロセスを起動しない
- 依存追加は最小限にする。追加する場合は理由をPRに書く

想定している依存（これ以外を追加する場合は要相談）:

- `modernc.org/sqlite` — cgo不要のSQLiteドライバ
- `golang.org/x/net/publicsuffix` — eTLD+1 の検証
- `gopkg.in/yaml.v3` — 設定ファイル
- `github.com/prometheus/client_golang` — exporter

## テスト方針

- `internal/cert` と `internal/evaluate` は純粋関数中心なので、テーブル駆動テストで
  カバレッジを厚くする。特に閾値判定は 398/200/100/47日 の各ケースを網羅する
- `internal/probe` のテストは `httptest.NewTLSServer` と、テスト実行時に生成した
  証明書（期限切れ・自己署名・チェーン不備・ホスト名不一致）を使う
- `internal/discover/crtname` は `httptest.NewServer` でAPIレスポンスをスタブする。
  実際の crt.name には接続しない
- ネットワークに出るテストを書く場合は `testing.Short()` でスキップ可能にする

## コミットとPR

- コミットメッセージは Conventional Commits（`feat:`, `fix:`, `docs:`, `refactor:`, `test:`, `chore:`）
- 1つのPRは1つの関心事に絞る。パイプラインの複数段を同時に変更しない
- 新機能には必ずテストを添える
- `docs/design.md` に反する実装をする場合は、先に design.md を更新するPRを分ける
- ユーザーから見える挙動（CLIコマンド・フラグ・出力・設定項目）を追加/変更した場合は
  同じPRで README.md の該当箇所も更新する

## 参照

- CA/Browser Forum Ballot SC-081v3（有効期間短縮スケジュール）
- RFC 9773 — ACME Renewal Information (ARI)
- RFC 6962 / Static CT — Certificate Transparency
- crt.name API: `GET https://crt.name/v1/search?apex={apex}&format=json&dates=1`
