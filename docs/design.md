# certinv 設計ドキュメント

TLS証明書インベントリツール

- ステータス: draft
- 最終更新: 2026-08-23

---

## 1. 背景と目的

CA/Browser Forum の Ballot SC-081v3 により、公開TLS証明書の最大有効期間は段階的に
短縮される。

| 適用開始 | 最大有効期間 | DCV再利用期間 |
|---|---|---|
| 2026-03-15 | 200日 | 200日 |
| 2027-03-15 | 100日 | 100日 |
| 2029-03-15 | 47日 | 10日 |

さらに Let's Encrypt は45日をCA/B Forumの要求より前倒しで実現する方針を示しており、
実質的な移行期限は上表より早いと見るべきである。

この変更で最初に顕在化するのは「更新作業の頻度」ではなく、
**「そもそも自組織にどれだけの証明書が存在するのか誰も把握していない」** という問題である。
更新サイクルが年1回であれば属人的な管理でも破綻しなかったが、年8回になると
管理外の証明書は確実に期限切れを起こす。

certinv は、ドメイン所有者が自組織の証明書を棚卸しし、期限切れを事前に検知するための
ツールである。

### 1.1 非目標

- 証明書の発行・更新は行わない（certbot / lego / cert-manager の領域）
- 秘密鍵を一切扱わない。読み取り専用ツールとして設計する
- 他者のドメインに対する調査には使わせない（§2 参照）

### 1.2 想定利用者

初期は 1〜数ドメインを管理する個人・小規模チーム。
将来的に100ドメイン以上の組織にも拡張できる構造にしておくが、
最初からその規模で最適化はしない（§8 参照）。

---

## 2. スコープ制御

サブドメイン列挙とTLSプローブは、対象を選ばなければ偵察行為になる。
以下を設計上の制約とする。

- 設定ファイルに明示的に登録された apex ドメインのみを処理する。
  コマンドライン引数だけでの任意ドメイン指定は行わない
- プローブの並列度・レートのデフォルトは保守的にする（初期値: 並列5、ホストあたり最大1接続）
- User-Agent に識別子と連絡先URLを含める
- README とヘルプに「所有ドメインの棚卸しツール」であることを明記する

---

## 3. アーキテクチャ

```
                    ┌─────────────┐
   config.yaml ────▶│    Core     │
                    │  (1回実行)   │
                    └──────┬──────┘
                           │
     ┌─────────┬───────────┼───────────┬─────────┐
     ▼         ▼           ▼           ▼         ▼
 discover   resolve     probe      dedupe    evaluate
     │         │           │           │         │
     └─────────┴───────────┴───────────┴─────────┘
                           │
                    ┌──────▼──────┐
                    │   Storage   │  SQLite
                    └──────┬──────┘
                           │
              ┌────────────┴────────────┐
              ▼                         ▼
        Notifier(s)               Exporter
    Slack / Webhook            Prometheus /metrics
```

CLIとデーモンは同じ Core を呼ぶ。デーモンは Core をスケジューラで定期起動し、
加えて exporter 用のHTTPサーバを常駐させる。ロジックを二重に持たない。

### 3.1 コマンド

```
certinv scan          1回実行して終了（cron向け）
certinv serve         常駐。スケジュール実行 + /metrics
certinv list          台帳の内容を表示
certinv check <host>  単一ホストのアドホック確認（台帳に書き込まない）
```

---

## 4. パイプライン

### 4.1 discover — 候補ホスト名の収集

複数ソースをプラグインとして持ち、結果をマージする。

| ソース | 実装優先度 | 備考 |
|---|---|---|
| crt.name | v0.1 | 主要ソース |
| 設定ファイルへの手動記載 | v0.1 | CTの盲点を埋める。ポート指定可 |
| DNSゾーンファイル | v0.4 | AXFR / ゾーンファイル読み込み |
| CIDRスキャン | 将来 | 内部ネットワーク向け |

#### crt.name API

```
GET https://crt.name/v1/search?apex={apex}&format=json&dates=1
```

- トークン不要、1000リクエスト/IP/日。apexあたり1リクエストなので実質制約にならない
- `apex` は eTLD+1 でなければならない。`golang.org/x/net/publicsuffix` で事前検証する
- **インデックスは名前を削除しない。** APIは `sub` フィールドでホスト名を返す。
  保持するのは `(apex, sub, first-seen)` の
  3フィールドのみ。長く運用したドメインほど、廃止済みホスト名が大量に返る。
  生存確認（§4.2）は必須であり、ここの精度が本ツールの価値そのものである
- **証明書メタデータを持たない。** SANホスト名だけを抽出して残りは破棄する設計のため、
  有効期限は自前で取得する必要がある。crt.name は「発見専用」と位置づける

#### CTの盲点（既知の限界としてドキュメント化する）

- ワイルドカード証明書は個別ホスト名をCTに残さない
- プライベートCA発行の証明書はCTに載らない
- CTは名前を返すがポートは返さない。SMTPS(465) / IMAPS(993) / LDAPS(636) /
  管理コンソール(8443) 等は手動登録が必要

有効期間短縮で最も困るのは ACME 非対応のアプライアンス類だが、
それらはまさにこの盲点に位置する。discovery をプラグイン化する理由はここにある。

### 4.2 resolve — 生存確認

DNS解決（A / AAAA / CNAME）に失敗した名前は台帳に載せない。
ただし **即座に削除はしない**。`last_resolved_at` を記録し、
`retire_after_days`（デフォルト30日）連続で解決失敗した場合に `retired` へ遷移させる。
一時的なDNS障害で台帳が消えるのを防ぐ。

### 4.3 probe — 証明書の取得

- SNI にホスト名を設定してTLSハンドシェイク
- **`InsecureSkipVerify: true` で接続し、検証は自前で行う。**
  期限切れ・自己署名の証明書こそが検知対象であり、標準検証で接続を落としてはいけない。
  本ツール内で `InsecureSkipVerify` を使うのはここだけとする
- ハンドシェイク完了時点でチェーンを取得し、アプリケーションデータは送らず切断する
- タイムアウト: 接続5秒 / ハンドシェイク5秒
- 対象ポートはホストごとに設定可能。デフォルト443

取得後に自前で検証し、以下を記録する。

- 有効期限（notBefore / notAfter）
- 発行者（Issuer CN / Organization）
- SANリスト
- 署名アルゴリズム・鍵アルゴリズム・鍵長
- チェーンの完全性（中間証明書が配信されているか）
- ホスト名の一致
- 自己署名かどうか

`probe.http_check` が有効な場合は、TLSプローブ完了後に同じ `host:port` へ
HTTPS GETを1回だけ行い、短いタイムアウトでHTTPステータスコードも記録する。
証明書検証はTLSプローブと同じく行わず、接続失敗はステータスなしとして扱い、
証明書プローブ全体は失敗にしない。デフォルトは無効である。

### 4.4 dedupe — 証明書単位への集約

**インベントリの主キーはホスト名ではなく証明書とする。**
SAN証明書1枚に数十ホスト名が含まれる場合、ホスト名単位の台帳では
1枚の期限切れが数十件のアラートになる。

証明書の同一性は **DER形式の SHA-256 フィンガープリント** で判定する。
ホスト名と証明書は多対多で紐づける。

### 4.5 evaluate — 判定

#### 閾値

**残存率ベースの閾値**を採用する。固定日数の閾値は有効期間短縮後に破綻するため。

```
threshold = max(floor_days, lifetime_days × ratio)

warn:  ratio = 0.25, floor = 3日
alert: ratio = 0.10, floor = 1日
```

| 有効期間 | warn発火 | alert発火 |
|---|---|---|
| 398日 | 残り99日 | 残り39日 |
| 200日 | 残り50日 | 残り20日 |
| 100日 | 残り25日 | 残り10日 |
| 47日 | 残り12日 | 残り5日 |

固定の「残り30日で警告」は47日証明書では寿命の36%消化時点で発火し、
常時警告状態になって誰も見なくなる。これを避けるための設計である。

将来的には ARI（RFC 9773）で更新推奨ウィンドウを公開しているCAについては、
そちらを優先参照する（v0.5）。

#### 期限以外の検知項目

- チェーン不備（中間証明書の欠落）
- ホスト名不一致
- 自己署名
- 弱い署名アルゴリズム / 鍵長
- **自動化推定**: 有効期間 ≤ 100日 かつ 既知のACME対応CA発行 → 自動更新の可能性が高い。
  逆に 200日以上 かつ 商用CA → 手動更新の疑い。
  47日移行に向けた優先対応リストとして使える

### 4.6 notify — 通知

**状態遷移時のみ発火する。** 毎回の実行で条件に合致するもの全てを通知すると
通知疲れを起こす。

| イベント | 説明 |
|---|---|
| `discovered` | 新しい証明書を発見 |
| `warn` / `alert` | 閾値を跨いだ |
| `renewed` | 同一ホストの証明書フィンガープリントが変化し、期限が延びた |
| `expired` | 期限切れを検知 |
| `misconfigured` | チェーン不備・ホスト名不一致等 |
| `retired` | ホストが到達不能になった |

`renewed` を明示的に扱うことで「更新されたので警告解除」がSlack上で分かるようにする。

Notifier はインターフェースとして定義し、Slack / 汎用Webhook から実装する。

#### Prometheus exporter

通知とは独立に `/metrics` を提供する。Alertmanager 側で閾値判定したい利用者は
こちらだけを使えばよい。

```
certinv_cert_not_after_timestamp{fingerprint,issuer,common_name}
certinv_cert_lifetime_days{fingerprint}
certinv_cert_remaining_ratio{fingerprint}
certinv_host_reachable{host,port}
certinv_scan_duration_seconds
certinv_scan_last_success_timestamp
```

### 4.7 Web UI — インベントリ表示と限定的な運用操作

`serve` モードのHTTPサーバに、ブラウザでインベントリを確認し、限定的な運用操作を行うUIを
追加する。UIから変更できるのはスキャン実行、イベントの確認状態、対象ホストの登録内容だけ
であり、証明書の発行・更新や秘密鍵の取り扱いは引き続き行わない。

表示対象は §5 のデータモデルに保存されているメタデータをベースにする。

- ホスト一覧: hostname / port / apex / source / host status / first_seen_at /
  last_resolved_at / last_probed_at
- 証明書一覧: fingerprint（短縮表示） / state / not_before / not_after /
  lifetime_days / issuer_cn / issuer_org / subject_cn / SAN / last_seen_at
- ホストと証明書の紐づき: observed_at / chain_complete / hostname_match
- scan状況: 最終成功時刻、直近scanの概要（Prometheus exporter と同じ情報を再利用）

優先度の高い操作機能を次の順で追加する。

1. **手動スキャントリガー**: UIから `POST /api/scan` を受け付け、`core.Runner.Run` を
   非同期で起動する。実行中の重複起動を防ぎ、受付結果と実行状態を返す。スキャンは既存の
   設定済みapexだけを対象とし、証明書の発行・更新処理は呼び出さない。
2. **イベント／アラートの確認済み化**: warn / alert のイベントをUIから acknowledged に
   遷移させる。`events` または `certificate_states` に確認状態、確認者、確認時刻を保持する
   カラムを追加し、証明書のメタデータや実体は変更しない。
3. **apex／manual host の追加・削除**: UIから対象ドメインと手動登録ホストを管理する。
   設定ファイルを直接書き換えるのではなく、`apexes` と `hosts` をDB側の管理情報として扱う
   方式を検討する。追加・削除時も §2 のスコープ検証を行い、登録外ドメインは処理しない。
4. **discovery source 設定のオーバーレイ**: UIは `Inventory` と `Sources & Targets` の
   タブに分ける。`Sources & Targets` では `config.yaml` をbaseとして、crt.nameの
   有効/無効とendpoint、zone file追加分をDBオーバーレイとして保存する。`config.yaml` は
   書き換えない。zone fileは `discovery.zone.allowed_dir` 配下の実在ファイルだけを選択
   できるようにし、正規化後のパスが許可ディレクトリ配下であることを検証する。

UIは本ツールの絶対ルールに従い、証明書の生DER/PEMや秘密鍵素材を表示しない。
出力してよいのは fingerprint、SAN、CN、issuer、有効期限、状態などのメタデータに限る。

実装は Go 標準ライブラリの `net/http` と `html/template` によるサーバーサイドレンダリング
とする。重いJavaScriptフレームワーク、フロントエンドのビルドパイプライン、新しい外部依存は
導入しない。`serve` コマンドの既存HTTPサーバに `/ui` として同居させ、`/` は `/ui` に
redirect する。`/metrics` はPrometheus用のまま維持する。

`serve` モードのHTTPサーバは、オプションでBasic認証を有効化できる。設定の
`exporter.basic_auth.username` と `exporter.basic_auth.password` の両方が空の場合は
認証なしで動作し、既存設定との後方互換を維持する。両方が設定されている場合は
`/metrics` と `/ui` の両方を保護する。認証情報の比較には定数時間比較を使い、
パスワードなどの秘匿情報をログに出してはならない。

外部公開する場合は、certinv のHTTPサーバを直接インターネットへ露出せず、TLS終端と
アクセス制御を行うリバースプロキシ配下に置くことを推奨する。

---

## 5. データモデル

```sql
CREATE TABLE apexes (
  apex           TEXT PRIMARY KEY,
  enabled        INTEGER NOT NULL DEFAULT 1,
  added_at       TEXT NOT NULL
);

CREATE TABLE hosts (
  id                INTEGER PRIMARY KEY,
  hostname          TEXT NOT NULL,
  port              INTEGER NOT NULL DEFAULT 443,
  apex              TEXT NOT NULL REFERENCES apexes(apex),
  source            TEXT NOT NULL,      -- 'crtname' | 'manual' | 'zone'
  first_seen_at     TEXT NOT NULL,
  last_resolved_at  TEXT,
  last_probed_at    TEXT,
  status            TEXT NOT NULL,      -- 'active' | 'unresolved' | 'retired'
  UNIQUE(hostname, port)
);

CREATE TABLE certificates (
  fingerprint       TEXT PRIMARY KEY,   -- SHA-256 of DER
  subject_cn        TEXT,
  issuer_cn         TEXT,
  issuer_org        TEXT,
  not_before        TEXT NOT NULL,
  not_after         TEXT NOT NULL,
  lifetime_days     INTEGER NOT NULL,
  sig_algorithm     TEXT,
  key_algorithm     TEXT,
  key_bits          INTEGER,
  is_self_signed    INTEGER NOT NULL,
  san_names         TEXT,               -- JSON array
  first_seen_at     TEXT NOT NULL,
  last_seen_at      TEXT NOT NULL
);

-- 1枚の証明書が複数ホストに紐づく（多対多）
CREATE TABLE host_certificates (
  host_id           INTEGER NOT NULL REFERENCES hosts(id),
  fingerprint       TEXT NOT NULL REFERENCES certificates(fingerprint),
  observed_at       TEXT NOT NULL,
  chain_complete    INTEGER,
  hostname_match    INTEGER,
  PRIMARY KEY (host_id, fingerprint)
);

CREATE TABLE certificate_states (
  host_id           INTEGER NOT NULL REFERENCES hosts(id),
  fingerprint       TEXT NOT NULL REFERENCES certificates(fingerprint),
  state             TEXT NOT NULL,      -- 'healthy' | 'warn' | 'alert' | 'expired' | 'misconfigured'
  updated_at        TEXT NOT NULL,
  PRIMARY KEY (host_id, fingerprint)
);

CREATE TABLE events (
  id                INTEGER PRIMARY KEY,
  kind              TEXT NOT NULL,
  fingerprint       TEXT,
  host_id           INTEGER,
  occurred_at       TEXT NOT NULL,
  notified_at       TEXT,
  detail            TEXT
);

CREATE INDEX idx_hosts_apex        ON hosts(apex);
CREATE INDEX idx_hosts_status      ON hosts(status);
CREATE INDEX idx_certs_not_after   ON certificates(not_after);
CREATE INDEX idx_events_notified   ON events(notified_at) WHERE notified_at IS NULL;
```

`events.notified_at` により、通知失敗時のリトライと重複通知の防止を両立する。
ポート列を最初からスキーマに含めているのは、443以外への対応を後付けすると
テーブル設計から作り直しになるため。

---

## 6. 設定ファイル

```yaml
apexes:
  - example.com
  - example.co.jp

# CTに現れないホストの手動登録
manual_hosts:
  - hostname: mail.example.com
    port: 993
  - hostname: vpn.example.com
    port: 443
  - hostname: lb01.internal.example.com
    port: 8443

discovery:
  sources: [crtname, manual]
  crtname:
    endpoint: https://crt.name/v1/search
  # v0.4 / PR #3: DNS zone file から取り込む場合
  # sources: [crtname, manual, zone]
  # zone:
  #   allowed_dir: ./zones
  #   files:
  #     - ./example.com.zone

probe:
  concurrency: 5
  connect_timeout: 5s
  handshake_timeout: 5s
  retire_after_days: 30

thresholds:
  warn:  { ratio: 0.25, floor_days: 3 }
  alert: { ratio: 0.10, floor_days: 1 }

storage:
  driver: sqlite
  dsn: ./certinv.db

schedule:            # serve モードのみ
  interval: 6h

notifiers:
  - type: slack
    webhook_url_env: SLACK_WEBHOOK_URL
    events: [alert, expired, misconfigured]
  - type: webhook
    url: https://example.com/hooks/certinv
    events: [warn, alert, renewed, expired]

exporter:            # serve モードのみ
  listen: :9101
  basic_auth:        # 任意。username/password の両方が空なら無効
    username: ""
    password: ""
```

通知Webhookなど外部連携のシークレットは、設定ファイルに直接書かせず環境変数参照のみを
許可する。`exporter.basic_auth.password` は小規模運用向けの任意設定として扱い、
ログには出さず、設定ファイルの権限管理または環境変数テンプレート等で保護する。

---

## 7. 技術選定

- **言語**: Go
  - 単一バイナリ配布、クロスコンパイル対応
  - `crypto/x509` / `crypto/tls` の標準ライブラリで要件を満たせる
  - 並列プローブが goroutine で素直に書ける
- **ストレージ**: SQLite（`modernc.org/sqlite` — cgo不要）
  - `store.Store` インターフェースで抽象化し、将来のPostgreSQL対応の余地を残す
- **依存の方針**: 暗号処理は自前実装しない。標準ライブラリのみを使う

---

## 8. スケーラビリティ

初期実装は1〜数ドメインを対象とするが、以下2点だけは最初から満たしておく。
これがあれば100ドメイン規模まで大きな書き直しなしに伸ばせる。

1. **プローブは並列度パラメータ付きのワーカープールで実装する。**
   逐次ループで書くと後からの並列化が全面書き直しになる。
   デフォルトの並列度は5と保守的にしておく
2. **ストレージはインターフェース越しに使う。**
   SQLiteは数万レコードなら十分だが、実装を差し替えられる形にしておく

---

## 9. ロードマップ

| バージョン | 内容 |
|---|---|
| v0.1 | `scan` コマンド。crt.name + 手動登録 → 生存確認 → プローブ → SQLite → 標準出力 |
| v0.2 | 閾値判定とイベント遷移管理。Slack / Webhook 通知 |
| v0.3 | `serve` モード。スケジューラ + Prometheus exporter |
| v0.4 | DNSゾーンファイル取り込み。自動化推定レポート |
| v0.5 | ARI 対応。大規模向けの並列度・ストレージ最適化 |
| v0.6 | `serve` モードにWeb UIを追加 |

---

## 10. 未決事項

- 閾値の係数（0.25 / 0.10）は運用してから調整する余地がある
- `check` コマンドで台帳外のホストを許すか。許すと §2 のスコープ制御が緩む
- ワイルドカード証明書の扱い。`*.example.com` を観測したとき、
  どのホスト名に紐づけるべきか
- 複数の apex が同一の証明書を共有する場合の集計表示

---

## 11. 参照

- CA/Browser Forum Ballot SC-081v3: Introduce Schedule of Reducing Validity and Data Reuse Periods
- RFC 9773 — ACME Renewal Information (ARI)
- RFC 6962 — Certificate Transparency / Static CT API
- crt.name — https://crt.name/
