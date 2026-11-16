# muse-monitor

ホストマシン（muse-vm）の状態を表示する、読み取り専用のモニタ
ダッシュボードを提供する Cloudflare Worker です。

ブラウザからのリクエストを受け、Durable Object 内の Tailscale WASM
ノード経由で tailnet 内の受信 API からホストの状態を取得して表示します。
この Worker 自身はデータを保持せず、実行系の機能も持ちません
（表示専用）。

## 構成

```
ブラウザ
  │ HTTPS
  ▼
Worker (muse-monitor)
  ・ダッシュボード画面（/）
  ・API プロキシ（/api/monitor/<section>, /api/status）
  │
  ▼
Durable Object (MonitorGateway)
  ・Tailscale WASM ノードを保持し、tailnet 経由で受信 API を呼ぶ
  │
  ▼
受信 API（ホスト側、tailnet 内 :8090）
  ・GET /monitor/<section> でホストの状態を JSON で返す
```

## 表示項目

| section   | 内容                     |
|-----------|--------------------------|
| status    | デーモンの状態           |
| diag      | システム診断サマリ       |
| sdkhealth | SDK ヘルスチェック       |
| sdkprofiles | SDK プロファイル一覧   |
| sdksessions | SDK セッション一覧     |
| sdkts     | SDK ヘルス（TypeScript） |
| jobs      | ジョブキュー             |
| pending   | 承認待ちリクエスト       |
| execlog   | 実行監査ログ             |
| pkgs      | パッケージのバージョン   |
| vm        | VM 情報                  |
| procs     | プロセス一覧（上位）     |
| ports     | 待ち受けポート           |
| git       | リポジトリの状態         |
| recent    | 直近の完了ジョブ         |

## エンドポイント

| パス                    | 認証          | 説明                     |
|-------------------------|---------------|--------------------------|
| `GET /`                 | 不要          | ダッシュボード画面       |
| `GET /health`           | 不要          | Worker の死活、コードの版(`revision`)、デプロイした版(`version`)、ノードの公開状態(`node`) |
| `GET /api/status`       | WORKER_API_KEY かログイン Cookie | WASM ノードの状態。キーで呼ぶとログイン Cookie(7日)を発行 |
| `GET /api/monitor/<s>`  | WORKER_API_KEY かログイン Cookie | section のデータを返す  |
| `POST /api/logout`      | なし | ログイン Cookie を消す |
| `GET /api/hmac/monitor/<s>` | HMAC 署名  | 本体 Worker 専用。署名が無い・不正・時刻が ±300 秒を超えるものは全て拒否する |
| `GET /api/hmac/status`  | HMAC 署名      | 本体 Worker 専用。ノード状態（署名対象は `status`） |

`GET /health` は鍵なしで、どの版が動いていて、ノードがどういう状態かを確かめるためのもの。秘密は含めない(ログインURL・IPアドレス・鍵の値は出さない)。

| 項目 | 内容 |
|---|---|
| `revision` | コードの版の目印。2以上なら netmap の読み違いの修正(#7)が入っている。3で `node` を追加。9で鍵の役割分離・HMAC リプレイ防止・構造化監査ログ |
| `version` | `[version_metadata]` の版のID・タグ・デプロイ時刻。無ければ `null` |
| `node.node` | ノードの状態(`not-started`・`NeedsLogin`・`Running` など) |
| `node.authKeySource` | ノードの参加に使った鍵のシークレット名(`TS_AUTHKEY` / `TS_API_KEY` / `null`)。`TS_API_KEY` なら移行フォールバック中 |
| `node.receiverKeySource` | 受信側へ送る鍵のシークレット名 |
| `node.loginPending` | 対話ログインの承認待ちか(URLは `/api/status` で鍵を付けて見る) |
| `node.receiverCandidates` | netmap に見えている muse-vm(-N) の数。0 なら muse-vm がピアに見えていない |
| `node.receiverResolved` | `/health` への到達で受信側の IP を決められたか |

HMAC の形式（本体 Worker からの呼び出し用）:

- ヘッダ `X-Muse-Timestamp`: unix 秒
- ヘッダ `X-Muse-Signature`: `HMAC-SHA256(MONITOR_HMAC_SECRET, "<timestamp>.<section>")` の hex
- 署名は1回だけ受理される。同じ署名の再送は 401 `{"error":"replay"}`。
  受理記録を確認できない場合は 503 `{"error":"replay_check_unavailable"}`（fail-closed）
- `/api/*` と `/api/hmac/*` の認証判定は、1件ごとに構造化監査ログ（JSON 1行）を出す。
  鍵の値・Cookie の値・署名そのものは記録しない

ダッシュボード画面では API キーを入力して取得します
（キーはブラウザの外に送信されません）。

## シークレット

デプロイ時に以下を Worker のシークレットとして設定します
（リポジトリには含めません）。

| 名前              | 用途                                   |
|-------------------|----------------------------------------|
| `TS_AUTHKEY`      | Tailscale が発行する認証キー。WASM ノードの tailnet 参加専用で、受信 API へは送らない。未設定の間は参加が `TS_API_KEY` へフォールバックし、その旨が `authKeySource` に出る |
| `TS_API_KEY`      | 運用者が決める任意文字列。受信 API への Bearer 専用。受信側の鍵ファイル（muse-vm の `~/.config/muse-receiver.env`）と同じ値を置く。未設定なら受信 API は呼ばない |
| `WORKER_API_KEY`  | `/api/*` への Bearer 認証。ログイン Cookie(`mm_auth`、7日、HttpOnly・Secure・SameSite=Strict)の署名にも使う。Cookie にキーは入らない。キーを変えると全 Cookie が無効になる |
| `MONITOR_HMAC_SECRET` | 本体 Worker と共有する HMAC 鍵（両方に同じ値を設定） |

受信 API の相手は、基名 `muse-vm` だけを `src/do.ts` に持ちます。
IP はノードの再登録で変わり、名前には数字の接尾辞が付くことがあるため、
実アドレスは WASM ノードの netmap から候補を挙げ、受信側の `/health`
への到達で判定して決めます（失敗時は再探索）。


## キー一覧（運用者向けメモ）

| 名前 | 置き場所 | 何の鍵か | 値 |
|------|----------|----------|----|
| `TS_AUTHKEY` | muse-monitor のシークレット | tailnet への参加専用 | Tailscale 管理画面で発行した認証キー |
| `TS_API_KEY` | muse-monitor のシークレットと、受信側の鍵ファイル（muse-vm の `~/.config/muse-receiver.env`） | 受信側への Bearer | 任意の文字列。両方に同じ値 |
| `WORKER_API_KEY` | muse-monitor のシークレット | ダッシュボードの `/api/*` を呼ぶ際の Bearer | 任意の文字列 |
| `MONITOR_HMAC_SECRET` | muse-monitor と本体 Worker の両方 | 本体 Worker からの HMAC 署名の共有鍵 | 両方に同じ任意の文字列 |

鍵の正本は台帳（`docs/KEY_LEDGER.md`）で、名前・発行者・用途・ローテーション・状態をそちらに記録する。
受信側は稼働中だが、Bearer の照合はまだ有効化していない（有効化の順序は SPEC.muse-monitor.security.hardening の移行手順）。

どの鍵がノードに渡ったかは `/api/status` の `authKeySource`（`TS_AUTHKEY` / `TS_API_KEY` / `null`）で確かめられます（値は出しません）。受信側が 401 を返したときは `receiver_unauthorized`、503 のときは `receiver_key_not_configured` として、どの鍵を送ったか（`keySource`）と合わせて返します。

## デプロイ

```sh
npm install
npx wrangler secret put TS_AUTHKEY
npx wrangler secret put TS_API_KEY
npx wrangler secret put WORKER_API_KEY
npx wrangler secret put MONITOR_HMAC_SECRET
npx wrangler deploy
```

GitHub 連携（Workers Builds）を使う場合は、このリポジトリを接続し、
本番ブランチを `main` に設定します。

## 開発

```sh
npm install
npm run typecheck   # tsc による型チェック
```
