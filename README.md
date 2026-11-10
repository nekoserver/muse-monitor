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
| `GET /health`           | 不要          | Worker 自身の死活        |
| `GET /api/status`       | WORKER_API_KEY | WASM ノードの状態       |
| `GET /api/monitor/<s>`  | WORKER_API_KEY | section のデータを返す  |
| `GET /api/hmac/monitor/<s>` | HMAC 署名  | 本体 Worker 専用。署名が無い・不正・時刻が ±300 秒を超えるものは全て拒否する |
| `GET /api/hmac/status`  | HMAC 署名      | 本体 Worker 専用。ノード状態（署名対象は `status`） |

HMAC の形式（本体 Worker からの呼び出し用）:

- ヘッダ `X-Muse-Timestamp`: unix 秒
- ヘッダ `X-Muse-Signature`: `HMAC-SHA256(MONITOR_HMAC_SECRET, "<timestamp>.<section>")` の hex

ダッシュボード画面では API キーを入力して取得します
（キーはブラウザの外に送信されません）。

## シークレット

デプロイ時に以下を Worker のシークレットとして設定します
（リポジトリには含めません）。

| 名前              | 用途                                   |
|-------------------|----------------------------------------|
| `TS_AUTHKEY`      | （任意）WASM ノードの Tailscale ログイン。未設定の場合は対話ログイン（`/api/status` の `loginUrl` を開いて承認）になる |
| `TS_API_KEY`| 受信 API への Bearer 認証              |
| `WORKER_API_KEY`  | `/api/*` への Bearer 認証              |
| `MONITOR_HMAC_SECRET` | 本体 Worker と共有する HMAC 鍵（両方に同じ値を設定） |

受信 API の相手は、基名 `muse-vm` だけを `src/do.ts` に持ちます。
IP はノードの再登録で変わり、名前には数字の接尾辞が付くことがあるため、
実アドレスは WASM ノードの netmap から候補を挙げ、受信側の `/health`
への到達で判定して決めます（失敗時は再探索）。

## デプロイ

```sh
npm install
npx wrangler secret put TS_AUTHKEY   # 任意（対話ログインを使う場合は不要）
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
