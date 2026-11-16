# 鍵台帳（muse-monitor）

muse-monitor が読む鍵の一覧。仕様は `SPEC.muse-monitor.security.hardening`
（リポジトリ外: `~/workspace/linted-specs/`）。鍵の値はここに書かない。
この表の名前集合が、コードの Env 宣言および `wrangler.toml` のコメントと
一致することは `test/ledger.test.ts` が保証する。

| 名前 | 発行者 | 用途 | 消費側 | 設定場所 | ローテーション | 状態 |
|------|--------|------|--------|----------|--------------|------|
| `TS_AUTHKEY` | Tailscale | WASM ノードの tailnet 参加専用。receiver へは送らない | `src/do.ts`（MonitorGateway のノード参加） | muse-monitor の Worker シークレット | Tailscale 管理画面で新しい認証キーを発行し、シークレットを差し替える。旧キーは管理画面で失効させる | 移行待ち（未設定。未設定の間は参加が `TS_API_KEY` へフォールバックする） |
| `TS_API_KEY` | 運用者（任意文字列） | receiver への Bearer 専用。tailnet 参加には使わない（フォールバック時を除く） | `src/do.ts`（receiver 呼び出し）、receiver 側は `receiver.py` | muse-monitor の Worker シークレットと、muse-vm の鍵ファイル `~/.config/muse-receiver.env`（両方に同じ値） | 両側の値を同時に差し替える。片側だけ変えると `receiver_unauthorized` になる | 設定済み（receiver 側の照合は有効化待ち。SPEC の移行手順を参照） |
| `WORKER_API_KEY` | 運用者（任意文字列） | `/api/*` の Bearer 認証と、ログイン Cookie（`mm_auth`）の署名 | `src/index.ts`、`src/auth-cookie.ts` | muse-monitor の Worker シークレット | シークレットを差し替える。差し替えると既存のログイン Cookie は全て無効になり、利用者は再ログインが必要になる | 設定済み |
| `MONITOR_HMAC_SECRET` | 運用者（任意文字列） | 本体 Worker からの `/api/hmac/*` 呼び出しの HMAC 署名 | `src/index.ts` | muse-monitor と本体 Worker の両方のシークレット（両方に同じ値） | 両側を同時に差し替える。片側だけ変えると本体 Worker の呼び出しが 401 になる | 設定済み |

## receiver 側の鍵ファイルについて

- `~/.config/muse-receiver.env` は `TS_API_KEY` の receiver 側の置き場所であり、
  別の鍵ではない。
- `~/.local/share/muse-code-wasm/api-key` は muse-code-wasm 用の置き場所で、
  現在は同じ値が入っている。値が同じでも、鍵は `TS_API_KEY` の1つである。

## ローテーション記録

| 鍵 | 最終実施日 | 備考 |
|----|-----------|------|
| `TS_AUTHKEY` | 未実施 | 初回設定が移行手順の手順2 |
| `TS_API_KEY` | 未実施 | receiver 照合の有効化と合わせて実施するかは未定 |
| `WORKER_API_KEY` | 未実施 | |
| `MONITOR_HMAC_SECRET` | 未実施 | |

自動ローテーションは実装しない（SPEC REQ-SEC-016）。実施したらこの表に日付を記録する。

## アラートの分担

この Worker からアラート通知は送らない（SPEC REQ-SEC-017）。
検出は次の2つが担う。

- `/health` の公開状態（revision、ノード状態、鍵の出所名）
- muse-vm 側の receiver-watch（receiver の死活監視と再起動）
