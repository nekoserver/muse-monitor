# 受信 API の契約（/monitor）

この Worker が依存するホスト側の受信 API のうち、モニタ用の
読み取り専用エンドポイントの契約をここに固定する。

## エンドポイント

```
GET /monitor/<section>
```

- 配置: ホスト（tailnet 内、ポート 8090）。公開インターネットからは
  到達しない。この Worker は Durable Object 内の Tailscale WASM
  ノード経由でのみアクセスする
- 相手の特定: 基名 `muse-vm` のみを固定とし、実 IP は netmap の
  ピア（`muse-vm`、`muse-vm-1`、…）から候補を挙げ、`/health` への
  到達で判定する。IP の固定指定はしない
- 認証: `Authorization: Bearer <TS_API_KEY>` 必須。
  未設定・不一致は 401、受信側に鍵が未設定なら 503

## レスポンス

```json
{
  "section": "status",
  "rc": 0,
  "output": "…スクリプトの標準出力（＋標準エラー）…",
  "truncated": false,
  "ts": "2026-11-11T05:30:00+0900"
}
```

- `output` の上限は 64 KiB。超えた場合は切り捨てて `truncated: true`
- 未知の section は 404
- スクリプトの実行がタイムアウト（60 秒）した場合は 504

## section 一覧

status / diag / jobs / pkgs / vm / procs / ports / git / recent /
pending / execlog / sdkhealth / sdkprofiles / sdksessions / sdkts

各 section はホスト側の読み取り専用スクリプト1本に対応する。
書き込み・実行系のエンドポイントはモニタ用には存在しない。

## 変更時の注意

- section の追加・削除は、この文書と Worker 側
  （`src/index.ts` の表示項目、`src/do.ts` の許可リスト）を
  同時に変更すること
- 認証方式を変える場合は、受信側と Worker のシークレット
  （`TS_API_KEY`）を合わせて変更すること
