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
  未設定・不一致は 401、受信側に鍵が未設定なら 503（エラー名は `receiver_key_not_configured` に統一する。SPEC REQ-SEC-062）
- 鍵の正: 受信側の `~/.config/muse-receiver.env`。Worker のシークレットは写しであり、食い違った場合は受信側に合わせる（SPEC REQ-SEC-059）
- 指紋: 受信側は `/health` に `keyFingerprint`（鍵の SHA-256 の先頭8文字。未設定なら null）を返し、401 の本文に `expectedKeyFingerprint` と `presentedKeyFingerprint` を含める。Worker は自ら提示した鍵の指紋を認証済み `/api/status` の `receiverKeyFingerprint` に出し、`receiver_unauthorized` の本文に両指紋を含める（SPEC REQ-SEC-060・061）

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
pending / execlog / sdkhealth / sdkprofiles / sdksessions / sdkts / hooks

各 section はホスト側の読み取り専用スクリプト1本に対応する。
書き込み・実行系のエンドポイントはモニタ用には存在しない。

## 変更時の注意

- section の追加・削除は、この文書と Worker 側
  （`src/index.ts` の表示項目、`src/do.ts` の許可リスト）を
  同時に変更すること
- 認証方式を変える場合は、受信側と Worker のシークレット
  （`TS_API_KEY`）を合わせて変更すること
- `TS_AUTHKEY` は受信側の鍵ではない（WASM ノードの tailnet 参加専用）。
  受信側が Bearer として受け付けるのは `TS_API_KEY` のみ

## TS_API_KEY を揃える正しい手順

鍵の正は受信側の `/home/hatch/.config/muse-receiver.env`。順序は、受信側の値を先に決め、Worker のシークレットをそれに合わせ、最後に指紋で照合する（REQ-SEC-059）。

1. 受信側の値を決める。付け替えは `receiver-key.sh` で行う（`set` は値を標準入力から読む。値をコマンドラインに書かない。シェルの履歴に残る）。SSH ログインのシェルは HOME が /root になるため、対象ファイルは絶対パスで明示する。付けないと `/root/.config/muse-receiver.env` を読み書きし、本体には届かない。

   ```
   MUSE_RECEIVER_ENV=/home/hatch/.config/muse-receiver.env sh /home/hatch/lib/muse/samples/receiver-key.sh set
   ```

2. Worker 側は Cloudflare ダッシュボードの muse-monitor → Settings → Variables and Secrets で、シークレット `TS_API_KEY` に同じ値を保存する。
3. シークレットの保存は、稼働中の gateway（Durable Object）には即時反映されない。反映は DO が作り直されたとき（コードのデプロイ時）に起きる。保存直後に 401 でも、保存した値が誤っているとは限らない（2026-11-21 実測: 保存 19:59 → 反映はデプロイ後の 20:05）。
4. 照合は値ではなく指紋で行う。受信側 `/health` の `keyFingerprint` と、認証済み `/api/status` の `receiverKeyFingerprint` が一致し、`/api/monitor/status` が section の中身（200）を返せば完了。
5. この状態は VM の再起動では戻らない。鍵ファイルは `~` 配下にあり永続し、受信側は再起動後に同じファイルを読み直す。Worker のシークレットは Cloudflare 側にあり、VM の再起動とは無関係。
