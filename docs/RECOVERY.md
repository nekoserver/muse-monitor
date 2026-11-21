# DO 復旧手順 — 永続化状態の破損

muse-monitor の MonitorGateway DO が保持するノードの永続化状態が壊れた場合の、検知から確認までの手順。運任せにしないため、順序と確認基準をここに固定する。

動作と回帰テストの基準は [再ログイン仕様](SPEC.needslogin-recovery.md) を参照する。

## 検知

- `/health` の node が NoState のまま変わらない、または全 section が `502 tailnet_unavailable` を返す。

## 切り分け

1. `/health` で revision、node、authKeySource を確認する。
2. `/api/status`（WORKER_API_KEY が必要）で lastError の文面を確認し、理由を確定する。文面が「discarded the persisted node state ...」であれば、下記の自動復旧は実施済みである。

## 自動復旧（revision 11 以降のコードの動作）

- 発動条件: 永続化状態ありで起動し、start が失敗した、または NoState のまま 60 秒を超えてもログイン URL が出ない場合。
- 動作: 永続化状態を破棄し、認証キー（TS_AUTHKEY）で初回参加をやり直す。やり直しは 1 回だけ。破棄した旨と理由は lastError に記録される。
- 確認基準: `/health` で node が Running になり、receiverResolved が true になること。

## 自動復旧で直らない場合の手作業

1. `/api/status` の lastError で理由を確定する（start の失敗か、鍵の拒否か）。
2. 鍵の拒否であれば、Tailscale 側で TS_AUTHKEY が有効な認証キーであること（失効・期限・再利用の可否）を確認し、必要なら新しい認証キーを発行して設定する。TS_API_KEY（receiver の Bearer 鍵）と取り違えないこと。鍵の役割は `docs/KEY_LEDGER.md` が正である。
3. 再デプロイ（空の変更の push でも可）で DO を新しい版に載せ替え、`/health` で再度確認する。
4. それでも Running にならない場合は、復旧できていないものとして扱う。「復旧済み」と報告しない。

## やってはいけないこと

- receiver 鍵の値を TS_AUTHKEY に設定しない（2026-11-12 の事故: 両 Worker が tailnet から切断された）。
- 状態の破棄を繰り返し実行しない（自動復旧は 1 回だけ。再試行は上の手作業の順序で行う）。

## 実績

- 2026-11-16: TS_AUTHKEY 設定後に node が NoState に固定された障害で、revision 11 の自動復旧が発動し、状態破棄と TS_AUTHKEY での再参加により 13:27 JST に Running へ復旧した（receiverResolved true まで確認）。

- 2026-11-21: revision 27 の本番で、保存状態から起動するたびに `NeedsLogin` で60秒の時間切れとなり、承認リンクが出なかった。revision 29 では前回の時間切れを保存済み起動記録から読み、鍵を付けずに対話ログインを開始する。稼働中のインスタンスの停止した起動処理にも一度だけ同じ再試行を適用する。状態の破棄は発動条件に含めていない。デプロイ後、公開 `/health` で承認リンクの生成を確認した。承認リンクは認証済みの画面で取得する。

- 2026-11-21 revision 30: 認証済み画面が承認リンクを取り直すよう修正した。対話ログインの時間切れ後も、再確認でリンクを更新できる。
