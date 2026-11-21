# REPORT: muse-monitor の NeedsLogin 固着 — 原因特定

- 日付: 2026-11-21
- 対象: nekoserver/muse-monitor（稼働中 revision 27、main 6eafcab）
- 依頼: Okiraku「まだ NeedsLogin だが原因特定を」
- 結論の検証区分: 固着の形と復旧の不発は実物で確認済み（real-verified）。登録が control に届かない理由の最下層は未特定（unverified）で、切り分け手順を §5 に残す。

## 1. 結論

固着の原因は、MonitorGateway DO の永続化状態が指すデバイス登録が control 側に存在しないこと（SPEC.muse-monitor.security.hardening の故障モード F8）と、その形の固着には現行コードの復旧がどれも発動しないことである。

- 永続化状態から復帰したノードは NeedsLogin に着地し、認証キーでの login を1回だけ繰り延べ実行するが、Running にも対話ログイン URL の提示にも至らず60秒で時間切れになる。これが起動のたびに同形で繰り返される。
- 自動復旧（REQ-SEC-026）の発動条件は「start の失敗」または「NoState のまま時間切れ」であり、NeedsLogin の時間切れは対象外である。
- 登録消失への復旧（REQ-SEC-036）は revision 16 の実経路悪化を受けて保留中であり、実装は稼働コードに無い。自動モードでの拡張（REQ-SEC-048）は未マージの v19 実装にのみ存在し、稼働中の revision 27 には入っていない。
- 鍵の問題ではない。同じ TS_AUTHKEY で 2026-11-16 13:27 に再参加が成功し Running になった実績がある（docs/RECOVERY.md「実績」、および当時の実測）。

したがって、現行の稼働コードのままでは、この固着は自然には解けない。解くには §5 の切り分けで最下層を確定したうえで、状態破棄と再参加（REQ-SEC-036 の再開）か対話ログインのどちらかの経路を、人手の判断で実行する必要がある。

## 2. 実測（2026-11-21、実物）

- `GET https://muse-monitor.nekoflare.workers.dev/health`: revision 27、version timestamp 2026-11-18T17:39:06Z（PR #19 マージのビルド）。node は NeedsLogin、ip は null、loginPending は false、lastError は null、authKeySource は TS_AUTHKEY。
- 起動記録（REQ-SEC-044、/health の直近5件）: 全件が同形。
  - 起点は persisted（永続化状態からの復帰）
  - login の呼び方は deferred（NeedsLogin での繰り延べ実行）
  - 遷移は NoState → NeedsLogin（記録のある件）
  - 対話ログイン URL の提示は全件なし（browseUrlOffered false）
  - 結果は全件 timeout（"tailscale node did not reach Running in 60s (state: NeedsLogin, auth key from: TS_AUTHKEY)"）
  - 試行時刻: 2026-11-19 03:17 / 03:23 / 11:09 / 18:22 UTC、2026-11-21 08:22 UTC（最後の1件は本調査の /health 呼び出しで駆動されたもの）
- muse-vm の netmap（LocalAPI で実測）: muse-monitor のノードは存在しない。main-worker-muse は online で、同じ WASM 方式のノード参加が他方では成立している。cf-demo-container、redmine-r9 等の他ノードも存在する。

## 3. コードで確認したこと（main 6eafcab、src/do.ts）

- 起動（startNode）: 永続化状態がある場合、ノード生成に authKey を渡さない。状態が NeedsLogin を返した場合に限り、認証キーで login() を1回だけ呼ぶ（REQ-SEC-022 の実装。notifyState 内、deferredLoginDone で一回限り）。
- 復旧の可否（recoveryEligible）: `recoveryDone` でなく、永続化状態からの起動であり、ログイン URL が提示されておらず、かつ「最終状態が NoState」または「エラー文に could not start を含む」ときだけ真。NeedsLogin のままの60秒時間切れはどちらの条件にも当たらないため、状態破棄と再参加は発動しない。
- 整合性検証（REQ-SEC-033、loadState）: 構造（オブジェクトかつ全値が文字列）だけを見る。構造が健全で意味的に壊れた状態は REQ-SEC-026 の復旧が受け持つ建て付けだが、上記のとおりその復旧はこの形には発動しない。
- 鍵なし再駆動（PR #19、revision 27）: initiateCheck 内。前回の試行が「Running でなく、URL の提示もなく」閉じた場合に、次回の確認で鍵なし login() を呼び対話 URL を出させる。発動は認証つき /api/status の読み込み、または /node-check（ダッシュボードのボタン）からのみ。鍵なし /health や /public-status からの起動では発動しない。

## 4. 履歴の事実（SPEC 変更履歴、docs/RECOVERY.md）

- 2026-11-16 13:27: 状態破棄と TS_AUTHKEY での再参加により Running へ復旧（receiverResolved true まで確認）。この時点で鍵での参加は成立していた。
- 2026-11-16 19:44〜19:49: 再発。muse-vm の netmap から muse-monitor が消えていることを実測（前提は REQ-SEC-036 に記録）。登録が消えた理由（削除、期限、ephemeral キーによる自動削除）は未確認。
- revision 16: REQ-SEC-036 を実装しデプロイしたが実経路で悪化した。復旧は発動して状態を破棄したものの、認証キーでの再参加が完了せず、新しいデバイスが netmap に現れなかった（登録が control に届いていない）。対話ログイン URL も提示されなかった。revision 15 へロールバックし、REQ-SEC-036 は保留となった。再開の条件は「鍵での参加が 13:27 には成功したのに現在は完了しない理由の特定」。
- revision 17: revision 16 の失敗した再参加が残した状態を、epoch 判定による一回限りのリセットで破棄した（その状態は復帰すると無言の NeedsLogin ループになり URL も提示されなかった）。
- 2026-11-18: Okiraku の判断で、「URL 提示のない NeedsLogin の時間切れ」を復旧対象に広げるのはモードが「自動」の場合に限り、状態の指紋ごとに1回限り（REQ-SEC-048）と確定した。初期値は「手動」で、その間は広げない。この実装（v19）は未マージで、main には入っていない。
- SPEC 前提 P8（2026-11-18 実測で確認済み）: 現在の固着は URL 提示のない形で起きており、REQ-SEC-036 の発動条件にも該当せず、現行の復旧（REQ-SEC-026〜028、036）のどれも発動しない。本調査の実測はこの前提と一致する。

## 5. 未特定の層と切り分け

残る未特定は1層だけである: 認証キーでの login（および破棄後の新規登録）が、なぜ control 側の登録にも対話 URL の発行にも至らないのか。revision 16 の時点で「登録が control に届いていない」ことまでは実測されているが、その理由は確定していない。

切り分け手順（未実施）:

1. 認証つき /api/status を読み、DO が返す ipn.status() の中身（バックエンド自身の状態、AuthURL の有無、自ノード情報）を確認する。あわせて起動記録の直近20件（認証つきでのみ露出）で、状態破棄の記録と試行の内訳を確認する。
2. ダッシュボードのボタン（/node-check）から鍵なし再駆動（PR #19）を1回実行し、起動記録に対話 URL の提示が記録されるかを見る。
   - URL が提示される → 詰まりは鍵つき login の経路にあり、対話ログインで復旧できる。
   - URL が提示されない → 詰まりは鍵でも状態でもなく、ノードの control セッション自体（WASM ノードから control への到達、または control 側での当該ノードの扱い）にある。この場合、状態を破棄しても revision 16 と同じ結果になる公算が高い。
3. どちらの結果でも、状態破棄と再参加を自動で繰り返さない（docs/RECOVERY.md の禁止事項）。

## 6. 検証区分

- 実物で確認（real-verified）: §2 のすべて（/health、起動記録、netmap）。§4 の 13:27 復旧と 19:49 消失は当時の実測記録に基づく。
- コードで確認（code-verified）: §3 のすべて（main 6eafcab の src/do.ts を読んだ）。
- テストで確認（test-verified）: 本調査では新規のテストは実行していない。既存の AC-SEC-031〜034（PR #18 の実経路確認）は未実施のまま。
- 未確認（unverified）: §5 の層。PR #19 の鍵なし再駆動がデプロイ後に本番で発動したかどうか（起動記録の遷移が空の2件は、生成済みノードへの再駆動と形が一致するが、確定はできない）。

## 7. 復旧確認とクローズ（2026-11-21）

**解決済み。** [PR #21](https://github.com/nekoserver/muse-monitor/pull/21) のコミット `59f69af` で、Tailscale ノードが未ログインのとき、認証済みの監視画面に対話ログインの承認リンクを表示し、期限切れ後も再発行できるようにした。

- **利用者の確認**。監視画面のリンクを開き、所属する tailnet のアカウントを選択すると、ノードがログイン済みの表示に変わった。
- **本番の確認**。公開 `/health` の revision 30 で `node.node = Running`、`loginPending = false`、`receiverResolved = true` を確認した。直近の起動記録は `outcome = running` だった。
- **残る調査事項**。初回の Tailscale 登録消失と、認証キー付きの再参加が完了しなかった理由は未特定。今回の障害は、対話ログインの実操作と受信側への到達を確認したためクローズする。
