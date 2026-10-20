# app-kms（アクセスポリシー）— itonami（dapp）上の分散型設計

状態: 第 1 スライス実装（2026-10-20）。正本はこの文書。
追跡: Linear JUN-128（親 JUN-116）。

## 位置づけ

app-kms は **kagitaba KMS**（kagitaba.kotoba.cloud）—— kagitaba keychain
項目の署名付きアクセスポリシー（ES256 JWT）を発行・version・revoke する
単体 Cloudflare Worker + KV。kagitaba 本体（cljc）は zero-dep のまま、
ホスト面はこの repo。

## このスライス: ポリシー判定コア

| 層 | 実体 | 状態 |
|---|---|---|
| 判定コア guest | `aiueos/kms_policy.cljk` — issue-judgment（`kagitaba://` 14 文字以上 / recipient は `did:<lower-alnum>:` 形 / 署名鍵未設定は 503）/ auth-judgment（read は public、mutation は ADMIN_TOKEN、secret 未設定は 503 misconfigured）/ chain-judgment（append-only・supersededBy 記録・**revoked head は mutation を 404 で拒む**）/ dedup-take（同一 canonical は既存再利用） | **実装済み・実測** |
| 記述子 | `aiueos/kms-policy.edn` | **実装済み** |
| parity | `worker/test/policy_parity.mjs` — **正本 Worker を node で直接実行**（mock KV + 実 ES256 鍵生成）し全経路を照合 | **実装済み・実測** |

実測: `amu test aiueos/kms_policy.cljk` → **33/33**（jvm-kir / js / wasm）。
parity → **all pass**（503 misconfig / 401 / issue / dedup / 検証拒否 /
addRecipient の chain（supersedes 記録）/ chain-follow / revoke /
revoked mutation 404）。

## 正本の正確な規則（guest はこれに追従）

- **CID は canonical から決定的**: `kms-sha256-<hex>` over
  `{resourcePattern, recipients(sorted,deduped), issuer}` —— 順不同・重複
  あっても同一 canonical は同一 CID → **re-issue は dedup して既存 JWT を返す**
  （実測: recipients を入れ替え・重複させても同一 CID）。
- **version chain は append-only**: add/removeRecipient は新 CID を作り、
  旧 head に `supersededBy` / 新側に `supersedes` を記録。**旧記録は書き換えない**。
  getAccessPolicy は chain 上のどの CID でも head に着地する（実測）。
- **revoke は tombstone**。revoked head への mutation は **404**（実測）。
- **read は public / mutation は ADMIN_TOKEN**（constant-time 比較）。
  secret 未設定は **503 misconfigured**（fail closed。実測）。

## 実測メモ（parity 実行で判明した API 細目）

- `addRecipient` の body キーは `did`（`recipientDid` ではない）。
- 発行成功は 201、revoke 成功は `{ok: true, policyCid, revoked: true}`。
- KV の `get(k, "json")` 慣習 —— mock は type 引数で JSON.parse を再現する必要
  があった（workerd の挙動に合わせる）。

## 未実装境界

- JWT 署名・JWK エクスポート（`jwk.d` 剥奪の実装含む）と constant-time 比較は
  host（Worker / WebCrypto）。
- policyJwt の検証（発行側と検証側の一致）の判定は別スライス候補。
- kagitaba（cljc zero-dep）側の item 判定。
- mon（DNA）化、aiueos session 載せ（fleet 共通）。
