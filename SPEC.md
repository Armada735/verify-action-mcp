# 02: verify_action — 技術仕様

## 1. 提供するインターフェース

agent が呼べる形を 2 つ用意:

### 1.1 MCP tool 形式（推奨、agent native）

agent ハーネスが `verify_action` を tool として discover/invoke できる:

```json
{
  "name": "verify_action",
  "description": "Third-party verification: confirm whether an agent's claim about completing an action matches the supplied evidence. Returns { verdict, reasoning, confidence }.",
  "inputSchema": {
    "type": "object",
    "properties": {
      "claim": { "type": "string", "description": "What the agent claims it did, in natural language." },
      "evidence": { "type": "object", "description": "Concrete evidence: file diffs, DB row counts, API response, etc." },
      "kind": {
        "type": "string",
        "enum": ["code_diff", "db_op", "file_op", "api_call", "generic"],
        "description": "Optional kind hint to dispatch the right verifier."
      },
      "context": { "type": "string", "description": "Optional brief context about the task." }
    },
    "required": ["claim", "evidence"]
  }
}
```

### 1.2 REST 形式（万人が叩けるよう）

```
POST /verify
Content-Type: application/json
{
  "claim": "...",
  "evidence": {...},
  "kind": "...",        // optional
  "context": "..."      // optional
}
```

レスポンス:
```json
{
  "verdict": "ok" | "mismatch" | "uncertain",          // legacy 3-value (alias)
  "aar_verdict": "verified" | "contradicted" |          // canonical 4-value
                 "insufficient_evidence" | "unsafe_to_verify",
  "reasoning": "Human-readable explanation, 1-3 sentences.",
  "confidence": 0.0-1.0,
  "verifier_used": "code_diff_v1" | "db_op_v1" | "file_op_v1" | "api_call_v1" | "generic_v1",
  "kind_dispatched": "code_diff" | "db_op" | "file_op" | "api_call" | "generic",
  "receipt": {                                          // verify_action_receipt.v0
    "schema": "verify_action_receipt.v0",
    "claim_hash": "sha256:...",
    "evidence_manifest_hash": "sha256:...",
    "verifier_id": "verify-action-mcp@<version>",
    "verifier_method": "rule_based.<kind>",
    "verdict": "<aar_verdict>",
    "confidence": 0.0-1.0,
    "reason_codes": ["..."],
    "issued_at": "<UTC ISO>",
    "issued_by": "aar:reference-impl@v0",
    "kid": "v0-default",
    "signature": "hmac-sha256:<base64>"
  }
}
```

The receipt is HMAC-attested: it asserts that this AAR instance issued this
verdict over these claim/evidence hashes at this time. It does NOT assert
that the underlying claim is factually true or legally admissible.

`verdict` is preserved as the legacy 3-value field for back-compat with
early callers; new integrations should consume `aar_verdict` (4 values).
The mapping is: ok → verified, mismatch → contradicted, uncertain →
insufficient_evidence, rejected → unsafe_to_verify.

---

## 2. Verdict 判定ロジック（Phase 1: rule-based のみ）

LLM-as-judge は Phase 2 以降。Phase 1 は **タスク種別ごとの専用 verifier** で構造比較する。

### 2.1 `code_diff` verifier

入力 example:
```json
{
  "claim": "Added a null check for user.email in src/user.py",
  "evidence": {
    "diff": "@@ -42,3 +42,5 @@\n def get_email(user):\n+    if user is None:\n+        return None\n     return user.email"
  }
}
```

判定ロジック:
- `claim` から keyword 抽出（"null check", "user.email", "src/user.py"）
- `evidence.diff` を parse して:
  - 言及されたファイル（`src/user.py`）が触られているか
  - 言及された変数（`user.email`）が登場するか
  - claim の動詞（"Added"）と diff の構造が整合するか
  - 想定外の変更（複数ファイル / 大規模追加削除）がないか
- 結果:
  - すべて整合: `verdict: ok, confidence: 0.85+`
  - 一部不整合（例: claim が単一だが diff は複数ファイル）: `verdict: mismatch, reasoning: "Claim mentions only src/user.py but diff modifies 3 files"`
  - 不明（diff が parse 不能、claim が抽象的）: `verdict: uncertain`

### 2.2 `db_op` verifier

入力 example:
```json
{
  "claim": "Deleted user with id=12345",
  "evidence": {
    "before_count": 1500,
    "after_count": 1499,
    "operation": "DELETE FROM users WHERE id=12345",
    "affected_rows": 1
  }
}
```

判定ロジック:
- 期待される行数変化（DELETE: -1, INSERT: +1, UPDATE: 0）と `before_count - after_count` が整合
- `affected_rows` が claim の数と整合
- SQL operation が claim の動詞と整合（"deleted" → DELETE）
- claim 内の id / 条件が SQL operation 内に含まれる
- 結果は同様に ok/mismatch/uncertain

### 2.3 `file_op` verifier

入力 example:
```json
{
  "claim": "Created a new file at /tmp/report.txt with 200 lines",
  "evidence": {
    "path": "/tmp/report.txt",
    "exists_before": false,
    "exists_after": true,
    "line_count": 200,
    "size_bytes": 12345
  }
}
```

判定ロジック:
- ファイル状態の変化が claim の動詞と整合（"Created" → exists: false→true）
- 行数 / サイズ等の数値が claim と整合
- パスが claim の path と完全一致

### 2.4 `api_call` verifier

入力 example:
```json
{
  "claim": "Successfully sent email to user@example.com",
  "evidence": {
    "request": {"to": "user@example.com", "subject": "..."},
    "response_status": 200,
    "response_body": {"id": "msg_123", "status": "sent"}
  }
}
```

判定ロジック:
- HTTP status が 2xx
- response_body の status が "sent" / "ok" / "success" 等
- request 内のターゲット（email など）が claim 内のターゲットと一致

### 2.5 `generic` verifier

`kind` が指定されない or 上記いずれにも当てはまらない場合の fallback:
- `claim` 内の固有名詞・数字・動詞を抽出
- `evidence` を JSON フラット化、各値を文字列化
- claim の固有名詞が evidence に出現するかチェック
- claim と evidence の意味的一致は保証できないので `uncertain` を多く返す（confidence < 0.5）

これは Phase 1 では弱い（LLM 不使用ゆえ）が、Phase 2 で claude -p ベース判定に置き換え可能。

---

## 3. Confidence の算出

各 verifier 内で正の signal と負の signal の合計から:
```
confidence = clamp(0.5 + 0.1 * positive_signals - 0.15 * negative_signals, 0.0, 1.0)
```
具体閾値:
- `verdict: ok`: confidence ≥ 0.7
- `verdict: mismatch`: 強い不整合 signal が 1 個以上
- `verdict: uncertain`: 上記いずれにも当てはまらない、または rule で判定できない

---

## 4. テレメトリ（蓄積データ）

`traces/traces-YYYY-MM-DD.jsonl` に append:

```jsonl
{
  "ts": "2026-05-01T11:35:00Z",
  "trace_id": "16char_hex",
  "ip_hash": "16char_hex",
  "user_agent": "...",
  "kind": "code_diff",            // dispatched verifier
  "verifier_used": "code_diff_v1",
  "verdict": "ok",
  "confidence": 0.88,
  "claim_length": 124,            // chars
  "evidence_keys": ["diff"],      // top-level keys of evidence
  "evidence_size_bytes": 567,
  "latency_ms": 23,
  "untrusted_payload": {          // sanitized
    "claim": "...",                // truncated to 8KB
    "evidence_keys_with_types": {"diff": "string", "files": "array"},
    "kind": "code_diff",
    "context": "..."               // truncated
  }
}
```

**保存しないもの**:
- 生 IP（hash で十分）
- evidence の full content（**option**: 「ユーザーが opt-in した場合のみ trace 保存」を Phase 2 で検討）
- API キーや credential（claim/evidence にあっても自動マスク）
- model fingerprint（user-agent だけ）

`responses/NOTICE.md` を置き、analyzer 向けに「これは untrusted user input」を明示（survey-box と同じ方針）。

---

## 5. API 全エンドポイント

| Method | Path | 用途 | 備考 |
|---|---|---|---|
| GET | `/` | About ページ | 透明性 |
| GET | `/about` | 同上 | |
| GET | `/healthcheck` | 生死確認 | cron 用 |
| GET | `/spec` | この SPEC のサマリ + JSON Schema | 透明性 |
| GET | `/rules` | 検出ルール詳細（rule-based 部分） | 透明性 |
| POST | `/verify` | 検証 API（REST） | rate-limit per ip_hash |
| POST | `/mcp` | MCP JSON-RPC 受信口 | stdlib 実装 |
| GET | `/stats` | 公開統計（verdict distribution 等） | aggregation only |

---

## 6. MCP プロトコル対応（最小実装）

MCP は JSON-RPC 2.0 over HTTP / stdio。Phase 1 では HTTP transport のみ対応。

実装する method:
- `initialize`: 初期化応答
- `tools/list`: `verify_action` ツール定義を返す
- `tools/call`: `verify_action` を実行 → POST /verify と同等の処理

stdlib `http.server` + JSON-RPC ルーターで実装。実装は `server.py` 参照。

---

## 7. Phase 2 マネタイズ路（実装はしない、SPEC として残す）

### 路線 (i): aggregated behavior intelligence
蓄積トレースから「モデル × タスク種別 × verdict 分布」を四半期レポート化、enterprise governance buyers に license。

### 路線 (ii): premium verification SLAs
Phase 1 の rule-based + Phase 2 の LLM-as-judge を組合せ、SLA ($99/mo)。同時 30 並列、優先 queue。

### 路線 (iii): dataset license to AI labs
匿名化トレースを academic / commercial researchers に license。eval set として使う動機がある。

### 路線 (iv): governance certification
特定 agent harness について「certified by toA」の信頼マーク発行。enterprise 採用判断の助けに。

---

## 8. Phase 1 で「やらない」こと（明示）

- LLM-as-judge は使わない（コスト + 複雑さ）
- ユーザー登録・課金フロー
- リアルタイム dashboard
- Webhook / async 通知（同期 REST のみ）
- 複数 verifier の連結（chain of verifiers）
- 生 evidence の保存（プライバシー配慮）
- pull-from-trace replay（Phase 2 で）

これらは Phase 2 mvp の検討対象。
