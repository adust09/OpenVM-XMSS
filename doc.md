# XMSS ゲスト実装 仕様書（TSL + OpenVM）

## 概要
- 目的: OpenVM 上で XMSS 署名検証を実行し、その実行結果（合否・検証件数）に対するアプリケーションレベルの証明を生成・検証する。
- 実装範囲: ゲストは no_std で動作し、TSL（Top Single Layer）エンコーディングに基づく WOTS ステップ導出、WOTS 公開鍵ハッシュ算出、ドメイン分離付き Merkle 認証を行う。
- 依存: `openvm`（ゲスト I/O・serde・entry）、`openvm-sha2`（SHA-256 アクセラレーション）。

## 構成・主要ファイル
- `guest/`
  - `src/main.rs`: OpenVM エントリ。`VerificationBatch` を読み、`xmss_verify::verify_batch` の結果（合否・件数）とステートメントコミットメントを `reveal_u32` で公開。
  - `src/hash.rs`: `openvm_sha2::{sha256, set_sha256}` ラッパ。`hash_message_randomness` など。
  - `src/tsl.rs`: TSL マッピング（H(ep||m)→LE u64→層 d0 のベクトルへの対応、DP による unranking）。
  - `src/xmss_verify.rs`: WOTS チェーンの前進ハッシュ、公開鍵ハッシュ、Merkle ルート算出と比較、バッチ検証、`statement_commitment` 計算。
  - `openvm.toml`: `[app_vm_config.sha256]` を有効化。
- `shared/src/lib.rs`: 共有型（no_std）。
  - `CompactSignature { leaf_index, randomness, wots_signature, auth_path }`
  - `CompactPublicKey { root, seed }`
  - `Statement { k, ep, m, public_keys }`
  - `Witness { signatures }`
  - `TslParams { w, v, d0, security_bits, tree_height }`
  - `VerificationBatch { params, statement, witness }`
- `host/src/bin/`
  - `gen_input.rs`: 空バッチの入力 JSON を生成。
  - `gen_fail.rs`: 失敗ケース用の 1 件バッチを生成。
  - `run_check.rs`: `cargo openvm run` を呼び、公開出力（u32×2）を検証。

## 入出力仕様
- 入力: `VerificationBatch`
  - `params`: `TslParams`（TSL と XMSS の最小パラメータ）
    - `w`: Winternitz 基数 (>1)
    - `v`: TSL 次元 (>0)。WOTS チェーン数に一致
    - `d0`: TSL レイヤ（0..=v*(w-1)）
    - `security_bits`: 参考用（128/160 など）
    - `tree_height`: Merkle 高さ（`auth_path.len()` と一致）
  - `statement`: `Statement`
    - `k`: 署名者数
    - `ep`: エポック（u64）
    - `m`: 単一メッセージ（全署名に共通）
    - `public_keys`: `CompactPublicKey` の配列
  - `witness`: `Witness`
    - `signatures`: `CompactSignature` の配列
- シリアライズ: `openvm::serde::to_vec`（u32 ワード列）。JSON 入力は `{"input":["0x01<LE バイト列 hex>"]}`。
- 公開出力（user public values）: u32 little-endian
  - `index 0`: `all_valid`（1: すべて妥当、0: いずれか失敗）
  - `index 1`: `num_verified`（検証した件数）
  - `index 2..9`: `stmt_commit`（`H(k||ep||len(m)||m||len(pks)||pk[..])` の 256bit、LE u32×8）

## アルゴリズム仕様
1) TSL ステップ導出（`tsl.rs`）
   - ドメイン: `ep||m` をバイト列として連結。
   - インデックス: ハッシュ先頭 8 バイトを little-endian `u64` として解釈。
   - マッピング Ψ: `integer_to_vertex(index % ℓ_d, w, v, d0)` で、各成分が `[0, w-1]`、総和が `d0` の長さ `v` ベクトルを lexicographic に unrank。
   - 実装: DP により `ℓ_d` を計数（u128）。大規模パラメータで飽和の可能性あり（既知の制限）。

2) WOTS チェーン前進（`xmss_verify.rs`）
   - 各チェーン i について、署名要素 `sig[i]` を `t_i = (w-1 - steps[i])` 回 `SHA-256` で前進ハッシュ。
   - すべてのチェーン結果を連結し、`leaf = SHA-256(concat(chains))` を計算（L-tree ではなく単一ハッシュ）。

3) Merkle ルート算出（ドメイン分離あり）
   - 各高さ h で、兄弟ノードと左右順序（`(leaf_index >> h) & 1`）に応じた `left`,`right` を決定。
   - ノードハッシュ: `H(0x01 || public_seed || height_be || parent_index_be || left || right)`
     - `public_seed`: `CompactPublicKey.seed`
     - `parent_index = leaf_index >> (h+1)`
   - 最終ノード（ルート）を `CompactPublicKey.root` と比較。

## 妥当性チェック
- `w > 1`, `v > 0`
- `wots_signature.len() == v`
- `auth_path.len() == tree_height`
- いずれか不一致の場合は当該要素を失敗とし、`all_valid` に反映。

## コマンド
- ビルド（ゲスト）: `cd guest && cargo openvm build`
- 実行（ランモード）: `cargo openvm run --input input.json`
- 鍵生成: `cargo openvm keygen`
- アプリ証明生成: `cargo openvm prove app --input input.json`
- アプリ証明検証: `cargo openvm verify app`

## テスト
- ユニットテスト
  - `tsl.rs`: 小パラメータでの DP/unranking、決定性の検証。
  - `xmss_verify.rs`: ドメイン分離付き Merkle ノードハッシュの検証（2 階層）。
- 統合テスト（ランモード補助）
  - `gen_input`: 空バッチ → `valid=1, count=0`
  - `gen_fail`: 偽署名 1 件 → `valid=0, count=1`
  - `run_check`: 実行結果をパースし、期待値と `stmt_commit` の一致を検証。

## 既知の制限 / 今後の課題
- TSL の DP 実装は大規模パラメータで計数が u128 を超える可能性（フォールバック（ハッシュベース）未実装）。
- WOTS 公開鍵の圧縮は `H(concat)` を採用。L-tree を用いる実装と互換が必要な場合は差し替えが必要。
- 署名生成（サイナー）は本リポジトリに含めていないため、真に妥当なベクトルを用いた正の統合テストは外部生成に依存。
- EVM 証明は重いセットアップ（`cargo openvm setup`）が必要。現状はアプリレベル証明での検証を想定。
