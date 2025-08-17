# XMSS 検証プローブ計画（TSL）

## 目的
OpenVM 内で XMSS 検証の正当性を証明する。ゲストは TSL で符号化された XMSS 署名のバッチを検証し、公開値として合否と件数を開示する。ホストはビルド・鍵生成・証明・検証を駆動する。

## コンポーネントと担当
- guest/: SHA-256 と TSL マッピングを用いる no_std 検証プログラム。
- shared/: 入出力およびパラメータ用の no_std 型。
- host/: 入力をエンコードし `cargo openvm` を呼ぶ CLI。

## データモデル（shared/src/lib.rs）
- 既存型:
  - `CompactSignature { leaf_index: u32, randomness: [u8;32], wots_signature: Vec<[u8;32]>, auth_path: Vec<[u8;32]> }`
  - `CompactPublicKey { root: [u8;32], seed: [u8;32] }`
  - `VerificationInput { signatures: Vec<CompactSignature>, messages: Vec<Vec<u8>>, public_keys: Vec<CompactPublicKey> }`
- 追加:
  - `TslParams { w: u16, v: u16, d0: u32, security_bits: u16 }`（no_std・Serialize/Deserialize）
  - `VerificationBatch { params: TslParams, input: VerificationInput }`

## OpenVM 設定と依存関係
- ゲスト VM 構成（`guest/openvm.toml`）
  - 高速ハッシュのため SHA-256 拡張を有効化: `[app_vm_config.sha256]`
  - `rv32i`, `io`, `rv32m` は維持。Keccak は任意。
- 依存関係（`guest/Cargo.toml`）
  - OpenVM 本体と SHA-256 ゲストライブラリを追加（必要に応じてタグ固定）:
    - `openvm = { git = "https://github.com/openvm-org/openvm.git", default-features = false }`
    - `openvm-sha2 = { git = "https://github.com/openvm-org/openvm.git" }`

## ゲスト実装（guest/src）
- main.rs（no_std, no_main）
  - 読み取り: `let batch: VerificationBatch = openvm::io::read();`
  - 呼び出し: `let (valid, checked) = xmss_verify::verify_batch(&batch);`
  - 開示: `openvm::io::reveal_u32(valid as u32, 0); openvm::io::reveal_u32(checked as u32, 1);`
- tsl.rs（no_std）
  - `pub struct TslParams { .. }`
  - `fn hash_message_randomness(msg: &[u8], rnd: &[u8]) -> [u8;32]`（`openvm_sha2::sha256` を使用）
  - `fn le_u64_of_first_8(bytes: &[u8;32]) -> u64`
  - `pub fn encode_vertex(msg: &[u8], rnd: &[u8], p: &TslParams) -> Result<Vec<u16>, MappingError>`
  - `fn map_to_layer(index: u64, p: &TslParams) -> Result<Vec<u16>, MappingError>`
  - `fn integer_to_vertex(index: usize, w: usize, v: usize, d0: usize) -> Result<Vec<u16>, MappingError>`（上限制約付き合計 d0 の組成を DP で rank/unrank）
- hash.rs（no_std）
  - `openvm_sha2::sha256`/`set_sha256` を直接使用。補助関数のみ実装:
    - `fn sha256_bytes(input: &[u8]) -> [u8;32] { openvm_sha2::sha256(input) }`
    - `fn hash_message_randomness(msg: &[u8], rnd: &[u8]) -> [u8;32]`（`msg||rnd` を連結して `sha256`）
- merkle.rs（no_std）
  - `fn compute_root(leaf: [u8;32], auth_path: &[[u8;32]]) -> [u8;32]`（インデックスのビットで左右を決定）
- wots.rs（no_std）
  - `fn wots_pk_from_sig(sig: &[[u8;32]], steps: &[u16], w: u16) -> [[u8;32]; V]`（`w-1-steps[i]` 回の前進ハッシュ）
  - `fn leaf_from_wots_pk(pk: &[[u8;32]]) -> [u8;32]`（要件に応じて連結ハッシュ/小マークル）
- xmss_verify.rs（no_std）
  - `pub fn verify_one(p: &TslParams, sig: &CompactSignature, msg: &[u8], pk: &CompactPublicKey) -> bool`
  - `pub fn verify_batch(batch: &VerificationBatch) -> (bool, u32)`（全て OK か/件数）

注意
- 確保を抑え、バッファ再利用でメモリを節約。
- ハッシュは全て `openvm-sha2`（`openvm_sha2::sha256`/`set_sha256`）を使用。ホスト乱数は使わない。

### 参考コード（ハッシュ結合）
```rust
use openvm_sha2::sha256;

fn hash_message_randomness(msg: &[u8], rnd: &[u8]) -> [u8; 32] {
    let mut buf = alloc::vec::Vec::with_capacity(msg.len() + rnd.len());
    buf.extend_from_slice(msg);
    buf.extend_from_slice(rnd);
    sha256(&buf)
}
```

## ホストワークフロー（host/src）
- CLI 拡張:
  - `prove --input input.json --output <proof>`: `VerificationBatch` を OpenVM バイト規則で直列化。
  - `verify --proof <file>`: `cargo openvm verify app` を呼ぶ。
- OpenVM 直列化:
  - LE・4 バイトパディング・各入力ストリーム先頭に `0x01` の形式。
  - `guest/input.json` 例: `{ "input": ["0x01<hex of VerificationBatch>"] }`。

## ビルド/証明/検証コマンド
- ゲストビルド: `cd guest && cargo openvm build`
- 鍵生成: `cargo openvm keygen`
- アプリ証明: `cargo openvm prove app --input guest/input.json`
- アプリ検証: `cargo openvm verify app`
- 任意の EVM（重い初期化）: `cargo openvm setup` 後に `prove evm`/`verify evm`

## テストと検証
- ゲスト実行（非証明）: `cargo openvm run --input guest/input.json` で動作確認。
- 単体テスト（no_std 想定）: 小さな `w,v,d0` で DP マッピング/WOTS/Merkle を検証。
- ゴールデンベクトル: 正常 1–2 件、改ざん経路による失敗 1 件。

## マイルストーン
1) ゲスト TSL マッパ + 小パラメータテスト。
2) 単一署名の WOTS+Merkle 検証（run モード）。
3) バッチ検証 + 公開値。
4) ホストエンコーダ + アプリ証明の E2E。
5) 任意: EVM 証明経路。

## リスクと対策
- TSL マッピングの不一致: LE u64 抽出と層制約を仕様通りに固定し、単体テストとゴールデンベクトルで検証。
- 大きな N/深い経路によるメモリ圧: 上限パラメータ化・必要ならストリーミング。
- no_std 制約: std 依存は host に分離、guest は no_std+alloc に限定。

## 入力 JSON 例（スケッチ）
```json
{
  "input": [
    "0x01<hex-encoded VerificationBatch serialized with OpenVM serde>"
  ]
}
```

## 関数シグネチャ（要約）
- guest::tsl::encode_vertex(msg, rnd, &TslParams) -> Result<Vec<u16>, MappingError>
- guest::wots::wots_pk_from_sig(sig: &[[u8;32]], steps: &[u16], w: u16) -> [[u8;32]; V]
- guest::merkle::compute_root(leaf: [u8;32], auth: &[[u8;32]]) -> [u8;32]
- guest::xmss_verify::verify_one(params, sig, msg, pk) -> bool
- guest::xmss_verify::verify_batch(batch) -> (bool, u32)
