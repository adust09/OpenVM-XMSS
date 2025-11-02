# hash-sig API 調査メモ

## 主要 API

- `SignatureScheme` トレイトが公開インターフェイス。
  - 関連型 `PublicKey` / `SecretKey` / `Signature` は `Serialize` + `DeserializeOwned` 必須。
  - 定数 `LIFETIME`（2 の冪）が利用可能なエポック数を表す。
  - `key_gen(rng, activation_epoch, num_active_epochs)`：エポック範囲を指定して鍵生成。範囲が `LIFETIME` を超えると `assert!` で異常終了。
  - `sign(rng, &sk, epoch, message)`：`Result<Signature, SigningError>`。内部のエンコードが最大 `MAX_TRIES` 失敗すると `SigningError::EncodingAttemptsExceeded` を返す。`epoch` は `u32`。
  - `verify(&pk, epoch, message, &sig)`：署名検証を行い `bool` を返す。
  - `internal_consistency_check()`（テスト限定）：パラメータ整合性の自己診断。
- `MESSAGE_LENGTH = 32`。署名対象メッセージは固定長 `[u8; 32]`。
- 具体的な XMSS インスタンスは `signature::generalized_xmss::instantiations_*` に型エイリアスとして定義（例：`instantiations_sha::...::SIGWinternitzLifetime18W4`）。
- 秘密鍵内部で Merkle 木・ハッシュチェーンを保持し、`key_gen`/`sign` では `rand` 0.9 系 RNG を要求。
- 公開キー／署名のフィールドは非公開（bincode などのシリアライズ経由で扱う想定）。

## 課題・懸念点

1. **メッセージ長固定 (32 バイト)**
   - 現在のワークフローは任意長メッセージ (`Vec<u8>`) を想定している。
   - `hash-sig` では 32 バイト固定のため、ハッシュ化などで 32 バイトに落とし込む設計が必要。

2. **エポック管理が呼び出し側責務**
   - 旧ラッパーのような OTS インデックス自動管理は提供されない。
   - 秘密鍵 + epoch の組み合わせは一度きりの使用前提。ラッパーでエポック進行を管理する仕組みを検討する必要がある。

3. **`sign` が確率的失敗し得る**
   - `SigningError::EncodingAttemptsExceeded` が返る可能性がある。
   - CLI/テスト/ベンチでのリトライ方針やエラー処理を決めておく必要がある。

4. **署名・公開鍵構造がブラックボックス**
   - フィールドが公開されていないため、`xmss-types` との変換はシリアライズ経由になる。
   - 既存 `xmss-types::Signature`（`wots_chain_ends`, `auth_path` など）とは直接整合しない。型の再設計または中間フォーマットの導入が必要。

5. **ゲスト実装の全面差し替えが必要**
   - 現状のゲストはハイパーキューブ XMSS 固有の検証手順を実装している。
   - hash-sig の署名形式に合わせてゲストの検証ロジックや証明データの構造を再構成する必要がある。

6. **`hashsig` は `std` 依存**
   - `rayon` や `dashmap` を利用しており `no_std` 非対応。
   - ゲストで直接利用することはできないため、ホスト側での処理完結やデータ形式の再検討が必要。

7. **パラメータ選定（LIFETIME, w など）の影響**
   - 旧デフォルト（例：木高さ 10）に相当するインスタンスを選ぶ必要がある。
   - `num_active_epochs` 設計、鍵生成コスト、署名サイズの変化を事前に把握しておく。

8. **`rand` 0.9 系 API への追従**
   - 旧コードは `rand` 0.8 系を想定している部分がある。
   - ラッパーでは `rand::rng()` など新 API に合わせた RNG 生成・注入方法が必要。

## 当面の検討優先事項

- メッセージ長 32 バイト制約への対応策（ハッシュ化の標準化など）。
- エポック管理ポリシーの設計（同期・永続化含む）。
- `xmss-types` およびゲストとのデータモデル再設計方針を決定する。
