## ADDED Requirements
### Requirement: Poseidon permutation reuse
XMSSゲスト検証は Poseidon2 (16レーン/24レーン) パーミュテーションを検証ループ外で初期化し、WOTSチェーン進行・Merkle認証・メッセージハッシュで共有しなければならない。この検証ロジック SHALL NOT 再帰的に `default_koalabear_poseidon2_*` を生成し直し、同一バッチ内では同一インスタンスを使い回して Poseidon ステート初期化のオーバーヘッドを排除しなければならない。

#### Scenario: guest reuses Poseidon builders
- **GIVEN** `cargo openvm run --mode meter --input guest/input.json` を実行して単一バッチを検証する
- **WHEN** WOTS チェーン `walk_chain` と `hash_tree_verify` が多数の Poseidon 圧縮を行う
- **THEN** それぞれの呼び出しは事前に確保された Poseidon2 コンテキストを共有し、新しい `Poseidon2KoalaBear` を都度生成しないため、命令数・セル数は再利用前の実装より減少する
