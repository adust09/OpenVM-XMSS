# Optimize Poseidon Permutation Reuse

## Motivation
Benchmark結果では、XMSSゲスト検証の総セル数の約88%が `poseidon_apply` を通じたパーミュテーション生成に費やされている。各WOTSチェーンおよびMerkle段ごとに `default_koalabear_poseidon2_*` を再構築しており、命令数・メモリ使用量の両方が増大している。単一ラン内で Poseidon インスタンスを再利用し、内部状態の再構築を避ける仕様が必要。

## Proposal
- Poseidonパーミュテーション（16要素・24要素双方）を検証ループ外で初期化し、XMSS検証中は共有参照を使い回す。
- 仕様で、ゲスト実装がチェーン進行や Merkle 認証のたびに新規インスタンスを生成してはならないことを明示する。
- これにより Poseidon 呼び出しあたりの初期化コストが削減され、OpenVM証明のトレース長を縮小させる。

## Impact
- ゲスト(`xmss-guest`)の検証パスが大幅に効率化され、`cargo openvm run --mode meter` でのセル数削減が見込まれる。
- API 互換性は維持されるが、Poseidonインスタンス管理の責務が追加される。

## Metrics / Validation
- 2署名ベンチ (`cargo run -p xmss-host -- benchmark`) での `prove` 時間短縮。
- `cargo openvm run --mode meter --input guest/input.json` にてセル数が現状 (約1.04B) より減少すること。
