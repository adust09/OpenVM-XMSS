## 1. Specification
- [x] 1.1 `xmss-hashsig` スペックに Poseidon パーミュテーションの再利用要件とシナリオを追加する。

## 2. Implementation
- [x] 2.1 ゲスト検証ロジックで Poseidon2 インスタンスを初期化・共有し、チェーン／Merkle パスの呼び出しごとに再生成しないよう更新する。
- [x] 2.2 `cargo openvm run --mode meter` や `cargo run -p xmss-host -- benchmark` で改善を確認し、proposal に記載した指標の成果を報告する。
