## ADDED Requirements
### Requirement: Benchmark-only fake XMSS keys
ベンチマークや負荷試験を行う CLI は、WOTS 部のみ正規に生成し Merkle 経路を乱数で埋める「偽鍵」モードを提供してもよい。偽鍵モードは明示的なフラグでのみ有効化しなければならず (SHALL NOT be enabled implicitly)、本番ワークフローでは偽鍵を使用してはならない (SHALL NOT)。偽鍵で生成した署名・公開鍵は `xmss-types::VerificationBatch` と互換であり、ゲスト検証が本来のフォーマットと同じ構造を期待できること (SHALL remain serialization-compatible)。ベンチ CLI は偽鍵使用時でも WOTS 署名計算に `hashsig::SignatureScheme::sign` を用いる一方、Merkle 経路のシリアライゼーション整合性だけを保持すればよい。

#### Scenario: benchmark CLI opts into fake keys
- **GIVEN** 開発者が `cargo run -p xmss-host -- benchmark --fake-keys` を実行する
- **WHEN** 入力生成ステップが大量の XMSS 署名を作成する
- **THEN** CLI は WOTS 秘密鍵＋乱数メルクル経路で高速に署名を作り、生成したバッチはゲストで検証できる一方で、`--fake-keys` を付けない通常の CLI 実行では偽鍵を決して使用しない
