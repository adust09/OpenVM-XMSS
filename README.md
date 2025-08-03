# xmss-for-Ethereum

- このレポジトリはXMSSの集約署名のベンチマークを計測するために存在します。
- XMSSの署名検証が成功することの証明を、zkVMで保証します。
- 集約する署名の数は10個です
- XMSSの実装として、https://github.com/adust09/hypercube/tree/main/src/xmss を使用
- ベンチマークの測定項目は、以下のとおりです
  - 証明時間（署名検証時間）
  - 消費メモリ

## 概要

このプロジェクトは、Ethereum向けのXMSS（eXtended Merkle Signature Scheme）署名集約システムを実装し、zkVMでの証明生成をサポートします。

## 技術スタック

- **言語**: Rust
- **XMSS実装**: [hypercube](https://github.com/adust09/hypercube)ライブラリ（TSL最適化付き）
- **zkVM**: OpenVM（統合予定）
- **ベンチマーク**: Criterion + 組み込みベンチマークツール

## 機能

- ✅ 設定可能なパラメータを持つXMSSラッパー（ツリー高さ、セキュリティレベル）
- ✅ 最大10個の署名の集約
- ✅ タイミング測定付きバッチ検証
- ✅ ベンチマークとテストデータ生成のためのCLIインターフェース
- ✅ zkVM証明生成のためのシリアル化
- 🚧 OpenVM統合（次フェーズ）

## プロジェクト構造

```
xmss-for-ethereum/
├── src/
│   ├── xmss/          # XMSSラッパーと署名集約
│   ├── zkvm/          # zkVM統合（OpenVM）
│   ├── benchmark/     # パフォーマンス測定ツール
│   └── main.rs        # CLIアプリケーション
├── tests/             # 統合テスト
├── benches/           # Criterionベンチマーク
└── libs/hypercube/    # XMSS実装のGitサブモジュール
```

## インストール

```bash
# サブモジュールを含めてクローン
git clone --recursive https://github.com/your-username/xmss-for-ethereum.git
cd xmss-for-ethereum

# プロジェクトをビルド
cargo build --release
```

## 使用方法

### CLIコマンド

```bash
# 10個の署名でベンチマークを実行
cargo run --release -- benchmark --signatures 10

# カスタムパラメータでベンチマークを実行
cargo run --release -- benchmark \
  --signatures 5 \
  --tree-height 8 \
  --security-bits 128 \
  --output results.json

# zkVM用のテストデータを生成
cargo run --release -- generate --count 10 --output test_data.bin
```

### ライブラリの使用

```rust
use xmss_for_ethereum::{XmssWrapper, SignatureAggregator};

// デフォルトパラメータでラッパーを作成
let wrapper = XmssWrapper::new()?;

// アグリゲータを作成
let mut aggregator = SignatureAggregator::new(wrapper.params().clone());

// 署名を生成して集約
for i in 0..10 {
    let keypair = wrapper.generate_keypair()?;
    let message = format!("Message {}", i).into_bytes();
    let signature = wrapper.sign(&keypair, &message)?;
    let public_key = keypair.lock().unwrap().public_key().clone();
    
    aggregator.add_signature(signature, message, public_key)?;
}

// すべての署名を検証
let (is_valid, duration) = aggregator.verify_all()?;
println!("{}個の署名を{:?}で検証しました", aggregator.len(), duration);
```

## ベンチマーク結果の例

```
Benchmark Results:
==================
Signatures: 10
Tree Height: 10 (max 1024 signatures per key)
Security Level: 128 bits
Verification Time: 25.3ms
Average per signature: 2.53ms
```

## パフォーマンスの注意点

- XMSS鍵生成は計算量が多い
- テストには小さいツリー高さ（例：4-8）を使用
- 本番環境では十分な署名数のためにツリー高さ10以上を使用
- Hypercube最適化により標準Winternitzより20-40%の改善

## 開発状況

- ✅ GitサブモジュールによるXMSSライブラリ統合
- ✅ 署名集約の実装（最大10個の署名）
- ✅ CLIインターフェースとベンチマークツール
- ✅ ユニットテストと統合テスト
- 🚧 OpenVM zkVM統合
- 🚧 オンチェーン検証コントラクト
- 🚧 パフォーマンス最適化

## 必要条件

- Rust 1.70+
- 16GB+ RAM推奨（ツリー高さ10以上の場合）
- MacOS/Linux（Windowsは未テスト）

## テスト

```bash
# すべてのテストを実行
cargo test

# 出力付きで実行
cargo test -- --nocapture

# 特定のテストを実行
cargo test test_single_signature_verification
```

## ライセンス

MIT