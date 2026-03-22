## 1. Specification
- [x] 1.1 `xmss-hashsig` へベンチマーク専用偽鍵 (fake XMSS key) の要件とシナリオを追加する。

## 2. Implementation
- [x] 2.1 `xmss-lib` / `xmss-host` に偽鍵生成ユーティリティを追加し、WOTS は正規鍵・Merkle はランダムで構築する高速パスを実装する。
- [x] 2.2 CLI ベンチ (`cargo run -p xmss-host -- benchmark`) などで偽鍵フラグを受け付け、本番コマンドでは必ず本物の hash-sig 鍵を使うようガードする。
- [x] 2.3 ドキュメントとテストにベンチモードの注意事項（セキュリティ不可）を追記する。
