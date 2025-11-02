# Hash-sig Type Conversion Problem

**Status**: BLOCKED
**Date**: 2025-11-02
**Task**: Task 11 - Build type conversion layer to xmss-types
**Severity**: High - Blocks Requirement 4.6

## Problem Summary (問題の概要)

Type conversion between hash-sig and xmss-types cannot be implemented as specified because **hash-sig's Signature and PublicKey types have private fields with no public accessor methods**.

hash-sigとxmss-types間の型変換が仕様通りに実装できない。理由は**hash-sigのSignatureとPublicKey型のフィールドがすべてprivate（非公開）で、公開アクセサメソッドがない**ため。

## Technical Details (技術的詳細)

### Hash-sig Internal Structure

Location: `~/.cargo/git/checkouts/hash-sig-3bab0b6cf9ec0e01/84dd456/src/signature/generalized_xmss.rs`

```rust
// Line 39-43
pub struct GeneralizedXMSSSignature<IE: IncomparableEncoding, TH: TweakableHash> {
    path: HashTreeOpening<TH>,      // PRIVATE - no public accessor
    rho: IE::Randomness,             // PRIVATE - no public accessor
    hashes: Vec<TH::Domain>,         // PRIVATE - no public accessor
}

// Line 48-51
pub struct GeneralizedXMSSPublicKey<TH: TweakableHash> {
    root: TH::Domain,        // PRIVATE - no public accessor
    parameter: TH::Parameter, // PRIVATE - no public accessor
}
```

### Required xmss-types Structure

Location: `/Users/ts21/pq/OpenVM-XMSS/xmss-types/src/lib.rs`

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Signature {
    pub leaf_index: u32,           // Must derive from epoch
    pub randomness: Vec<u8>,       // Should map from rho
    pub wots_chain_ends: Vec<Vec<u8>>, // Should map from hashes
    pub auth_path: Vec<Vec<u8>>,   // Should map from path.co_path
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicKey {
    pub root: Vec<u8>,        // Should map from root
    pub parameter: Vec<u8>,   // Should map from parameter
}
```

### Field Mapping Gap

| Hash-sig Field | Type | Access | xmss-types Field | Type | Access |
|----------------|------|--------|------------------|------|--------|
| `path: HashTreeOpening<TH>` | Generic | Private | `auth_path: Vec<Vec<u8>>` | Concrete | Public |
| `rho: IE::Randomness` | Generic | Private | `randomness: Vec<u8>` | Concrete | Public |
| `hashes: Vec<TH::Domain>` | Generic | Private | `wots_chain_ends: Vec<Vec<u8>>` | Concrete | Public |
| (epoch param) | N/A | N/A | `leaf_index: u32` | Concrete | Public |
| `root: TH::Domain` | Generic | Private | `root: Vec<u8>` | Concrete | Public |
| `parameter: TH::Parameter` | Generic | Private | `parameter: Vec<u8>` | Concrete | Public |

## Attempted Solutions (試した解決策)

### 1. Bincode Round-trip (FAILED)

**Approach**: Serialize hash-sig type → deserialize as xmss-types

```rust
let bytes = bincode::serialize(&wrapped_signature.inner)?;
let xmss_sig: Signature = bincode::deserialize(&bytes)?; // FAILS
```

**Result**:
```
ConversionError {
    reason: "Failed to deserialize signature: io error: unexpected end of file"
}
```

**Test Output**:
- Hash-sig signature serialized length: 1518 bytes
- First 100 bytes (hex): `[12, 00, 00, 00, 00, 00, 00, 00, fc, 45, 72, 03, ...]`

**Why it fails**:
- Hash-sig serializes complex generic types (IE::Randomness, TH::Domain, HashTreeOpening<TH>)
- xmss-types expects simple Vec<u8> fields
- Binary format mismatch: hash-sig's bincode output != xmss-types' expected input

### 2. Direct Field Access (IMPOSSIBLE)

```rust
let auth_path = signature.path.co_path; // ERROR: field `path` is private
```

All fields are private with no getters.

### 3. Accessor Methods Search (NOT FOUND)

Searched hash-sig's public API - no accessor methods available:
- No `pub fn path(&self)`
- No `pub fn randomness(&self)`
- No `pub fn hashes(&self)`

## Impact on Requirements (要件への影響)

### Blocked Requirement

**Requirement 4.6** (from `/Users/ts21/pq/OpenVM-XMSS/.kiro/specs/hash-sig-wrapper/requirements.md:56`):

> WHEN xmss_types structures are converted back to hash-sig types THEN the XmssWrapper SHALL provide reverse conversion methods

### Partially Achievable Requirements

**Requirement 4.1-4.3**: Forward conversion (hash-sig → xmss-types) MAY be possible through:
- Deep bincode parsing (fragile)
- Custom serialization logic

**Requirement 4.4-4.5**: Public key conversion has same issue

## Proposed Solutions (提案する解決策)

### Option 1: Fork hash-sig (Quick Fix)

**Approach**:
1. Fork `https://github.com/b-wagn/hash-sig.git`
2. Make signature/public key fields public
3. Update Cargo.toml to use forked version

**Pros**:
- Immediate unblocking
- Full control over API

**Cons**:
- Maintenance burden (sync with upstream)
- Divergence risk
- Community fragmentation

**Effort**: Low (1-2 hours)

### Option 2: Contribute Upstream (Proper Fix)

**Approach**:
1. Open issue on hash-sig repository
2. Submit PR adding accessor methods:
   ```rust
   impl<IE: IncomparableEncoding, TH: TweakableHash> GeneralizedXMSSSignature<IE, TH> {
       pub fn path(&self) -> &HashTreeOpening<TH> { &self.path }
       pub fn randomness(&self) -> &IE::Randomness { &self.rho }
       pub fn hashes(&self) -> &[TH::Domain] { &self.hashes }
   }

   impl<TH: TweakableHash> GeneralizedXMSSPublicKey<TH> {
       pub fn root(&self) -> &TH::Domain { &self.root }
       pub fn parameter(&self) -> &TH::Parameter { &self.parameter }
   }
   ```
3. Wait for review and merge

**Pros**:
- Proper solution
- Benefits entire hash-sig community
- No maintenance burden

**Cons**:
- Time delay (days to weeks)
- May not be accepted
- Blocks current progress

**Effort**: Medium (PR preparation + wait time)

### Option 3: Manual Bincode Parser (Fragile)

**Approach**:
1. Study hash-sig's bincode serialization format
2. Implement custom parser to extract fields from byte stream
3. Handle generic type serialization manually

**Example skeleton**:
```rust
fn parse_signature_bytes(bytes: &[u8]) -> Result<Signature, WrapperError> {
    // Parse bincode format manually
    // Extract: Vec length, HashTreeOpening structure, etc.
    let mut cursor = 0;

    // Skip generic type metadata
    // Extract Vec<TH::Domain> as Vec<Vec<u8>>
    // ...
}
```

**Pros**:
- No external dependencies on hash-sig changes
- Immediate implementation

**Cons**:
- Extremely fragile (breaks with bincode version updates)
- Complex implementation (generic type handling)
- Maintenance nightmare
- May break with hash-sig updates

**Effort**: High (4-8 hours implementation + ongoing maintenance)

### Option 4: Forward-only Conversion (Pragmatic)

**Approach**:
1. Implement only hash-sig → xmss-types conversion
2. Skip xmss-types → hash-sig reverse conversion
3. Document limitation clearly
4. Re-evaluate when hash-sig provides accessors

**Implementation**:
```rust
impl TypeConverter {
    /// Convert hash-sig Signature to xmss-types::Signature
    ///
    /// NOTE: Reverse conversion (xmss-types → hash-sig) is NOT supported
    /// due to hash-sig's private fields. Use hash-sig directly for signing.
    pub fn to_xmss_signature<S: SignatureScheme>(
        wrapped_signature: &WrappedSignature<S>,
    ) -> Result<Signature, WrapperError> {
        // Attempt bincode parsing or custom logic
    }

    // NO from_xmss_signature implementation
}
```

**Pros**:
- Unblocks primary use case (host signs → guest verifies)
- Honest about limitations
- Can add reverse conversion later

**Cons**:
- Fails Requirement 4.6
- Incomplete API

**Effort**: Low (use existing test code)

### Option 5: Rethink Architecture (Long-term)

**Approach**:
1. Keep hash-sig types internal to wrapper
2. Never expose xmss-types conversion
3. Provide direct serialization of wrapper types for host-guest communication

**Pros**:
- Avoids conversion problem entirely
- Simpler architecture

**Cons**:
- Requires redesigning host-guest interface
- Breaks existing xmss-types usage
- Major architectural change

**Effort**: Very High (multi-day effort)

## Recommendation (推奨事項)

### Immediate Action: Option 4 (Forward-only Conversion)

**Rationale**:
- Primary use case is: Host generates signatures → Guest verifies
- Forward conversion (hash-sig → xmss-types) is sufficient for this flow
- Guest receives xmss-types::Signature, never needs to create hash-sig::Signature
- Reverse conversion may not be needed in practice

**Implementation Plan**:
1. Remove reverse conversion tests from `conversions.rs`
2. Implement forward conversion only (attempt bincode parsing with error handling)
3. Document limitation clearly in API docs
4. Add TODO comment linking to this problem.md

### Medium-term Action: Option 2 (Upstream Contribution)

**Parallel track**:
1. Open GitHub issue on hash-sig repository explaining use case
2. Submit PR with accessor methods (non-breaking change)
3. Monitor PR status
4. If merged, implement reverse conversion

### Contingency: Option 1 (Fork) if Upstream Rejects

If upstream doesn't accept accessor methods within 2 weeks, fork hash-sig as fallback.

## Current Test Status (現在のテスト状況)

**File**: `/Users/ts21/pq/OpenVM-XMSS/lib/src/xmss/conversions.rs`

```
running 6 tests
test xmss::conversions::tests::test_conversion_error_handling ... ok (1/6 passing)
test xmss::conversions::tests::test_public_key_conversion_roundtrip ... FAILED
test xmss::conversions::tests::test_wrapped_public_key_to_xmss_types_method ... FAILED
test xmss::conversions::tests::test_conversion_preserves_cryptographic_material ... FAILED
test xmss::conversions::tests::test_signature_conversion_roundtrip ... FAILED
test xmss::conversions::tests::test_wrapped_signature_to_xmss_types_method ... FAILED
```

All round-trip tests fail with same error: `io error: unexpected end of file`

## Next Steps (次のステップ)

### Decision Required

User must choose:
- [ ] **Option 4**: Proceed with forward-only conversion (fastest)
- [ ] **Option 2**: Wait for upstream PR (proper but slow)
- [ ] **Option 1**: Fork hash-sig (quick but messy)
- [ ] **Option 3**: Manual parser (high effort)
- [ ] **Option 5**: Redesign architecture (major change)

### If Option 4 Selected (Recommended)

1. Update todo list - mark Task 11 as "partial completion"
2. Remove failing reverse conversion tests
3. Implement forward conversion with best-effort bincode parsing
4. Document limitation in README and API docs
5. Open upstream issue/PR on hash-sig
6. Continue to Task 12 (test utilities)

### If Option 1 Selected

1. Fork hash-sig repository
2. Make fields public in fork
3. Update Cargo.toml dependency
4. Test round-trip conversions
5. Continue implementation

### If Option 2 Selected

1. Open GitHub issue on hash-sig
2. Prepare PR with accessor methods
3. Pause Task 11 until PR review
4. Work on other tasks (Tasks 12-14) in parallel

## References (参考資料)

- **Hash-sig repository**: https://github.com/b-wagn/hash-sig.git
- **Requirements**: `.kiro/specs/hash-sig-wrapper/requirements.md` (Requirement 4.6)
- **Design**: `.kiro/specs/hash-sig-wrapper/design.md` (TypeConverter section)
- **Implementation**: `lib/src/xmss/conversions.rs:24-110`
- **Test failures**: `lib/src/xmss/conversions.rs:136-272`
