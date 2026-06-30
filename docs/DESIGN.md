# DataIntegrity — Design & Integration Guide

How the library is structured, how each operation works, and how to integrate it
into your own app. For the React Native bridge specifically, see
[`REACT_NATIVE_INTEGRATION.md`](REACT_NATIVE_INTEGRATION.md).

---

## 1. What it does

`DataIntegrity` verifies and derives [W3C Verifiable Credential Data Integrity](https://www.w3.org/TR/vc-data-integrity/)
proofs, and exposes RDF canonicalization as a standalone function.

| Operation | Cryptosuites |
|---|---|
| **Verify** | `ecdsa-sd-2023` (derived), `ecdsa-rdfc-2019` / `ecdsa-jcs-2019` (P-256/P-384), `eddsa-rdfc-2022` / `eddsa-jcs-2022` (Ed25519), `Ed25519Signature2020` |
| **Derive** (selective disclosure) | `ecdsa-sd-2023` |
| **Canonicalize** | RDFC-1.0 / URDNA2015 (a.k.a. `rdfc-2019`) |

Everything crosses the public boundary as JSON `String`, async/await, with a
single `DataIntegrityError` error type — so it bridges cleanly to React Native,
a server, or another Swift app.

---

## 2. Architecture

```
                       ┌──────────────────────────────┐
   JSON String  ─────► │       DataIntegrityClient     │  ◄── public facade
                       └───────────────┬──────────────┘
                                       │
        ┌──────────────────────────────┼───────────────────────────────┐
        ▼                              ▼                                ▼
  canonicalize()               verifyCredential()              deriveCredential()
        │                              │                                │
        │                     CredentialVerifier (routes by cryptosuite)│
        │                       │                  │                    │
        ▼                       ▼                  ▼                    ▼
  Canonicalization     RdfcSuiteVerifier      EcdsaSd2023.verify   EcdsaSd2023.derive
  (JSON-LD→RDF→RDFC)   (rdfc/eddsa/2020)      (Sd/* primitives)    (Sd/* primitives)
        │                       │                  │                    │
        └───────── shared: JSON-LD expand+toRDF (swift-jsonld),  ───────┘
                   RDFC-1.0 canonicalize (swift-rdf-canonize),
                   P-256/P-384/Ed25519 + SHA + HMAC (swift-crypto),
                   bundled @context loader, did:key/did:web resolution
```

**The pipeline that underpins everything:** JSON → `JSONValue` → JSON-LD
**expand + toRDF** (`swift-jsonld`) → map to quads → **RDFC-1.0 canonicalize**
(`swift-rdf-canonize`) → canonical N-Quads. Signatures are computed/verified over
hashes of those N-Quads.

---

## 3. Source layout

```
Sources/DataIntegrity/
  DataIntegrityClient.swift     Public facade: canonicalize / verifyCredential / deriveCredential
  JSON/JSONValue.swift          Value-typed JSON model (+ Any/JSONLD bridges, RFC8259)
  JSON/JSONParser.swift         Correctly-rounded JSON parser (number fidelity vs JSONSerialization)
  JSON/JCS.swift                JSON Canonicalization Scheme (RFC 8785) for jcs suites
  DTO/VerificationResult.swift  { verified, cryptosuite?, reason? }
  Errors/DataIntegrityError.swift   Stable error codes
  JSONLD/
    Canonicalization.swift      JSON-LD → RDF → RDFC-1.0 N-Quads
    ContextDocumentLoader.swift Bundled + network @context loader
    ContextProtection.swift     Recursive `@protected` stripping
  Crypto/
    Encoding.swift              base64url, base58btc, multibase
    VerificationKey.swift       P-256/P-384/Ed25519 key + Multikey + JWK decode
    ECPointDecompression.swift  SEC1 point decompression (iOS 14 support)
    KeyResolver.swift           did:key / did:web / https → key
    DigestUtil.swift, BigEndian.swift   SHA/HMAC, low-S normalization
  Constants/                    cryptosuite names, multikey prefixes, bundled-context manifest
  Suites/
    CredentialVerifier.swift    Routes a proof to its suite
    RdfcSuiteVerifier.swift     ecdsa-rdfc-2019 / eddsa-rdfc-2022 / Ed25519Signature2020
    JcsSuiteVerifier.swift      ecdsa-jcs-2019 / eddsa-jcs-2022 (JCS / RFC 8785)
    Proof.swift                 Proof extraction
    EcdsaSd2023.swift           ecdsa-sd-2023 verify + derive orchestration
    Sd/                         selective-disclosure primitives (below)
  Vendor/RDFCLabels/            see §8
  Resources/contexts/           bundled @context JSON
Tests/DataIntegrityTests/       70 tests (see §10)
```

### Selective-disclosure primitives (`Suites/Sd/`)
Ports of digitalbazaar `di-sd-primitives`, faithful enough for byte-for-byte interop:
- `JSONPointer.swift` — RFC 6901 pointer parsing.
- `JSONLDSelect.swift` — `selectJsonLd`: structure-preserving selection by pointers.
- `Skolemize.swift` — `urn:bnid:` skolemization so pointer selections produce stable RDF.
- `SdPrimitives.swift` — HMAC label-map factory, blank-node relabel, label-replacement canonicalize.
- `SdGroup.swift` — `canonicalizeAndGroup`: split N-Quads into mandatory/selective/combined.
- `SdProofValue.swift` — parse/serialize base (`0xd95d00`) and derived (`0xd95d01`) proof values.
- `CBORDecode.swift` / `CanonicalCBOR.swift` — built-in CBOR (no third-party CBOR dependency).
- `NQuadsRelabel.swift` — relabel + JS-compatible UTF-16 sort.

---

## 4. How each operation works

### canonicalize(jsonLd)
Expand + `toRDF` (`swift-jsonld`) → map `JSONLD.Quad` → `RDFCanonize.Quad` →
`RDFCanonize.canonicalize` (RDFC-1.0) → canonical N-Quads. `@context`s are resolved
by the document loader (§7).

### verifyCredential — ecdsa-rdfc-2019 / eddsa-rdfc-2022 / Ed25519Signature2020
1. Resolve the issuer key from `proof.verificationMethod`.
2. `proofConfigHash = SHA(canonicalize(proof options))`, `docHash = SHA(canonicalize(doc − proof))`.
3. `hashData = proofConfigHash ‖ docHash`.
4. ECDSA verifies `hashData` (curve hashes it internally; P-384 ⇒ SHA-384); EdDSA verifies it directly.

`ecdsa-jcs-2019` and `eddsa-jcs-2022` are identical except the document and proof
config are canonicalized with **JCS** (RFC 8785, `JSON/JCS.swift`) instead of
RDFC-1.0 — so they do no JSON-LD processing and need no document loader
(`eddsa-jcs-2022` verifies with Ed25519, `ecdsa-jcs-2019` with ECDSA). Both run
through `JcsSuiteVerifier`.

### verifyCredential — ecdsa-sd-2023 (derived)
1. `parseDerivedProofValue` → `baseSignature`, ephemeral `publicKey`, `signatures`, `labelMap`, `mandatoryIndexes`.
2. `proofHash = SHA-256(canonicalize(proof config))`.
3. Canonicalize the disclosed doc → relabel `_:c14nN` → HMAC labels from `labelMap` → re-sort → split by `mandatoryIndexes`.
4. `mandatoryHash = SHA-256(join(mandatory))`.
5. Verify `baseSignature` over `proofHash ‖ publicKey ‖ mandatoryHash` with the **issuer** key.
6. Verify each `signatures[i]` over the non-mandatory n-quad with the **ephemeral** key.

### deriveCredential — ecdsa-sd-2023 (holder)
`parseBaseProofValue` → skolemize → `canonicalizeAndGroup` by mandatory/selective/combined
pointers (HMAC blank-node labels) → compute `mandatoryIndexes`, filter the base
signatures to disclosed non-mandatory statements, build the verifier label map,
`selectJsonLd` the reveal document → `serializeDerivedProofValue`.

---

## 5. Public API

```swift
public final class DataIntegrityClient: Sendable {
    public init(documentLoader: ContextDocumentLoader = ContextDocumentLoader())
    public init(documentLoader: any JSONLDDocumentLoader)   // inject a custom loader

    public func canonicalize(jsonLd: String) async throws -> String
    public func verifyCredential(_ credential: String) async throws -> VerificationResult
    public func deriveCredential(baseCredential: String, selectivePointers: [String]) async throws -> String
}

public struct VerificationResult: Codable, Sendable { let verified: Bool; let cryptosuite: String?; let reason: String? }
public struct DataIntegrityError: Error, LocalizedError { let code: DataIntegrityErrorCode; let message: String }
```

`verifyCredential` never throws on a *verification* failure — it returns
`verified: false` with a `reason`. It only throws on input it can't parse at all.

---

## 6. Security model (issuer / holder / verifier)

- The **issuer** signs the full credential. For `ecdsa-sd-2023` this is a *base
  proof*: a signature over the mandatory statements plus a per-statement signature
  over every selectively-disclosable statement, under an ephemeral key.
- The **holder** keeps the base credential and **derives** a disclosure for each
  presentation. Derivation does **not** validate the base proof — the holder owns
  it; integrity is enforced when the *derived* proof is verified.
- The **verifier** only ever sees the derived/secured credential. Its checks:
  - tampered **mandatory** data → caught by the base signature (mandatory hash);
  - tampered **disclosed** data → caught by that statement's per-statement signature;
  - a field the holder doesn't disclose is simply absent (by design of selective
    disclosure) — not a failure.

Practical guidance: bundle/pin `@context`s (don't fetch live) for deterministic,
auditable verification, and confirm the issuer key is authorized for the proof
purpose against the controller/DID document.

---

## 7. JSON-LD contexts

`ContextDocumentLoader` resolves `@context`s **bundled-first, then network**, and
strips `@protected` from every context (matching the Android/server canonicalizer
so combined contexts — e.g. OpenBadge + VCDM v2 — expand and verify byte-for-byte;
removing `@protected` does not change term→IRI mappings). Bundled contexts
(`Resources/contexts/`) include VCDM v2/v1, Data Integrity v1/v2, Multikey,
Ed25519-2020/2018, Open Badges v3, and the First Responder / render-method
contexts. Use `ContextDocumentLoader(networkPolicy: .deny)` for strict offline
verification, or inject your own `JSONLDDocumentLoader`.

---

## 8. Dependencies & the vendored canonicalizer

- `Kingpin-Apps/swift-jsonld` — JSON-LD expand + `toRDF`.
- `Kingpin-Apps/swift-rdf-canonize` — RDFC-1.0 (used directly for verify + canonicalize).
- `apple/swift-crypto` — ECDSA, Ed25519, SHA-2, HMAC.
- CBOR is **built in** (`Sd/CanonicalCBOR.swift` + `CBORDecode.swift`) — no CBOR dependency.

`Vendor/RDFCLabels/` is a renamed copy of `swift-rdf-canonize` that adds one
function — `canonicalizeWithLabels` — exposing the canonical blank-node label map
that the **derive** path needs (upstream computes it internally but doesn't expose
it). Verify/canonicalize use the upstream package directly. The full rationale —
options weighed, decision matrix, sequence diagram, and the upstream-fix workflow —
is in [ADR 0001](adr/0001-vendored-rdf-canonicalizer.md); re-sync steps are in
`Vendor/RDFCLabels/NOTICE.md`.

Key design decisions: verify relabels in **c14n space** (the proof's `labelMap` is
keyed by `c14n` labels) so it needs no label map; SEC1 points are decompressed
in-library (`ECPointDecompression.swift`) because CryptoKit's compressed-point API
is iOS 16+ but the library targets **iOS 14**; ECDSA signatures are normalized to
low-S so high-S issuer signatures still verify; and JSON is parsed by a
correctly-rounded parser (`JSON/JSONParser.swift`) rather than `JSONSerialization`,
whose decimal rounding can otherwise diverge from the signer's canonical bytes.

---

## 9. Integration

### Install (Swift Package Manager)

```swift
.package(url: "https://github.com/jainhitesh9998/data-integrity-ios.git", from: "0.3.0"),
// target dependency:
.product(name: "DataIntegrity", package: "data-integrity-ios"),
```

In Xcode: *File ▸ Add Package Dependencies…* → the repo URL → add `DataIntegrity`.

### Use

```swift
import DataIntegrity

let client = DataIntegrityClient()   // bundled contexts + network fallback

// 1. Verify (any supported suite; did:key offline, did:web/https resolved over network)
let result = try await client.verifyCredential(credentialJSON)
if result.verified { /* good */ } else { print(result.reason ?? "") }

// 2. Canonicalize (RDFC-1.0 N-Quads)
let nquads = try await client.canonicalize(jsonLd: documentJSON)

// 3. Derive an ecdsa-sd-2023 selective disclosure (holder side)
let derived = try await client.deriveCredential(
    baseCredential: baseVcJSON,
    selectivePointers: ["/credentialSubject/name", "/credentialSubject/address"])
```

- **Offline / deterministic:** `DataIntegrityClient(documentLoader: ContextDocumentLoader(networkPolicy: .deny))`.
- **Errors:** catch `DataIntegrityError` (has `.code` and `.message`); `verifyCredential`
  reports verification failures via `result.reason` rather than throwing.
- **Concurrency:** the client is `Sendable`; methods are `async`. Reuse one client to
  share the `@context` cache.
- **React Native:** wrap the three methods in an `RCTBridgeModule` — see
  [`REACT_NATIVE_INTEGRATION.md`](REACT_NATIVE_INTEGRATION.md).

---

## 10. Testing

`swift test` — 75 tests, offline against bundled contexts/vectors (plus a live
`did:web` test). Coverage ≈ 88% of the library's own code. Highlights:
- canonicalization parity, round-trip verify for every suite, P-384, JWK decode;
- full `ecdsa-sd-2023` issue → derive → verify lifecycle and optional-field shapes;
- **standard conformance suites** (run in CI on every push): W3C `rdf-canon`
  (RDFC-1.0, 63/64 positive vectors — `test075` is an upstream ordering bug), RFC 8785 JCS via `cyberphone` (6/6), and
  Project Wycheproof ECDSA P-256/P-384 + Ed25519 — each group's key decoded
  through this library's own JWK / compressed-point decoders (exercising the
  iOS-14 SEC1 decompression). See `Tests/DataIntegrityTests/Vectors/ATTRIBUTION.md`;
- **real-world interop** against an externally-issued credential (`MedicalTechnician.json`);
- **negatives**: wrong key, corrupted/flipped proof value, tampered mandatory vs
  selective fields (in the derived doc *and* the base credential), injected/removed
  statements, invalid pointers.

## 11. Platforms & limitations

iOS 14+, macOS 13+; Swift 6 toolchain (consumable from a Swift 5 app target).
Android needs a parallel native implementation for `ecdsa-sd-2023`.
