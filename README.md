# DataIntegrity

[![CI](https://github.com/jainhitesh9998/data-integrity-ios/actions/workflows/ci.yml/badge.svg)](https://github.com/jainhitesh9998/data-integrity-ios/actions/workflows/ci.yml)
[![Swift](https://img.shields.io/badge/Swift-6.0-orange.svg)](https://swift.org)
[![Platforms](https://img.shields.io/badge/Platforms-iOS%2014%2B%20%7C%20macOS%2013%2B-blue.svg)](https://github.com/jainhitesh9998/data-integrity-ios)
[![codecov](https://codecov.io/gh/jainhitesh9998/data-integrity-ios/branch/main/graph/badge.svg)](https://codecov.io/gh/jainhitesh9998/data-integrity-ios)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

> The Swift and Platforms badges are static snapshots so they render immediately;
> once listed on the [Swift Package Index](https://swiftpackageindex.com/add-a-package)
> you can swap them for the live SPI badges (via the package page's "Do you
> maintain this package?" link). **Coverage** is reported live by Codecov and
> populates after the repo is connected at codecov.io (CI uploads `coverage.lcov`).

A Swift library to **verify** and **derive** W3C Verifiable Credential Data
Integrity proofs — with first-class support for the **`ecdsa-sd-2023`**
selective-disclosure cryptosuite — plus a standalone **RDF canonicalization**
function. Built to plug into the Inji Wallet (React Native) iOS app the same way
`inji-vci-client-ios-swift` does.

📖 **Design & integration guide:** [`docs/DESIGN.md`](docs/DESIGN.md) · **React Native:** [`docs/REACT_NATIVE_INTEGRATION.md`](docs/REACT_NATIVE_INTEGRATION.md)

## Features

| Capability | Cryptosuites |
|---|---|
| **Verify** a credential's proof | `ecdsa-sd-2023` (derived), `ecdsa-rdfc-2019` (P-256/P-384), `eddsa-rdfc-2022` (Ed25519), `Ed25519Signature2020` |
| **Derive** a selectively-disclosed credential | `ecdsa-sd-2023` |
| **Canonicalize** a JSON-LD document | RDFC-1.0 / URDNA2015 (rdfc-2019) |

- Offline-capable & deterministic: the standard `@context`s (VCDM v2/v1, Data
  Integrity, Multikey, Ed25519-2020, Open Badges v3) are **bundled**; unknown
  contexts fall back to the network. `@protected` is stripped to match the
  Android/server canonicalizer byte-for-byte.
- Key resolution: `did:key` (offline) and `did:web` / `https` (controller doc),
  `publicKeyMultibase` and `publicKeyJwk`.
- ECDSA signatures are normalized to low-S, so high-S issuer signatures verify.

## Installation

**Swift Package Manager** — add to your `Package.swift`:

```swift
dependencies: [
    .package(url: "https://github.com/jainhitesh9998/data-integrity-ios.git", from: "0.1.1"),
],
targets: [
    .target(name: "YourTarget", dependencies: [
        .product(name: "DataIntegrity", package: "data-integrity-ios"),
    ]),
]
```

**Xcode** — *File ▸ Add Package Dependencies…*, enter
`https://github.com/jainhitesh9998/data-integrity-ios`, and add the
**`DataIntegrity`** library.

## Public API

```swift
let client = DataIntegrityClient()    // bundled contexts + network fallback

// Standalone canonicalization (RDFC-1.0 N-Quads)
let nquads = try await client.canonicalize(jsonLd: documentJSON)

// Verify any supported Data Integrity proof
let result = try await client.verifyCredential(credentialJSON)   // .verified / .cryptosuite / .reason

// Derive an ecdsa-sd-2023 selective disclosure (holder side)
let derivedJSON = try await client.deriveCredential(
    baseCredential: baseCredentialJSON,
    selectivePointers: ["/credentialSubject/address"])   // RFC 6901 JSON Pointers
```

JSON crosses the boundary as `String`; errors are a single
`DataIntegrityError` with stable `DataIntegrityErrorCode`s.

## Architecture

```
DataIntegrityClient                       ── public facade
├─ JSON/JSONValue                          ── value-typed JSON model + JSONLD bridge
├─ JSONLD/Canonicalization                 ── JSON-LD → RDF (swift-jsonld) → RDFC-1.0 (swift-rdf-canonize)
├─ JSONLD/ContextDocumentLoader            ── bundled + network @context loader, @protected stripping
├─ Crypto/{Encoding,VerificationKey,...}   ── base64url/base58/multibase/multikey, P-256/P-384/Ed25519, low-S
├─ Suites/
│  ├─ CredentialVerifier                   ── routes by cryptosuite
│  ├─ RdfcSuiteVerifier                    ── ecdsa-rdfc-2019 / eddsa-rdfc-2022 / Ed25519Signature2020
│  └─ EcdsaSd2023 (+ Sd/*)                 ── verify + derive: proofValue CBOR, skolemize, selectJsonLd,
│                                             HMAC label map, grouping, canonical CBOR
└─ Vendor/RDFCLabels                       ── see "Dependencies" below
```

### Dependencies

- [`Kingpin-Apps/swift-jsonld`](https://github.com/Kingpin-Apps/swift-jsonld) — JSON-LD expansion + `toRDF`.
- [`Kingpin-Apps/swift-rdf-canonize`](https://github.com/Kingpin-Apps/swift-rdf-canonize) — RDFC-1.0 canonicalization (used directly for **verify** and **canonicalize**, as required).
- [`apple/swift-crypto`](https://github.com/apple/swift-crypto) — ECDSA, Ed25519, SHA-2, HMAC.

The `ecdsa-sd-2023` proof value's CBOR is encoded/decoded by built-in code
(`Suites/Sd/CanonicalCBOR.swift` + `CBORDecode.swift`) — no third-party CBOR
dependency.

**`Vendor/RDFCLabels`** is a renamed copy of `swift-rdf-canonize` that adds one
function, `canonicalizeWithLabels`, surfacing the canonical blank-node label map
(`input → c14n`). The **derive** path requires this map to compute the HMAC
blank-node labels, and upstream computes it internally but does not expose it.
Verification and standalone canonicalization use the upstream package directly.
(Upstreaming this as a public API would remove the vendored copy.)

## Testing

```bash
swift test
```

20 tests, all offline against the bundled contexts:

- **Canonicalization** parity on inline-context and blank-node documents.
- **Round-trip verify** for `ecdsa-rdfc-2019`, `eddsa-rdfc-2022`,
  `Ed25519Signature2020` (sign with a fresh key → verify; tamper → fail).
- **`ecdsa-sd-2023` verify** of a self-generated derived proof; tamper / wrong
  key / malformed proof value → fail.
- **`ecdsa-sd-2023` full lifecycle**: issue base proof → derive a selective
  disclosure → verify; confirms only mandatory + selected fields are revealed;
  tamper → fail.
- **Real-world interop** (`RealWorldInteropTests`): an externally-issued
  credential (`MedicalTechnician.json`, a NREMT First Responder badge with
  `ecdsa-rdfc-2019`, `ecdsa-jcs-2019`, and an `ecdsa-sd-2023` base proof),
  verified **fully offline**:
  - the real `ecdsa-rdfc-2019` signature verifies → our RDF canonicalization
    matches a real issuer byte-for-byte;
  - deriving a selective disclosure from the real `ecdsa-sd-2023` base proof and
    verifying it → the full SD pipeline is interop-correct against a real issuer.

`Samples/` holds generated, verifiable sample VCs for each suite (including a
real selectively-disclosed `ecdsa-sd-2023` credential).

> Remaining nice-to-have: run the broader [W3C vc-di-ecdsa test suite](https://github.com/w3c/vc-di-ecdsa-test-suite)
> for wider coverage. `ecdsa-jcs-2019` (JCS canonicalization) is intentionally
> out of scope — this library does RDF canonicalization (rdfc/sd).

## React Native integration

See [`docs/REACT_NATIVE_INTEGRATION.md`](docs/REACT_NATIVE_INTEGRATION.md) for
wiring this into the Inji Wallet (the native `DataIntegrityCanonize` bridge and
the JS routing for `ecdsa-sd-2023`).

## Platforms

iOS 14+, macOS 13+. Swift 6 toolchain (consumable from a Swift 5 app target).
Verified to build for the iOS device and simulator SDKs and macOS.

> CryptoKit's compressed EC-point APIs are iOS 16+, but Multikey/`did:key`
> public keys are compressed — so the library decompresses SEC1 points itself
> (`Crypto/ECPointDecompression.swift`, validated against CryptoKit) and uses the
> iOS 14 `x963Representation` initializer. This keeps the package usable from the
> wallet's iOS 14 deployment target.

## License

MIT — see [`LICENSE`](LICENSE).

`Sources/DataIntegrity/Vendor/RDFCLabels` is a derived copy of
`Kingpin-Apps/swift-rdf-canonize` (also MIT); its license/notice are preserved in
that directory (`Vendor/RDFCLabels/LICENSE`, `NOTICE.md`).
```
