# Integrating `DataIntegrity` into the Inji Wallet (React Native)

This guide wires the `DataIntegrity` Swift package into the Inji Wallet
React Native app (iOS). It mirrors how `inji-vci-client-ios-swift` is integrated:
the library is a Swift Package, exposed to JS through a thin `RN…Module` bridge.

What you get:

- **`DataIntegrityCanonize.canonicalize(jsonLd)`** — the native RDFC-1.0
  canonicalizer the wallet's JS already calls. It exists on Android but was
  **missing on iOS**, so adding it makes the existing pure-JS
  `ecdsa-rdfc-2019` / `eddsa-rdfc-2022` / `Ed25519Signature2020` verification
  start working on iOS.
- **`DataIntegrityCanonize.verifyCredential(credential)`** — native verification
  for **`ecdsa-sd-2023`** (selective disclosure) and the other DI suites.
- **`DataIntegrityCanonize.deriveCredential(base, pointers)`** — selective
  disclosure derivation (holder side).

---

> **Already wired.** The package and bridge files have been added to
> `ios/Inji.xcodeproj` (via the `xcodeproj` gem): a local Swift package
> reference `../../lib`, the `DataIntegrity` product on the **Inji** target,
> the framework link, and `RNDataIntegrityModule.swift/.m` in the Sources phase.
> A backup is at `ios/Inji.xcodeproj/project.pbxproj.bak`. Open
> `ios/Inji.xcworkspace` and build. The sections below document what was done
> (and how to switch to a published remote package for release). Note: the
> `swiftcbor` package-identity warning in the graph is **pre-existing**
> (`inji-vci-client` uses `valpackett/SwiftCBOR`, another package uses the
> `abhip2565` fork) and is unrelated to this library, which has no CBOR dependency.

## 1. Add the Swift package to the Xcode project

The wallet already consumes SPM packages directly in `ios/Inji.xcodeproj`
(`securekeystore`, `pixelpass`, `VCIClient`, `OpenID4VP`, …). This one was added
the same way — as a **local** package (`../../lib`) for development. For release,
publish it (e.g. `github.com/inji/inji-data-integrity-ios-swift`) and replace the
local reference with an exact-version remote one, matching the other Inji packages.

**Open the workspace**

```
open ios/Inji.xcworkspace
```

**Local package (development).** In Xcode: *File ▸ Add Package Dependencies… ▸
Add Local…* and choose the `lib/` folder (this package). Then select the **Inji**
target ▸ *Frameworks, Libraries, and Embedded Content* and confirm
`DataIntegrity` is listed.

**Remote package (CI / release).** Publish the package (e.g.
`https://github.com/inji/inji-data-integrity-ios-swift`) and add it via *Add
Package Dependencies…* with an **exact version** pin, matching the other Inji
packages.

> Toolchain: the package is `swift-tools-version: 6.0`. Xcode 15+/26 builds it
> fine even though the app target is Swift 5 — a Swift 6 package compiles in its
> own language mode and links normally. Minimum deployment target is iOS 14
> (matches the wallet's `Podfile`).

This package's only third-party Swift dependencies are `swift-jsonld`,
`swift-rdf-canonize`, and `swift-crypto`; SwiftPM resolves them automatically.
The standard JSON-LD `@context`s are **bundled** in the package
(`Resources/contexts`), so verification works offline and deterministically.

## 2. Add the bridge files to the Inji target

Two files were added under `ios/` (next to `RNVCVerifierModule.*`):

- `ios/RNDataIntegrityModule.swift`
- `ios/RNDataIntegrityModule.m`

In Xcode, make sure both are members of the **Inji** target (*File ▸ Add Files
to "Inji"…* if they aren't already shown, then check the target box). The Swift
file `import DataIntegrity` — it won't compile until step 1 is done.

The bridge registers the JS module **`DataIntegrityCanonize`** with three
methods (`canonicalize`, `verifyCredential`, `deriveCredential`), all returning
Promises. No `Podfile` change is required (SPM is independent of CocoaPods here).

## 3. JS usage

The wallet already calls `NativeModules.DataIntegrityCanonize.canonicalize(...)`
from `shared/vcjs/dataIntegrity/verifyDataIntegrity.ts`; that now resolves on
iOS too.

For `ecdsa-sd-2023`, a helper and a route were added:

- `shared/vcjs/dataIntegrity/verifyEcdsaSd2023.ts` — `isEcdsaSd2023Proof`,
  `verifyEcdsaSd2023Credential`, `deriveEcdsaSd2023Credential`.
- `shared/vcjs/verifyCredential.ts` — routes `ecdsa-sd-2023` credentials to the
  native verifier **before** the generic Data Integrity branch (which only
  handles `rdfc-2019` / `eddsa`).

Direct usage:

```ts
import {NativeModules} from 'react-native';
const {DataIntegrityCanonize} = NativeModules;

// Canonicalize (RDFC-1.0 N-Quads)
const nquads = await DataIntegrityCanonize.canonicalize(JSON.stringify(doc));

// Verify any DI proof (ecdsa-sd-2023, ecdsa-rdfc-2019, eddsa-rdfc-2022, Ed25519Signature2020)
const {verified, cryptosuite, reason} =
  await DataIntegrityCanonize.verifyCredential(JSON.stringify(vc));

// Derive a selectively-disclosed ecdsa-sd-2023 presentation
const derivedJson = await DataIntegrityCanonize.deriveCredential(
  JSON.stringify(baseVc),
  ['/credentialSubject/fullName', '/credentialSubject/program'], // JSON Pointers
);
const derived = JSON.parse(derivedJson);
```

No `NativeEventEmitter` is needed — every method is a plain async Promise (no
host callbacks), unlike `InjiVciClient`.

## 4. Verification flow after integration

`verifyCredential(vc, format)` (the single entry point all verification funnels
through) now:

1. `ecdsa-sd-2023` → native `DataIntegrityCanonize.verifyCredential` → then the
   existing bitstring revocation-status check.
2. other `DataIntegrityProof` (`ecdsa-rdfc-2019` / `eddsa-rdfc-2022` /
   `Ed25519Signature2020`) → existing pure-JS path, which now succeeds on iOS
   because `DataIntegrityCanonize.canonicalize` resolves.
3. legacy JWT/LinkedData suites → unchanged.

## 5. Android

Android already ships a `DataIntegrityCanonize` native module
(`DataIntegrityCanonizeModule.kt`) with **only** `canonicalize`. For
`ecdsa-sd-2023` verify/derive on Android, add a parallel native implementation
exposing `verifyCredential` / `deriveCredential` (e.g. a Kotlin port of this
package, or the digitalbazaar JVM stack). The JS helpers already degrade
gracefully (`verified:false` with a reason) when the native method is absent, so
iOS can ship first.

## 6. Troubleshooting

- **`Native DataIntegrityCanonize.* unavailable`** → the bridge files aren't in
  the target, or the app wasn't rebuilt after adding them. Clean build folder
  and rebuild.
- **`CANONICALIZATION_FAILED` / context errors** → an unbundled `@context` and
  the device is offline. Add the context JSON to the package's
  `Resources/contexts` (and `BundledContexts.manifest`), or allow network in
  `ContextDocumentLoader`.
- **Signature won't verify but the VC is valid elsewhere** → almost always a
  canonicalization mismatch from `@protected` term redefinition. The loader
  strips `@protected` to match the signer; confirm the issuer's context is the
  one bundled.
```
