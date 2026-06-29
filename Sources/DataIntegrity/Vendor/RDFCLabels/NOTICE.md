# Vendored: RDFCLabels

The Swift files in this directory are a **derived copy** of
[`Kingpin-Apps/swift-rdf-canonize`](https://github.com/Kingpin-Apps/swift-rdf-canonize)
(MIT, © 2026 Kingpin Apps — see `LICENSE` here), with two changes:

1. the namespace is renamed `RDFCanonize` → `RDFCLabels` so it can coexist with
   the upstream package (which this library still depends on directly for
   verification and standalone canonicalization), and
2. a `canonicalizeWithLabels(quads:)` function is added to surface the canonical
   blank-node label map (`input → c14n`), which the ecdsa-sd-2023 **derive** path
   requires. Upstream computes this map internally but does not expose it.

## Keeping it in sync with upstream

Verification and standalone canonicalization depend on the **upstream
`swift-rdf-canonize` package directly** (see `Package.swift`), so an upstream fix
reaches those paths simply by **bumping the dependency version** — nothing here
needs to change.

This vendored copy is used **only by the `ecdsa-sd-2023` derive path** and is a
frozen snapshot of upstream **0.2.2**; it does **not** update automatically. When
upstream ships a relevant fix (e.g. for the `test075` first-degree-hash ordering
bug), re-sync it:

1. Copy the updated `Sources/RDFCanonize/*.swift` from the new upstream tag into
   this directory.
2. Re-apply the two local changes: rename the `RDFCanonize` namespace to
   `RDFCLabels`, and re-add `canonicalizeWithLabels(quads:)`.
3. Bump `swift-rdf-canonize` in `Package.swift` to the same tag.

If upstream adds a public accessor for the canonical id map, this vendored copy
can be deleted and the dependency used directly for derive too — then a single
version bump fixes every path at once.
