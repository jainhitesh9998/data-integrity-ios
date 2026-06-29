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

If upstream adds a public accessor for the canonical id map, this vendored copy
can be deleted and the dependency used directly.
