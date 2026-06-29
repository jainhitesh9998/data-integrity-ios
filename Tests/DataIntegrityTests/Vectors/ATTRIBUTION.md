# Third-party conformance test vectors

These directories bundle official, upstream test suites used by the
`Conformance*Tests` to validate this library against authoritative vectors.
Each suite retains its upstream license; the files are **test inputs only** and
are not part of the shipped `DataIntegrity` library.

- **`rdf-canon/`** — W3C RDF Dataset Canonicalization (RDFC-1.0 / URDNA2015)
  test suite. Source: <https://github.com/w3c/rdf-canon> (`tests/rdfc10`).
  Only the positive `*-in.nq` → `*-rdfc10.nq` pairs are included (negative /
  "poison" tests are excluded). License: W3C Test Suite Licence.

- **`jcs/`** — JSON Canonicalization Scheme (RFC 8785) reference test data.
  Source: <https://github.com/cyberphone/json-canonicalization> (`testdata`).
  License: Apache-2.0.

- **`wycheproof/`** — Project Wycheproof cryptographic test vectors: ECDSA
  P-256 / P-384 (IEEE P1363 raw signatures) and Ed25519. Source:
  <https://github.com/C2SP/wycheproof> (`testvectors_v1`). License: Apache-2.0.

- **`MedicalTechnician.json`** — a real, externally-issued credential used for
  interop testing (see `RealWorldInteropTests`).
