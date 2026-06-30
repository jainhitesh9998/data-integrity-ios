import Foundation

/// Holder-side helpers for `ecdsa-sd-2023`: describe what the issuer forced
/// (mandatory) vs. what the holder may choose (optional), and enumerate the
/// optional set for "reveal everything" (verify-on-open).
///
/// The **mandatory** pointers are read straight from the base proof (the issuer
/// committed them at issuance); the **optional** pointers are every disclosable
/// claim leaf that isn't already covered by a mandatory pointer. Enumeration is
/// authoritative here because it walks the *same* document the derive path
/// selects against — so every emitted pointer resolves (no `/type/0`, no
/// `@context` noise).
enum SdDisclosure {
    /// `(mandatory, optional)` pointer sets for an `ecdsa-sd-2023` base credential.
    static func describe(baseCredential: JSONValue) throws -> (mandatory: [String], optional: [String]) {
        let mandatory = try SdProofValue.parseBase(baseProofValue(baseCredential)).mandatoryPointers
        // Walk only the claims — skip `@context` (JSON-LD framing, no RDF
        // statements) and `proof`.
        let claims = baseCredential.removing("proof").removing("@context")
        var leaves: [String] = []
        enumerate(claims, "", &leaves)
        let optional = leaves.filter { leaf in
            !mandatory.contains { leaf == $0 || leaf.hasPrefix($0 + "/") }
        }
        return (mandatory.sorted(), optional.sorted())
    }

    /// Every optional (non-mandatory) pointer — pass these to `derive` to reveal
    /// the whole credential for a full-integrity (verify-on-open) check.
    static func allOptionalPointers(baseCredential: JSONValue) throws -> [String] {
        try describe(baseCredential: baseCredential).optional
    }

    // MARK: - internals

    private static func baseProofValue(_ doc: JSONValue) throws -> String {
        let proofs = ProofExtractor.proofs(in: doc)
        guard let proof = proofs.first(where: {
            $0["type"]?.stringValue == "DataIntegrityProof" && $0["cryptosuite"]?.stringValue == EcdsaSd2023.name
        }), let proofValue = proof["proofValue"]?.stringValue else {
            throw DataIntegrityError(.malformedProof, "no ecdsa-sd-2023 base proof found")
        }
        return proofValue
    }

    /// Emit one RFC 6901 pointer per disclosable claim leaf. Objects recurse;
    /// real arrays recurse by index; scalars are leaves; the `type`/`@type`
    /// keyword is disclosed as a node (never `/type/0`).
    private static func enumerate(_ value: JSONValue, _ prefix: String, _ out: inout [String]) {
        switch value {
        case .object(let object):
            for key in object.keys.sorted() {
                let pointer = prefix + "/" + escape(key)
                if key == "type" || key == "@type" { out.append(pointer) }
                else { enumerate(object[key]!, pointer, &out) }
            }
        case .array(let array):
            if array.isEmpty { out.append(prefix) }
            else { for (i, element) in array.enumerated() { enumerate(element, prefix + "/\(i)", &out) } }
        default:
            out.append(prefix)
        }
    }

    private static func escape(_ key: String) -> String {
        key.replacingOccurrences(of: "~", with: "~0").replacingOccurrences(of: "/", with: "~1")
    }
}
