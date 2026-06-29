import Foundation

/// A parsed Data Integrity proof (or legacy Ed25519Signature2020 proof).
struct DataIntegrityProof {
    /// The raw proof object (used to build the canonicalized proof config).
    let object: JSONValue
    let type: String
    let cryptosuite: String?
    let verificationMethod: String
    let proofValue: String
    let proofPurpose: String?

    /// Effective cryptosuite, mapping the legacy `Ed25519Signature2020`
    /// LinkedData suite onto the equivalent `eddsa-rdfc-2022` algorithm.
    var effectiveCryptosuite: String {
        if type == "Ed25519Signature2020" { return "eddsa-rdfc-2022" }
        return cryptosuite ?? ""
    }
}

enum ProofExtractor {
    /// Return all proof objects on a credential (handles single or array).
    static func proofs(in credential: JSONValue) -> [JSONValue] {
        guard let proof = credential["proof"] else { return [] }
        return proof.asArray
    }

    /// Parse a proof object into a ``DataIntegrityProof`` (nil if it lacks
    /// the required fields).
    static func parse(_ object: JSONValue) -> DataIntegrityProof? {
        guard let type = object["type"]?.stringValue,
              let verificationMethod = object["verificationMethod"]?.stringValue,
              let proofValue = object["proofValue"]?.stringValue else {
            return nil
        }
        return DataIntegrityProof(
            object: object,
            type: type,
            cryptosuite: object["cryptosuite"]?.stringValue,
            verificationMethod: verificationMethod,
            proofValue: proofValue,
            proofPurpose: object["proofPurpose"]?.stringValue
        )
    }
}
