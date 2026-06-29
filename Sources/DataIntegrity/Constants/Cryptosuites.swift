import Foundation

enum Cryptosuite {
    static let ecdsaSd2023 = "ecdsa-sd-2023"
    static let ecdsaRdfc2019 = "ecdsa-rdfc-2019"
    static let eddsaRdfc2022 = "eddsa-rdfc-2022"
    static let ed25519Signature2020 = "Ed25519Signature2020"

    /// The Ed25519Signature2020 suite canonicalizes its proof options under
    /// its own suite context, not the document's. The VCDM v2 context does
    /// not define the suite term, so using the document context would
    /// canonicalize the proof options to an empty graph and never verify.
    static let ed25519Signature2020Context = "https://w3id.org/security/suites/ed25519-2020/v1"
}
