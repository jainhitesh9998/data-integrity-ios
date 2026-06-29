import Foundation

extension RDFCLabels {
    /// Issues unique blank-node identifiers in insertion order.
    ///
    /// `IdentifierIssuer` is used in two roles by [RDFC-1.0](https://www.w3.org/TR/rdf-canon/):
    /// - the **canonical** issuer (`prefix: "c14n"`) accumulates the
    ///   final `_:c14n0`, `_:c14n1`, … labels.
    /// - a per-blank-node **temporary** issuer (`prefix: "b"`) labels
    ///   blank nodes visited during the n-degree hash recursion.
    ///
    /// Issuers are value-typed so callers can clone with `let copy = issuer`
    /// when exploring permutations.
    struct IdentifierIssuer: Sendable, Hashable {
        let prefix: String
        private(set) var existing: [String: String] = [:]
        private(set) var order: [String] = []
        private var counter: Int = 0

        init(prefix: String) {
            self.prefix = prefix
        }

        /// Return the issued id for `old`, creating one if needed.
        /// The returned identifier carries the `_:` N-Quads prefix.
        @discardableResult
        mutating func getId(_ old: String) -> String {
            if let existingID = existing[old] { return existingID }
            let issued = "_:\(prefix)\(counter)"
            counter += 1
            existing[old] = issued
            order.append(old)
            return issued
        }

        /// Whether `old` has already been issued an identifier.
        func hasId(_ old: String) -> Bool { existing[old] != nil }

        /// Original ids in the order they were issued — used by the
        /// canonical issuer when transferring labels from a chosen
        /// temporary issuer.
        var issuedOrder: [String] { order }
    }
}
