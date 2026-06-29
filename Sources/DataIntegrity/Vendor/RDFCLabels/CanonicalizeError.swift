import Foundation

extension RDFCLabels {
    /// Errors raised by the canonicalization algorithm.
    public enum CanonicalizeError: Error, CustomStringConvertible, Sendable {
        /// The N-Degree Hash Quads recursion exceeded `maxDeepIterations`.
        ///
        /// Inputs that hit this bound are "poison graphs" — symmetric
        /// blank-node topologies where the search space grows faster
        /// than the work factor permits. Raise `workFactor` to allow
        /// more iterations, or surface this as a rejection per the
        /// W3C [poison-graph test guidance](https://www.w3.org/TR/rdf-canon/#dfn-poison-dataset).
        case iterationLimitExceeded(limit: Int)

        public var description: String {
            switch self {
            case .iterationLimitExceeded(let n):
                return "RDFC-1.0 N-Degree Hash exceeded the deep-iteration limit (\(n))."
            }
        }
    }
}
