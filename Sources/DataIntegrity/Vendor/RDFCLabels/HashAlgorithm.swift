import Foundation
import Crypto

extension RDFCLabels {
    /// Hash algorithm selector for [RDFC-1.0](https://www.w3.org/TR/rdf-canon/).
    ///
    /// The spec is normative on SHA-256 as the default; SHA-384 is
    /// supported as an alternative and exercised by W3C test #test075.
    public enum HashAlgorithm: String, Sendable, Hashable {
        case sha256
        case sha384

        /// Hex-encoded digest of the UTF-8 bytes of `s`.
        func hex(_ s: String) -> String {
            let data = Data(s.utf8)
            switch self {
            case .sha256:
                return SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
            case .sha384:
                return SHA384.hash(data: data).map { String(format: "%02x", $0) }.joined()
            }
        }
    }
}
