import Foundation

/// Blank-node relabeling + JS-compatible sort for the selective-disclosure
/// canonicalization steps. Mirrors digitalbazaar `di-sd-primitives`
/// `relabelBlankNodes` (regex `/(_:([^\s]+))/g`) and the subsequent
/// `Array.prototype.sort()` (UTF-16 code-unit order).
enum NQuadsRelabel {
    /// Replace each `_:LABEL` token in one N-Quad line using `map`
    /// (`LABEL → newLabel`); the result token is `_:newLabel`. Labels not in
    /// the map are left unchanged. `LABEL` is the maximal run of
    /// non-whitespace after `_:`, matching the reference regex.
    static func relabelLine(_ line: String, map: [String: String]) -> String {
        let scalars = Array(line.unicodeScalars)
        var out = String.UnicodeScalarView()
        var i = 0
        let count = scalars.count
        while i < count {
            if scalars[i] == "_", i + 1 < count, scalars[i + 1] == ":" {
                var j = i + 2
                var label = String.UnicodeScalarView()
                while j < count, !isWhitespace(scalars[j]) {
                    label.append(scalars[j])
                    j += 1
                }
                let labelString = String(label)
                out.append(contentsOf: "_:".unicodeScalars)
                if let newLabel = map[labelString] {
                    out.append(contentsOf: newLabel.unicodeScalars)
                } else {
                    out.append(contentsOf: labelString.unicodeScalars)
                }
                i = j
            } else {
                out.append(scalars[i])
                i += 1
            }
        }
        return String(out)
    }

    /// `\s` per the reference regex. Within a single N-Quad line only space
    /// and tab can appear as separators.
    private static func isWhitespace(_ s: Unicode.Scalar) -> Bool {
        switch s.value {
        case 0x20, 0x09, 0x0A, 0x0D, 0x0C, 0x0B: return true
        default: return false
        }
    }

    /// Sort N-Quad lines by UTF-16 code unit, matching JavaScript's default
    /// `Array.prototype.sort()` (which the reference implementation relies on).
    /// This differs from Swift's default `String` ordering for non-ASCII
    /// literals and is required for byte-for-byte parity.
    static func sortUTF16(_ lines: [String]) -> [String] {
        lines.sorted(by: lessUTF16)
    }

    static func lessUTF16(_ a: String, _ b: String) -> Bool {
        let au = Array(a.utf16)
        let bu = Array(b.utf16)
        let n = Swift.min(au.count, bu.count)
        var i = 0
        while i < n {
            if au[i] != bu[i] { return au[i] < bu[i] }
            i += 1
        }
        return au.count < bu.count
    }
}
