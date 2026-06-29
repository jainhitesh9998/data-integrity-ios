import Foundation

/// One step of a parsed JSON Pointer: an object key or an array index.
enum PointerPath: Equatable {
    case key(String)
    case index(Int)
}

/// RFC 6901 JSON Pointer parsing. Port of digitalbazaar `di-sd-primitives`
/// `parsePointer`: a numeric path becomes an array index; `~1`/`~0` unescape
/// to `/`/`~`.
enum JSONPointer {
    static func parse(_ pointer: String) throws -> [PointerPath] {
        // Drop the leading empty segment from the initial "/".
        let paths = pointer.split(separator: "/", omittingEmptySubsequences: false).dropFirst()
        var parsed: [PointerPath] = []
        for path in paths {
            let p = String(path)
            if !p.contains("~") {
                if let index = Int(p) {
                    parsed.append(.index(index))
                } else {
                    parsed.append(.key(p))
                }
            } else {
                parsed.append(.key(try unescape(p)))
            }
        }
        return parsed
    }

    private static func unescape(_ path: String) throws -> String {
        var out = ""
        var chars = Array(path)
        var i = 0
        while i < chars.count {
            if chars[i] == "~", i + 1 < chars.count {
                let next = chars[i + 1]
                if next == "1" { out.append("/"); i += 2; continue }
                if next == "0" { out.append("~"); i += 2; continue }
                throw DataIntegrityError(.invalidPointer, "invalid JSON pointer escape \"~\(next)\"")
            }
            out.append(chars[i])
            i += 1
        }
        return out
    }
}
