import Foundation

/// Structure-preserving JSON-LD selection by JSON Pointers. Port of
/// digitalbazaar `di-sd-primitives` `selectJsonLd` / `_selectPaths` /
/// `_initSelection`.
///
/// For each pointer: intermediate object nodes carry only `id` (non-blank) and
/// `type`; the terminal value is included in full. The root carries `@context`.
enum JSONLDSelect {
    /// Sentinel for a sparse-array hole (an index not yet selected).
    private static let hole = JSONValue.object(["\u{0}__di_sd_hole__\u{0}": .bool(true)])

    static func selectJsonLd(
        document: JSONValue,
        pointers: [String],
        includeTypes: Bool = true
    ) throws -> JSONValue? {
        guard case .object = document else {
            throw DataIntegrityError(.invalidCredential, "document must be an object")
        }
        if pointers.isEmpty { return nil }

        var rootDict = initSelection(source: document, includeTypes: includeTypes)
        if let context = document["@context"] {
            rootDict["@context"] = context
        }
        var selection = JSONValue.object(rootDict)

        for pointer in pointers {
            let paths = try JSONPointer.parse(pointer)
            if paths.isEmpty { return document }  // whole document selected
            selection = try selectPaths(
                selection: selection, document: document, paths: paths[...],
                pointer: pointer, includeTypes: includeTypes)
        }

        return densify(selection)
    }

    private static func selectPaths(
        selection: JSONValue?,
        document: JSONValue,
        paths: ArraySlice<PointerPath>,
        pointer: String,
        includeTypes: Bool
    ) throws -> JSONValue {
        guard let first = paths.first else {
            // Terminal: include the full document value (blended with id/type
            // for objects, which `document` already subsumes).
            if case .object = document {
                return merge(selection, document)
            }
            return document
        }
        let rest = paths.dropFirst()

        switch first {
        case .key(let key):
            var dict = selection?.objectValue ?? initSelection(source: document, includeTypes: includeTypes)
            guard let childDocument = document[key] else {
                throw DataIntegrityError(.invalidPointer, "JSON pointer \"\(pointer)\" does not match document")
            }
            dict[key] = try selectPaths(
                selection: dict[key], document: childDocument, paths: rest,
                pointer: pointer, includeTypes: includeTypes)
            return .object(dict)

        case .index(let index):
            var array = selection?.arrayValue ?? []
            guard let documentArray = document.arrayValue, index < documentArray.count else {
                throw DataIntegrityError(.invalidPointer, "JSON pointer \"\(pointer)\" does not match document")
            }
            while array.count <= index { array.append(hole) }
            let existing = array[index] == hole ? nil : array[index]
            array[index] = try selectPaths(
                selection: existing, document: documentArray[index], paths: rest,
                pointer: pointer, includeTypes: includeTypes)
            return .array(array)
        }
    }

    private static func initSelection(source: JSONValue, includeTypes: Bool) -> [String: JSONValue] {
        var selection: [String: JSONValue] = [:]
        if case .string(let id)? = source["id"], !id.hasPrefix("_:") {
            selection["id"] = .string(id)
        }
        if includeTypes, let type = source["type"] {
            selection["type"] = type
        }
        return selection
    }

    /// `{...selection, ...document}` — document wins, selection-only keys kept.
    private static func merge(_ selection: JSONValue?, _ document: JSONValue) -> JSONValue {
        guard case .object(let documentDict) = document else { return document }
        var result = selection?.objectValue ?? [:]
        for (key, value) in documentDict { result[key] = value }
        return .object(result)
    }

    /// Remove sparse-array holes, recursively.
    private static func densify(_ value: JSONValue) -> JSONValue {
        switch value {
        case .array(let array):
            return .array(array.filter { $0 != hole }.map(densify))
        case .object(let object):
            return .object(object.mapValues(densify))
        default:
            return value
        }
    }
}
