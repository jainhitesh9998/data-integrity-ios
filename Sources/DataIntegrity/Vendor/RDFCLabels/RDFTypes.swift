extension RDFCLabels {
    /// A single RDF quad: subject + predicate + object + optional
    /// graph name.
    public struct Quad: Sendable, Hashable {
        public var subject: Term
        public var predicate: Term
        public var object: Term
        public var graph: Term?

        public init(subject: Term, predicate: Term, object: Term, graph: Term? = nil) {
            self.subject = subject
            self.predicate = predicate
            self.object = object
            self.graph = graph
        }
    }

    /// An RDF term: IRI, blank node, or literal.
    public enum Term: Sendable, Hashable {
        case iri(String)
        case blankNode(String)
        case literal(Literal)
    }

    /// An RDF literal: lexical form, datatype, optional language /
    /// direction.
    public struct Literal: Sendable, Hashable {
        public var value: String
        public var datatype: String
        public var language: String?
        public var direction: String?

        public static let xsdString = "http://www.w3.org/2001/XMLSchema#string"
        public static let rdfLangString = "http://www.w3.org/1999/02/22-rdf-syntax-ns#langString"

        public init(
            value: String,
            datatype: String = Literal.xsdString,
            language: String? = nil,
            direction: String? = nil
        ) {
            self.value = value
            self.datatype = datatype
            self.language = language
            self.direction = direction
        }
    }
}
