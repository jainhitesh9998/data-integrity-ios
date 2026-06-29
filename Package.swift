// swift-tools-version: 6.0
// DataIntegrity — W3C Verifiable Credential Data Integrity verification & selective
// disclosure (ecdsa-sd-2023, ecdsa-rdfc-2019, eddsa-rdfc-2022, Ed25519Signature2020) for
// Swift / iOS, designed to plug into the Inji Wallet (React Native) the same way
// inji-vci-client-ios-swift does.
import PackageDescription

let package = Package(
    name: "data-integrity-ios",
    platforms: [
        .iOS(.v14),
        .macOS(.v13),
    ],
    products: [
        .library(name: "DataIntegrity", targets: ["DataIntegrity"]),
    ],
    dependencies: [
        // JSON-LD 1.1 expansion + toRDF (Deserialize JSON-LD to RDF). Transitively pulls
        // in swift-rdf-canonize, which we also use directly for RDFC-1.0 canonicalization.
        .package(url: "https://github.com/Kingpin-Apps/swift-jsonld.git", from: "0.1.3"),
        .package(url: "https://github.com/Kingpin-Apps/swift-rdf-canonize.git", from: "0.2.2"),
        // ECDSA (P-256/P-384), Ed25519, SHA-256/384, HMAC. swift-crypto is the
        // cross-platform CryptoKit (already pulled in transitively by rdf-canonize).
        .package(url: "https://github.com/apple/swift-crypto.git", "3.0.0"..<"5.0.0"),
        // CBOR is decoded by a tiny built-in decoder (Suites/Sd/CBORDecode.swift)
        // and encoded by CanonicalCBOR — no third-party CBOR dependency, which
        // also avoids a `swiftcbor` package-identity clash with the wallet.
    ],
    targets: [
        .target(
            name: "DataIntegrity",
            dependencies: [
                .product(name: "JSONLD", package: "swift-jsonld"),
                .product(name: "RDFCanonize", package: "swift-rdf-canonize"),
                .product(name: "Crypto", package: "swift-crypto"),
            ],
            resources: [
                .copy("Resources/contexts"),
            ]
        ),
        .testTarget(
            name: "DataIntegrityTests",
            dependencies: ["DataIntegrity"],
            resources: [
                .copy("Vectors"),
            ]
        ),
    ]
)
