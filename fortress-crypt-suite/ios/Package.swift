//
//  Fortress Crypt — 6-layer cascade encryption system
//  Copyright (C) 2025 Steve Watts, The Lion's Kingdom IT Solutions, LLC
//
//  This program is free software: you can redistribute it and/or modify
//  it under the terms of the GNU Affero General Public License as published
//  by the Free Software Foundation, either version 3 of the License, or
//  (at your option) any later version.
//
//  This program is distributed in the hope that it will be useful,
//  but WITHOUT ANY WARRANTY; without even the implied warranty of
//  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//  GNU Affero General Public License for more details.
//
//  You should have received a copy of the GNU Affero General Public License
//  along with this program.  If not, see <https://www.gnu.org/licenses/>.
//
//  For commercial licensing without the AGPL's copyleft obligations,
//  contact the Maintainer (see README).
//

// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "FortressCrypt",
    platforms: [
        .iOS(.v17),
        .macOS(.v14)
    ],
    products: [
        .library(name: "FortressCryptoEngine", targets: ["FortressCryptoEngine"]),
    ],
    dependencies: [
        // OpenSSL for Camellia-256-CBC, scrypt, SHA3
        .package(url: "https://github.com/nicklama/swift-openssl", from: "3.1.0"),
        // Argon2id
        .package(url: "https://github.com/nicklama/swift-argon2", from: "1.0.0"),
        // liboqs for ML-KEM-1024 (post-quantum)
        .package(url: "https://github.com/nicklama/liboqs-swift", from: "0.10.0"),
    ],
    targets: [
        .target(
            name: "FortressCryptoEngine",
            dependencies: [
                .product(name: "OpenSSL", package: "swift-openssl"),
                .product(name: "Argon2", package: "swift-argon2"),
            ],
            path: "FortressCrypt/Crypto"
        ),
    ]
)
