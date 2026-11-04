// Copyright (c) 2026, Circle Internet Group, Inc. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

import Foundation

struct AuthKeyWireFixture: Decodable {
    struct P256PublicKey: Decodable {
        let x963Hex: String
        let spkiBase64Url: String
        let jwkThumbprint: String
    }

    struct ECDSASignature: Decodable {
        let name: String
        let derHex: String
        let rawHex: String
    }

    struct SignedMessage: Decodable {
        let name: String
        let messageHex: String
        let publicKeyX963Hex: String
        let derHex: String
        let rawHex: String
    }

    struct NamedHex: Decodable {
        let name: String
        let hex: String
    }

    struct Rejected: Decodable {
        let ecdsaDer: [NamedHex]
        let ecdsaRaw: [NamedHex]
        let x963PublicKeys: [NamedHex]
        let subjectPublicKeyInfo: [NamedHex]
    }

    let profile: String
    let contract: String
    let p256PublicKey: P256PublicKey
    let signedMessage: SignedMessage
    let ecdsaSignatures: [ECDSASignature]
    let rejected: Rejected

    static func load() throws -> AuthKeyWireFixture {
        let url = Bundle.module.url(
            forResource: "AuthKeyWireV1",
            withExtension: "json",
            subdirectory: "Fixtures"
        )
        guard let url else {
            throw FixtureError.missing
        }

        let bundledData = try Data(contentsOf: url)
        let canonicalData = try Data(contentsOf: canonicalURL)
        guard bundledData == canonicalData else {
            throw FixtureError.outOfSync
        }

        let fixture = try JSONDecoder().decode(AuthKeyWireFixture.self, from: bundledData)
        guard fixture.profile == "daa-authkey-wire-v1",
              fixture.contract == "docs/authkey-wire-contract.md" else {
            throw FixtureError.invalidMetadata
        }
        return fixture
    }

    private static var canonicalURL: URL {
        URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .appendingPathComponent("Conformance/AuthKeyWireV1.json")
    }
}

enum FixtureError: Error {
    case missing
    case invalidMetadata
    case outOfSync
}

extension Data {
    init?(hexadecimal: String) {
        let compact = hexadecimal.filter { !$0.isWhitespace }
        guard compact.count.isMultiple(of: 2) else {
            return nil
        }

        var bytes = [UInt8]()
        bytes.reserveCapacity(compact.count / 2)
        var index = compact.startIndex
        while index < compact.endIndex {
            let next = compact.index(index, offsetBy: 2)
            guard let byte = UInt8(compact[index..<next], radix: 16) else {
                return nil
            }
            bytes.append(byte)
            index = next
        }
        self.init(bytes)
    }
}
