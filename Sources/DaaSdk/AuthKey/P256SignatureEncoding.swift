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

import CryptoKit
import Foundation

enum P256SignatureEncoding {
    private static let rawByteCount = 64
    private static let scalarByteCount = rawByteCount / 2
    private static let groupOrder = Data([
        0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84,
        0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63, 0x25, 0x51
    ])

    static func rawRepresentation(fromDER der: Data) throws -> Data {
        do {
            let signature = try P256.Signing.ECDSASignature(derRepresentation: der)
            let raw = signature.rawRepresentation
            guard signature.derRepresentation == der, hasValidScalars(raw) else {
                throw AuthKeyWireError.malformedECDSASignature
            }
            return raw
        } catch {
            throw AuthKeyWireError.malformedECDSASignature
        }
    }

    static func derRepresentation(fromRaw raw: Data) throws -> Data {
        try signature(fromRaw: raw).derRepresentation
    }

    static func signature(fromRaw raw: Data) throws -> P256.Signing.ECDSASignature {
        guard hasValidScalars(raw) else {
            throw AuthKeyWireError.malformedECDSASignature
        }

        do {
            return try P256.Signing.ECDSASignature(rawRepresentation: raw)
        } catch {
            throw AuthKeyWireError.malformedECDSASignature
        }
    }

    private static func hasValidScalars(_ raw: Data) -> Bool {
        guard raw.count == rawByteCount else {
            return false
        }

        let midpoint = raw.index(raw.startIndex, offsetBy: scalarByteCount)
        return isValidScalar(raw[..<midpoint]) && isValidScalar(raw[midpoint...])
    }

    private static func isValidScalar(_ scalar: Data.SubSequence) -> Bool {
        scalar.contains(where: { $0 != 0 }) && scalar.lexicographicallyPrecedes(groupOrder)
    }
}
