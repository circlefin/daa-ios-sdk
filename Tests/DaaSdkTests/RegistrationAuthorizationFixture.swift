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

@testable import DaaSdk

enum RegistrationAuthorizationFixture {
    static let flowTyp = "daa-registration-flow-authorization+jws"
    static let deviceTyp = "daa-device-authorization+jws"
    static let profileID = String(repeating: "p", count: 22)

    /// The binding claims only the flow proof carries. A device payload that
    /// carries any of them is malformed.
    static let bindingClaims = [
        "auth_key_thumbprint", "code_verifier_sha256", "profile_id", "registration_handle_sha256"
    ]

    /// An embedded JWK for a fresh random key, i.e. one no test signer holds.
    static func embeddedJWK() -> [String: Any] {
        embeddedJWK(x963: P256.Signing.PrivateKey().publicKey.x963Representation)
    }

    /// An embedded JWK for the given uncompressed X9.63 P-256 point.
    static func embeddedJWK(x963 point: Data) -> [String: Any] {
        let xCoordinate = point.subdata(in: 1..<33)
        let yCoordinate = point.subdata(in: 33..<65)
        return [
            "kty": "EC",
            "crv": "P-256",
            "x": Base64URL.encode(xCoordinate),
            "y": Base64URL.encode(yCoordinate)
        ]
    }

    static func header(
        typ: String = flowTyp,
        jwk: [String: Any] = embeddedJWK()
    ) -> [String: Any] {
        [
            "alg": "ES256",
            "jwk": jwk,
            "typ": typ
        ]
    }

    /// Shape-valid but arbitrary — matches no real key's thumbprint. The flow
    /// payload's `auth_key_thumbprint` names the AuthKey, not the flow key that
    /// signs the flow proof, so no signing site compares it against its own
    /// key and any shape-valid value works.
    static let unmatchedAuthKeyThumbprint = Base64URL.encode(Data(repeating: 0xCD, count: 32))

    /// The ten claims both registration proofs carry. This is the complete
    /// device-proof payload.
    static func devicePayload(
        nowEpochSeconds: Int64 = Int64(Date().timeIntervalSince1970)
    ) -> [String: Any] {
        [
            "aud": "circle-digital-asset-accounts",
            "body_sha256": Base64URL.encode(Data(repeating: 0xAB, count: 32)),
            "canonical_path": "/v1/accounts/auth/deviceKeyRegistration",
            "discriminator": "device_key_registration.v1",
            "exp": nowEpochSeconds + 300,
            "iat": nowEpochSeconds,
            "idempotency_key": "01234567-89ab-cdef-0123-456789abcdef",
            "jti": "11111111-1111-4111-8111-111111111111",
            "method": "POST",
            "schema_version": 1
        ]
    }

    /// The fourteen-claim flow-proof payload: the device claims plus the four
    /// binding claims.
    static func payload(
        nowEpochSeconds: Int64 = Int64(Date().timeIntervalSince1970),
        authKeyThumbprint: String = unmatchedAuthKeyThumbprint
    ) -> [String: Any] {
        devicePayload(nowEpochSeconds: nowEpochSeconds).merging([
            "auth_key_thumbprint": authKeyThumbprint,
            "code_verifier_sha256": Base64URL.encode(Data(repeating: 0x22, count: 32)),
            "profile_id": profileID,
            "registration_handle_sha256": Base64URL.encode(Data(repeating: 0x11, count: 32))
        ]) { _, binding in binding }
    }

    static func signingInput(
        header: [String: Any]? = nil,
        payload: [String: Any]? = nil
    ) throws -> Data {
        let headerObject = header ?? Self.header()
        let payloadObject = payload ?? Self.payload()
        let headerData = try JSONSerialization.data(withJSONObject: headerObject)
        let payloadData = try JSONSerialization.data(withJSONObject: payloadObject)
        return Data("\(Base64URL.encode(headerData)).\(Base64URL.encode(payloadData))".utf8)
    }
}
