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

@testable import DaaSdk

enum DeviceAuthorizationFixture {
    static let emptyBodySHA256 = "47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU"

    static func header() -> [String: Any] {
        [
            "alg": "ES256",
            "kid": "auth-key-1",
            "typ": "aw-device-authorization+jws"
        ]
    }

    static func completeSocialLoginPayload(
        nowEpochSeconds: Int64 = Int64(Date().timeIntervalSince1970)
    ) -> [String: Any] {
        postPayload(
            discriminator: "complete_social_login",
            canonicalPath: "/v1/accounts/auth/sessions",
            nowEpochSeconds: nowEpochSeconds
        )
    }

    private static func postPayload(
        discriminator: String,
        canonicalPath: String,
        nowEpochSeconds: Int64
    ) -> [String: Any] {
        [
            "aud": "circle-digital-asset-accounts",
            "body_sha256": Base64URL.encode(Data(repeating: 0xAB, count: 32)),
            "canonical_path": canonicalPath,
            "discriminator": discriminator,
            "exp": nowEpochSeconds + 300,
            "iat": nowEpochSeconds,
            "idempotency_key": "01234567-89ab-cdef-0123-456789abcdef",
            "jti": "11111111-1111-4111-8111-111111111111",
            "method": "POST",
            "schema_version": 1
        ]
    }

    static func getDeviceContextPayload(
        nowEpochSeconds: Int64 = Int64(Date().timeIntervalSince1970)
    ) -> [String: Any] {
        [
            "aud": "circle-digital-asset-accounts",
            "body_sha256": emptyBodySHA256,
            "canonical_path": "/v1/accounts/auth/context",
            "discriminator": "get_device_context",
            "exp": nowEpochSeconds + 300,
            "iat": nowEpochSeconds,
            "jti": "11111111-1111-4111-8111-111111111111",
            "method": "GET",
            "schema_version": 1
        ]
    }

    static func createAccountPayload(
        nowEpochSeconds: Int64 = Int64(Date().timeIntervalSince1970)
    ) -> [String: Any] {
        postPayload(
            discriminator: "create_account",
            canonicalPath: "/v1/accounts",
            nowEpochSeconds: nowEpochSeconds
        )
    }

    static func transferPayload(
        nowEpochSeconds: Int64 = Int64(Date().timeIntervalSince1970)
    ) -> [String: Any] {
        postPayload(
            discriminator: "transfer",
            canonicalPath: "/v1/accounts/transfers",
            nowEpochSeconds: nowEpochSeconds
        )
    }

    static func withdrawalPayload(
        nowEpochSeconds: Int64 = Int64(Date().timeIntervalSince1970)
    ) -> [String: Any] {
        postPayload(
            discriminator: "withdrawal",
            canonicalPath: "/v1/accounts/withdrawals",
            nowEpochSeconds: nowEpochSeconds
        )
    }

    static func registerDeviceKeyPayload(
        nowEpochSeconds: Int64 = Int64(Date().timeIntervalSince1970)
    ) -> [String: Any] {
        postPayload(
            discriminator: "register_device_key",
            canonicalPath: "/v1/accounts/auth/deviceKeyRegistration",
            nowEpochSeconds: nowEpochSeconds
        )
    }

    static func contextSigningInput() throws -> Data {
        try signingInput(payload: getDeviceContextPayload())
    }

    static func signingInput(
        header: [String: Any] = header(),
        payload: [String: Any]
    ) throws -> Data {
        let headerData = try JSONSerialization.data(withJSONObject: header)
        let payloadData = try JSONSerialization.data(withJSONObject: payload)
        return Data("\(Base64URL.encode(headerData)).\(Base64URL.encode(payloadData))".utf8)
    }

}
