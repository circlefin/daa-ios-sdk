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

/// Validated exact bytes for an `X-Device-Authorization` compact-JWS input.
public struct DaaDeviceAuthorizationSigningInput: Equatable, Sendable {
    let exactBytes: Data
    /// The validated operation discriminator, read from the single validation
    /// pass below and never re-parsed. Exposed so a protection-profile gate can
    /// be applied against the operation class without re-decoding the input.
    let operation: DeviceAuthorizationInputValidator.Operation
    /// True for Device Registration Complete (`register_device_key`) and
    /// `complete_social_login`, the enrollment operations an AuthKey may sign
    /// while still created, before its registration is acknowledged. Read from
    /// [operation], never re-parsed.
    let permitsPendingRegistration: Bool

    /// Validate an existing signing input without decoding and re-encoding it.
    public init(exactBytes: Data) throws {
        try self.init(
            exactBytes: exactBytes,
            nowEpochSeconds: Int64(Date().timeIntervalSince1970)
        )
    }

    init(exactBytes: Data, nowEpochSeconds: Int64) throws {
        guard let operation = DeviceAuthorizationInputValidator.validatedOperation(
            exactBytes,
            nowEpochSeconds: nowEpochSeconds
        ) else {
            throw DaaSecureKeyError.invalidSigningInput
        }
        self.exactBytes = exactBytes
        self.operation = operation
        permitsPendingRegistration = operation.permitsPendingRegistration
    }

    func signingBytes(nowEpochSeconds: Int64) throws -> Data {
        guard DeviceAuthorizationInputValidator.validatedOperation(
            exactBytes,
            nowEpochSeconds: nowEpochSeconds
        ) != nil else {
            throw DaaSecureKeyError.invalidSigningInput
        }
        return exactBytes
    }
}

enum DeviceAuthorizationInputValidator {
    enum Operation: String, Sendable {
        case completeSocialLogin = "complete_social_login"
        case getDeviceContext = "get_device_context"
        case createAccount = "create_account"
        case transfer = "transfer"
        case withdrawal = "withdrawal"
        case registerDeviceKey = "register_device_key"

        var permitsPendingRegistration: Bool {
            switch self {
            case .completeSocialLogin, .registerDeviceKey:
                return true
            case .getDeviceContext, .createAccount, .transfer, .withdrawal:
                return false
            }
        }

        /// Whether `.deviceUnlocked` protection — which signs with no
        /// per-signature user verification — may sign this operation. Written
        /// as an allowlist and switched exhaustively with no `default:`, so a
        /// case added to `Operation` later must be given an explicit answer
        /// here instead of silently inheriting a pass.
        var isPermittedUnderDeviceUnlockedProtection: Bool {
            switch self {
            case .getDeviceContext, .registerDeviceKey, .completeSocialLogin:
                return true
            case .createAccount, .transfer, .withdrawal:
                return false
            }
        }

        /// Human-readable label naming this operation in the biometric consent
        /// prompt — never the raw wire discriminator. The wording is a
        /// cross-platform table and must stay byte-for-byte identical to the
        /// `daa-android-sdk` labels. Switched exhaustively with no `default:`,
        /// so a case added later must be given an explicit label here rather
        /// than silently inheriting one.
        var authorizationLabel: String {
            switch self {
            case .transfer:
                return "transfer"
            case .withdrawal:
                return "withdrawal"
            case .createAccount:
                return "account creation"
            case .registerDeviceKey:
                return "device registration"
            case .completeSocialLogin:
                return "sign-in"
            case .getDeviceContext:
                return "device verification"
            }
        }
    }

    private static let allowedHeaderKeys: Set<String> = ["alg", "kid", "typ"]
    private static let allowedPayloadKeys: Set<String> = [
        "aud", "body_sha256", "canonical_path", "discriminator", "exp", "iat",
        "idempotency_key", "jti", "method", "schema_version"
    ]
    private static let maximumAuthorizationLifetime: Int64 = 300
    private static let maximumKeyIDLength = 256
    private static let clockSkewLeeway: Int64 = 60
    private static let emptyBodySHA256 = "47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU"

    static func validatedOperation(
        _ input: Data,
        nowEpochSeconds: Int64
    ) -> Operation? {
        let segments = input.split(
            separator: UInt8(ascii: "."),
            maxSplits: 2,
            omittingEmptySubsequences: false
        )
        guard segments.count == 2,
              let headerData = decodeBase64URL(segments[0]),
              let payloadData = decodeBase64URL(segments[1]),
              !DuplicateJSONKeys.existAtTopLevel(headerData),
              !DuplicateJSONKeys.existAtTopLevel(payloadData),
              let header = jsonObject(headerData),
              let payload = jsonObject(payloadData) else {
            return nil
        }
        guard isValidHeader(header) else {
            return nil
        }
        return validatedOperation(payload, nowEpochSeconds: nowEpochSeconds)
    }

    private static func isValidHeader(_ header: [String: Any]) -> Bool {
        guard Set(header.keys) == allowedHeaderKeys,
              header["alg"] as? String == "ES256",
              header["typ"] as? String == "aw-device-authorization+jws",
              let keyID = header["kid"] as? String else {
            return false
        }
        return isValidKeyID(keyID)
    }

    // Same bound and character class as `canonical_path`: `kid` is otherwise
    // the one claim in this validator with no shape check beyond non-empty,
    // unlike every sibling claim above and below it.
    private static func isValidKeyID(_ keyID: String) -> Bool {
        guard !keyID.isEmpty, keyID.count <= maximumKeyIDLength else {
            return false
        }
        return keyID.unicodeScalars.allSatisfy(isCanonicalPathScalar)
    }

    private static func validatedOperation(
        _ payload: [String: Any],
        nowEpochSeconds: Int64
    ) -> Operation? {
        guard Set(payload.keys).isSubset(of: allowedPayloadKeys),
              let bodyDigest = payload["body_sha256"] as? String,
              decodeBase64URL(Data(bodyDigest.utf8)[...])?.count == 32,
              let discriminator = payload["discriminator"] as? String,
              let operation = Operation(rawValue: discriminator),
              integer(payload["schema_version"]) == 1,
              let path = payload["canonical_path"] as? String,
              isCanonicalPath(path),
              let method = payload["method"] as? String,
              payload["aud"] as? String == "circle-digital-asset-accounts",
              let tokenID = payload["jti"] as? String,
              UUID(uuidString: tokenID) != nil,
              let issuedAt = integer(payload["iat"]),
              let expiresAt = integer(payload["exp"]),
              issuedAt > 0,
              expiresAt > issuedAt,
              expiresAt - issuedAt <= maximumAuthorizationLifetime,
              issuedAt <= nowEpochSeconds + clockSkewLeeway,
              expiresAt >= nowEpochSeconds - clockSkewLeeway else {
            return nil
        }
        guard matchesAllowList(
            operation,
            payload: payload,
            method: method,
            path: path,
            bodyDigest: bodyDigest
        ) else {
            return nil
        }
        return operation
    }

    private static func matchesAllowList(
        _ operation: Operation,
        payload: [String: Any],
        method: String,
        path: String,
        bodyDigest: String
    ) -> Bool {
        switch operation {
        case .completeSocialLogin:
            return isPostWithIdempotency(
                payload,
                method: method,
                path: path,
                expectedPath: "/v1/accounts/auth/sessions"
            )
        case .getDeviceContext:
            return method == "GET"
                && path == "/v1/accounts/auth/context"
                && payload["idempotency_key"] == nil
                && bodyDigest == emptyBodySHA256
        case .createAccount:
            return isPostWithIdempotency(
                payload,
                method: method,
                path: path,
                expectedPath: "/v1/accounts"
            )
        case .transfer:
            return isPostWithIdempotency(
                payload,
                method: method,
                path: path,
                expectedPath: "/v1/accounts/transfers"
            )
        case .withdrawal:
            return isPostWithIdempotency(
                payload,
                method: method,
                path: path,
                expectedPath: "/v1/accounts/withdrawals"
            )
        case .registerDeviceKey:
            return isPostWithIdempotency(
                payload,
                method: method,
                path: path,
                expectedPath: "/v1/accounts/auth/deviceKeyRegistration"
            )
        }
    }

    private static func isPostWithIdempotency(
        _ payload: [String: Any],
        method: String,
        path: String,
        expectedPath: String
    ) -> Bool {
        guard method == "POST",
              path == expectedPath,
              let idempotencyKey = payload["idempotency_key"] as? String,
              UUID(uuidString: idempotencyKey) != nil else {
            return false
        }
        return true
    }

    // Defence in depth: every operation in `matchesAllowList` compares
    // `canonical_path` against a literal, so a path this rejects is rejected
    // there too. It runs first and fails closed, and it would decide the
    // outcome for any allowed path that is not a literal, such as a templated
    // path.
    //
    // `internal` rather than `private` so the rule itself has direct test
    // coverage. Going through a signing input cannot provide that: the
    // allow-list rejects the same strings, so such a test passes whatever this
    // function returns. `internal` is not part of the package's public API.
    static func isCanonicalPath(_ path: String) -> Bool {
        guard path.count > 1,
              path.first == "/",
              path.last != "/" else {
            return false
        }
        let segments = path.dropFirst().split(
            separator: "/",
            omittingEmptySubsequences: false
        )
        return segments.allSatisfy { segment in
            !segment.isEmpty &&
                segment != "." &&
                segment != ".." &&
                segment.unicodeScalars.allSatisfy(isCanonicalPathScalar)
        }
    }

    private static func isCanonicalPathScalar(_ scalar: Unicode.Scalar) -> Bool {
        let value = scalar.value
        return (48...57).contains(value) ||
            (65...90).contains(value) ||
            (97...122).contains(value) ||
            value == 45 || value == 46 || value == 95 || value == 126
    }

    private static func jsonObject(_ data: Data) -> [String: Any]? {
        (try? JSONSerialization.jsonObject(with: data)) as? [String: Any]
    }

    private static func integer(_ value: Any?) -> Int64? {
        guard let number = value as? NSNumber,
              CFGetTypeID(number) != CFBooleanGetTypeID() else {
            return nil
        }
        let double = number.doubleValue
        guard double.isFinite,
              double.rounded(.towardZero) == double,
              double >= Double(Int64.min),
              double <= Double(Int64.max) else {
            return nil
        }
        return number.int64Value
    }

    private static func decodeBase64URL(_ encoded: Data.SubSequence) -> Data? {
        guard !encoded.isEmpty,
              encoded.allSatisfy(isBase64URLByte),
              encoded.count % 4 != 1 else {
            return nil
        }

        guard let original = String(bytes: encoded, encoding: .utf8) else {
            return nil
        }
        let padding = String(repeating: "=", count: (4 - encoded.count % 4) % 4)
        let standardBase64 = original
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        guard let decoded = Data(base64Encoded: standardBase64 + padding),
              Base64URL.encode(decoded) == original else {
            return nil
        }
        return decoded
    }

    private static func isBase64URLByte(_ byte: UInt8) -> Bool {
        (48...57).contains(byte) ||
            (65...90).contains(byte) ||
            (97...122).contains(byte) ||
            byte == 45 || byte == 95
    }
}
