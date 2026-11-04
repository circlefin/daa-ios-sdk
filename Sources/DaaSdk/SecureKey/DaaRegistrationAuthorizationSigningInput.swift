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

/// Validated exact bytes for a Device Registration Complete compact-JWS input.
///
/// Complete uses two registration headers, not `X-Device-Authorization`. Both
/// embed the signer's public JWK (no `kid`) because the AuthKey is not
/// registered yet. This type accepts both `typ` values and does not re-encode
/// the supplied signing input.
///
/// The two `typ` values share one header shape but carry different payload
/// claim sets, and the claim set is chosen by the validated `typ`:
///
/// - `flowAuthorization` carries the full binding set: the shared claims plus
///   `registration_handle_sha256`, `profile_id`, `auth_key_thumbprint`, and
///   `code_verifier_sha256`.
/// - `deviceAuthorization` is a possession-only proof and carries exactly the
///   shared claims and none of the binding claims. Circle decodes it
///   strictly, so a device payload that carries any binding claim is rejected
///   here rather than signed and rejected by Circle.
///
/// The validated `typ` is retained as `typ` below and exposed within the
/// module. Accepting both shapes here is deliberate — see
/// `RegistrationAuthorizationInputValidator.validatedFields` — but a signing
/// call site is not: `signRegistrationAuthorization` and
/// `signRegistrationDeviceAuthorization` each bind to exactly one `typ` and
/// fail closed on the other, using this property, so the flow key cannot mint
/// the device-typed proof or vice versa.
///
/// The RFC 7638 thumbprint of the embedded header `jwk` is retained the same
/// way, for a different gap: this type proves the header `jwk` is shaped like a
/// P-256 JWK (exact members, 32-byte coordinates; not checked to be on the
/// curve), but it does not, and cannot, prove that `jwk` is the public half of
/// the key that is about to sign. That comparison needs the
/// actual signer, which this type does not have.
/// `signRegistrationDeviceAuthorization` reads `headerJWKThumbprint` to compare
/// against its own key's `thumbprint()` before signing, so a device proof that
/// names a different key in its header is rejected rather than signed anyway.
/// The device payload has no `auth_key_thumbprint` claim, so the header `jwk`
/// is the only statement in a device proof of which key signs it.
public struct DaaRegistrationAuthorizationSigningInput: Equatable, Sendable {
    let exactBytes: Data
    /// The `typ` validated at construction. Stored here so a signing-time
    /// binding check reads the value construction already proved, rather than
    /// re-parsing `exactBytes` against the current clock.
    let typ: RegistrationAuthorizationInputValidator.Typ
    /// RFC 7638 thumbprint of the embedded header `jwk`, derived at
    /// construction from the validated coordinates. It proves which key the
    /// header names, not that this key signs. See the type-level doc comment
    /// above.
    let headerJWKThumbprint: String

    /// Validate an existing signing input without decoding and re-encoding it.
    public init(exactBytes: Data) throws {
        try self.init(
            exactBytes: exactBytes,
            nowEpochSeconds: Int64(Date().timeIntervalSince1970)
        )
    }

    init(exactBytes: Data, nowEpochSeconds: Int64) throws {
        guard let fields = RegistrationAuthorizationInputValidator.validatedFields(
            exactBytes,
            nowEpochSeconds: nowEpochSeconds
        ) else {
            throw DaaSecureKeyError.invalidSigningInput
        }
        self.exactBytes = exactBytes
        self.typ = fields.typ
        self.headerJWKThumbprint = fields.headerJWKThumbprint
    }

    func signingBytes(nowEpochSeconds: Int64) throws -> Data {
        guard RegistrationAuthorizationInputValidator.validatedFields(
            exactBytes,
            nowEpochSeconds: nowEpochSeconds
        ) != nil else {
            throw DaaSecureKeyError.invalidSigningInput
        }
        return exactBytes
    }
}

/// `internal` (not `private`) so the validated `typ` can be named as the type
/// of `DaaRegistrationAuthorizationSigningInput.typ` above and compared
/// against at a signing call site elsewhere in this module. `internal` is not
/// part of the package's public API surface.
enum RegistrationAuthorizationInputValidator {
    /// `deviceAuthorization` here is a distinct namespace from the unrelated
    /// `aw-device-authorization+jws` used by `DeviceAuthorizationInputValidator`'s
    /// `X-Device-Authorization` header profile (disjoint header/payload shapes:
    /// `jwk` here vs. `kid` there) — the similar spelling is coincidental.
    enum Typ: String {
        case flowAuthorization = "daa-registration-flow-authorization+jws"
        case deviceAuthorization = "daa-device-authorization+jws"
    }

    private enum CanonicalRegistrationPath: String {
        case deviceKeyRegistration = "/v1/accounts/auth/deviceKeyRegistration"
    }

    private enum Method: String {
        case post = "POST"
    }

    private static let allowedHeaderKeys: Set<String> = ["alg", "typ", "jwk"]
    private static let allowedJWKKeys: Set<String> = ["kty", "crv", "x", "y"]
    /// Claims both registration proofs carry, with the same value rules.
    private static let sharedPayloadKeys: Set<String> = [
        "aud", "body_sha256", "canonical_path", "discriminator", "exp", "iat",
        "idempotency_key", "jti", "method", "schema_version"
    ]
    /// Claims that bind the registration session to the AuthKey. Only the
    /// flow proof carries them; the device proof must carry none of them.
    private static let bindingPayloadKeys: Set<String> = [
        "auth_key_thumbprint", "code_verifier_sha256", "profile_id",
        "registration_handle_sha256"
    ]
    private static let expectedDiscriminator = "device_key_registration.v1"
    private static let expectedSchemaVersion: Int64 = 1
    private static let maximumAuthorizationLifetime: Int64 = 300
    private static let clockSkewLeeway: Int64 = 60
    private static let profileIDLength = 22...256

    /// The exact payload claim set for `typ`: the shared claims plus, for the
    /// flow proof only, the binding claims.
    static func requiredPayloadKeys(for typ: Typ) -> Set<String> {
        switch typ {
        case .flowAuthorization:
            return sharedPayloadKeys.union(bindingPayloadKeys)
        case .deviceAuthorization:
            return sharedPayloadKeys
        }
    }

    /// The `typ` and header `jwk` thumbprint validated together from one
    /// parse, so a caller never has to re-parse `exactBytes` to get the second
    /// value after already having the first.
    struct Fields {
        let typ: Typ
        let headerJWKThumbprint: String
    }

    /// Validate the exact bytes and return the fields a signing call site
    /// binds against.
    ///
    /// Both `typ` values share this one validation on purpose — see the doc
    /// comment on `DaaRegistrationAuthorizationSigningInput` above. The header
    /// shape is the same for both; the payload claim set is the one
    /// `requiredPayloadKeys(for:)` returns for the validated `typ`. This
    /// function does not decide which `typ` a caller may sign with, nor
    /// whether the header `jwk` belongs to whichever key ends up signing; it
    /// only proves the bytes are well-formed and returns the two fields a
    /// signing call site needs in order to decide both of those for itself.
    static func validatedFields(_ input: Data, nowEpochSeconds: Int64) -> Fields? {
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
              let payload = jsonObject(payloadData),
              let fields = validatedHeader(header),
              isValidPayload(payload, typ: fields.typ, nowEpochSeconds: nowEpochSeconds) else {
            return nil
        }
        return fields
    }

    /// Validate the header and return its `typ` and the RFC 7638 thumbprint of
    /// its embedded `jwk`.
    private static func validatedHeader(_ header: [String: Any]) -> Fields? {
        guard Set(header.keys) == allowedHeaderKeys,
              header["alg"] as? String == "ES256",
              let typRaw = header["typ"] as? String,
              let typ = Typ(rawValue: typRaw),
              let jwk = header["jwk"] as? [String: Any],
              let thumbprint = embeddedJWKThumbprint(jwk) else {
            return nil
        }
        switch typ {
        case .flowAuthorization, .deviceAuthorization:
            break
        }
        return Fields(typ: typ, headerJWKThumbprint: thumbprint)
    }

    /// Validate the embedded JWK and return its RFC 7638 thumbprint.
    ///
    /// The coordinates are decoded with `decodeBase64URL`, which accepts only
    /// canonical unpadded Base64URL, so the thumbprint is computed over the
    /// same coordinate strings the header carries.
    private static func embeddedJWKThumbprint(_ jwk: [String: Any]) -> String? {
        guard Set(jwk.keys) == allowedJWKKeys,
              jwk["kty"] as? String == "EC",
              jwk["crv"] as? String == "P-256",
              let xCoordinate = decodedSHA256Bytes(jwk["x"]),
              let yCoordinate = decodedSHA256Bytes(jwk["y"]),
              let thumbprint = try? P256PublicKeyEncoding.jwkThumbprint(
                xCoordinate: xCoordinate,
                yCoordinate: yCoordinate
              ) else {
            return nil
        }
        return thumbprint
    }

    /// Validate the payload against the exact claim set for `typ` and the
    /// value rules for every claim it carries.
    ///
    /// The flow payload's `auth_key_thumbprint` is validated only for shape
    /// (see `isUnpaddedSHA256` below). It names the AuthKey, not the flow
    /// key that signs the flow proof, so no signing call site compares it
    /// against its own key.
    private static func isValidPayload(
        _ payload: [String: Any],
        typ: Typ,
        nowEpochSeconds: Int64
    ) -> Bool {
        guard Set(payload.keys) == requiredPayloadKeys(for: typ),
              isValidSharedClaims(payload, nowEpochSeconds: nowEpochSeconds) else {
            return false
        }
        switch typ {
        case .flowAuthorization:
            return isValidBindingClaims(payload)
        case .deviceAuthorization:
            return true
        }
    }

    private static func isValidSharedClaims(
        _ payload: [String: Any],
        nowEpochSeconds: Int64
    ) -> Bool {
        guard payload["discriminator"] as? String == expectedDiscriminator,
              integer(payload["schema_version"]) == expectedSchemaVersion,
              isUnpaddedSHA256(payload["body_sha256"]),
              let pathRaw = payload["canonical_path"] as? String,
              let path = CanonicalRegistrationPath(rawValue: pathRaw),
              let methodRaw = payload["method"] as? String,
              let method = Method(rawValue: methodRaw),
              payload["aud"] as? String == "circle-digital-asset-accounts",
              let idempotencyKey = payload["idempotency_key"] as? String,
              UUID(uuidString: idempotencyKey) != nil,
              let tokenID = payload["jti"] as? String,
              UUID(uuidString: tokenID) != nil,
              let issuedAt = integer(payload["iat"]),
              let expiresAt = integer(payload["exp"]),
              issuedAt > 0,
              expiresAt > issuedAt,
              expiresAt - issuedAt <= maximumAuthorizationLifetime,
              issuedAt <= nowEpochSeconds + clockSkewLeeway,
              expiresAt >= nowEpochSeconds - clockSkewLeeway else {
            return false
        }
        switch path {
        case .deviceKeyRegistration:
            break
        }
        switch method {
        case .post:
            break
        }
        return true
    }

    private static func isValidBindingClaims(_ payload: [String: Any]) -> Bool {
        guard isUnpaddedSHA256(payload["registration_handle_sha256"]),
              isUnpaddedSHA256(payload["code_verifier_sha256"]),
              isUnpaddedSHA256(payload["auth_key_thumbprint"]),
              let profileID = payload["profile_id"] as? String,
              profileIDLength.contains(profileID.count) else {
            return false
        }
        return true
    }

    private static func isUnpaddedSHA256(_ value: Any?) -> Bool {
        decodedSHA256Bytes(value) != nil
    }

    /// The decoded bytes of a canonical unpadded Base64URL string that
    /// decodes to exactly 32 bytes, or `nil`.
    private static func decodedSHA256Bytes(_ value: Any?) -> Data? {
        guard let encoded = value as? String,
              let decoded = decodeBase64URL(Data(encoded.utf8)[...]),
              decoded.count == 32 else {
            return nil
        }
        return decoded
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
