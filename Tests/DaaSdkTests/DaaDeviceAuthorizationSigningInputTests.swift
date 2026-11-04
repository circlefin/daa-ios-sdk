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
import XCTest

@testable import DaaSdk

final class DaaDeviceAuthorizationSigningInputTests: XCTestCase {
    func testAcceptsCompleteSocialLoginAndPreservesExactBytes() throws {
        let exactBytes = try DeviceAuthorizationFixture.signingInput(
            payload: DeviceAuthorizationFixture.completeSocialLoginPayload()
        )
        let input = try DaaDeviceAuthorizationSigningInput(exactBytes: exactBytes)

        XCTAssertEqual(input.exactBytes, exactBytes)
    }

    func testAcceptsBodylessGetDeviceContextAndPreservesExactBytes() throws {
        let exactBytes = try DeviceAuthorizationFixture.signingInput(
            payload: DeviceAuthorizationFixture.getDeviceContextPayload()
        )
        let input = try DaaDeviceAuthorizationSigningInput(exactBytes: exactBytes)

        XCTAssertEqual(input.exactBytes, exactBytes)
    }

    func testRejectsExpiredAndTooFarFutureInputsAtConstruction() throws {
        let now: Int64 = 1_700_000_000
        let expired = try DeviceAuthorizationFixture.signingInput(
            payload: DeviceAuthorizationFixture.completeSocialLoginPayload(
                nowEpochSeconds: now - 361
            )
        )
        let future = try DeviceAuthorizationFixture.signingInput(
            payload: DeviceAuthorizationFixture.completeSocialLoginPayload(
                nowEpochSeconds: now + 61
            )
        )

        assertInvalid(expired, nowEpochSeconds: now)
        assertInvalid(future, nowEpochSeconds: now)
    }

    func testAcceptsInclusiveFreshnessSkewBoundaries() throws {
        let now: Int64 = 1_700_000_000
        let issuedAtFutureBoundary = try DeviceAuthorizationFixture.signingInput(
            payload: DeviceAuthorizationFixture.completeSocialLoginPayload(
                nowEpochSeconds: now + 60
            )
        )
        let expiresAtPastBoundary = try DeviceAuthorizationFixture.signingInput(
            payload: DeviceAuthorizationFixture.completeSocialLoginPayload(
                nowEpochSeconds: now - 360
            )
        )

        XCTAssertNoThrow(try DaaDeviceAuthorizationSigningInput(
            exactBytes: issuedAtFutureBoundary,
            nowEpochSeconds: now
        ))
        XCTAssertNoThrow(try DaaDeviceAuthorizationSigningInput(
            exactBytes: expiresAtPastBoundary,
            nowEpochSeconds: now
        ))
    }

    func testRevalidatesFreshnessImmediatelyBeforeSigning() throws {
        let now: Int64 = 1_700_000_000
        let exactBytes = try DeviceAuthorizationFixture.signingInput(
            payload: DeviceAuthorizationFixture.completeSocialLoginPayload(
                nowEpochSeconds: now - 1
            )
        )
        let input = try DaaDeviceAuthorizationSigningInput(
            exactBytes: exactBytes,
            nowEpochSeconds: now
        )

        XCTAssertThrowsError(try input.signingBytes(nowEpochSeconds: now + 361)) { error in
            XCTAssertEqual(error as? DaaSecureKeyError, .invalidSigningInput)
        }
    }

    func testRejectsNonJWSAndMalformedSegments() throws {
        let header = try JSONSerialization.data(
            withJSONObject: DeviceAuthorizationFixture.header()
        )
        let nonObjectPayload = Base64URL.encode(Data("[]".utf8))
        let invalidInputs = [
            Data("arbitrary bytes".utf8),
            Data("a.b.c".utf8),
            Data("=.abc".utf8),
            Data("abc.".utf8),
            Data("\(Base64URL.encode(header)).\(nonObjectPayload)".utf8)
        ]

        for input in invalidInputs {
            assertInvalid(input)
        }
    }

    func testRejectsWrongProtectedHeaderProfile() throws {
        let invalidHeaders: [[String: Any]] = [
            ["alg": "RS256", "kid": "key-1", "typ": "aw-device-authorization+jws"],
            ["alg": "ES256", "kid": "", "typ": "aw-device-authorization+jws"],
            ["alg": "ES256", "kid": "key-1", "typ": "JWT"],
            [
                "alg": "ES256",
                "jwk": ["kty": "EC"],
                "kid": "key-1",
                "typ": "aw-device-authorization+jws"
            ]
        ]

        for header in invalidHeaders {
            assertInvalid(try DeviceAuthorizationFixture.signingInput(
                header: header,
                payload: DeviceAuthorizationFixture.completeSocialLoginPayload()
            ))
        }
    }

    /// `kid` beyond the length cap or outside the `[A-Za-z0-9._~-]`
    /// allowlist is rejected, mirroring `canonical_path`'s allowlist.
    func testRejectsKeyIDOutsideLengthOrCharacterAllowlist() throws {
        let maximumKeyIDLength = 256
        let tooLongKeyID = String(repeating: "a", count: maximumKeyIDLength + 1)
        // BEL (U+0007): a C0 control character a length-only check would let through.
        let controlCharacterKeyID = "key-\u{0007}-1"
        // é (U+00E9): non-ASCII, also outside a length-only check.
        let nonASCIIKeyID = "key-\u{00E9}-1"

        let invalidHeaders: [[String: Any]] = [
            ["alg": "ES256", "kid": tooLongKeyID, "typ": "aw-device-authorization+jws"],
            ["alg": "ES256", "kid": controlCharacterKeyID, "typ": "aw-device-authorization+jws"],
            ["alg": "ES256", "kid": nonASCIIKeyID, "typ": "aw-device-authorization+jws"]
        ]

        for header in invalidHeaders {
            assertInvalid(try DeviceAuthorizationFixture.signingInput(
                header: header,
                payload: DeviceAuthorizationFixture.completeSocialLoginPayload()
            ))
        }
    }

    /// The length cap is inclusive, and the fixture's default `kid` is not
    /// rejected by the length and character-class checks.
    func testAcceptsKeyIDAtTheLengthCapAndTheDefaultKeyID() throws {
        let maximumKeyIDLength = 256
        let atCapKeyID = String(repeating: "a", count: maximumKeyIDLength)

        var atCapHeader = DeviceAuthorizationFixture.header()
        atCapHeader["kid"] = atCapKeyID

        XCTAssertNoThrow(try DaaDeviceAuthorizationSigningInput(
            exactBytes: DeviceAuthorizationFixture.signingInput(
                header: atCapHeader,
                payload: DeviceAuthorizationFixture.completeSocialLoginPayload()
            )
        ))

        XCTAssertNoThrow(try DaaDeviceAuthorizationSigningInput(
            exactBytes: DeviceAuthorizationFixture.signingInput(
                payload: DeviceAuthorizationFixture.completeSocialLoginPayload()
            )
        ))
    }

    func testRejectsInvalidSharedClaims() throws {
        let now: Int64 = 1_700_000_000

        var wrongAudience = DeviceAuthorizationFixture.completeSocialLoginPayload(
            nowEpochSeconds: now
        )
        wrongAudience["aud"] = "circle-wallets"

        var stringSchemaVersion = DeviceAuthorizationFixture.completeSocialLoginPayload(
            nowEpochSeconds: now
        )
        stringSchemaVersion["schema_version"] = "1"

        var wrongSchemaVersion = DeviceAuthorizationFixture.completeSocialLoginPayload(
            nowEpochSeconds: now
        )
        wrongSchemaVersion["schema_version"] = 2

        var wrongBodyDigest = DeviceAuthorizationFixture.completeSocialLoginPayload(
            nowEpochSeconds: now
        )
        wrongBodyDigest["body_sha256"] = Base64URL.encode(Data(repeating: 0, count: 31))

        var malformedJti = DeviceAuthorizationFixture.completeSocialLoginPayload(
            nowEpochSeconds: now
        )
        malformedJti["jti"] = "not-a-uuid"

        var booleanIssuedAt = DeviceAuthorizationFixture.completeSocialLoginPayload(
            nowEpochSeconds: now
        )
        booleanIssuedAt["iat"] = true

        var negativeLifetime = DeviceAuthorizationFixture.completeSocialLoginPayload(
            nowEpochSeconds: now
        )
        negativeLifetime["iat"] = -2
        negativeLifetime["exp"] = -1

        var longLifetime = DeviceAuthorizationFixture.completeSocialLoginPayload(
            nowEpochSeconds: now
        )
        longLifetime["exp"] = now + 301

        var extra = DeviceAuthorizationFixture.completeSocialLoginPayload()
        extra["resource"] = "wallet"

        for payload in [
            wrongAudience, stringSchemaVersion, wrongSchemaVersion, wrongBodyDigest,
            malformedJti, booleanIssuedAt, negativeLifetime, longLifetime, extra
        ] {
            assertInvalid(
                try DeviceAuthorizationFixture.signingInput(payload: payload),
                nowEpochSeconds: now
            )
        }
    }

    func testRejectsInvalidCompleteSocialLoginOperationBinding() throws {
        var missingIdempotency = DeviceAuthorizationFixture.completeSocialLoginPayload()
        missingIdempotency.removeValue(forKey: "idempotency_key")

        var malformedIdempotency = DeviceAuthorizationFixture.completeSocialLoginPayload()
        malformedIdempotency["idempotency_key"] = "not-a-uuid"

        var wrongPath = DeviceAuthorizationFixture.completeSocialLoginPayload()
        wrongPath["canonical_path"] = "/v1/accounts/auth/context"

        var wrongMethod = DeviceAuthorizationFixture.completeSocialLoginPayload()
        wrongMethod["method"] = "GET"

        var wrongDiscriminator = DeviceAuthorizationFixture.completeSocialLoginPayload()
        wrongDiscriminator["discriminator"] = "get_device_context"

        for payload in [
            missingIdempotency, malformedIdempotency, wrongPath, wrongMethod, wrongDiscriminator
        ] {
            assertInvalid(try DeviceAuthorizationFixture.signingInput(payload: payload))
        }
    }

    /// The canonical-path rule itself, exercised directly.
    ///
    /// Driving the rule through a signing input cannot test it:
    /// `matchesAllowList` compares the path against a literal, so those
    /// assertions hold whatever `isCanonicalPath` returns. Calling it directly
    /// is the only way a break in the parser — accepting `..`, an empty
    /// segment, or a raw separator — fails a test.
    func testCanonicalPathRule() {
        let rejected = [
            "/v1/accounts/../accounts",   // traversal
            "/v1/accounts/./auth",        // dot segment
            "/v1/accounts//auth",         // empty segment
            "/v1/accounts/auth/",         // trailing separator
            "v1/accounts/auth",           // no leading separator
            "/v1/accounts%2Fauth",        // encoded separator
            "/v1/accounts?query=1",       // query string
            "/v1/acc ounts",              // whitespace
            "/v1/accounts#fragment",      // fragment
            "/",                          // separator only
            ""                            // empty
        ]
        for path in rejected {
            XCTAssertFalse(
                DeviceAuthorizationInputValidator.isCanonicalPath(path),
                "expected \(path) to be rejected"
            )
        }

        let accepted = [
            "/v1/accounts",
            "/v1/accounts/auth/context",
            "/v1/accounts/auth/deviceKeyRegistration",
            "/v1/accounts/transfers",
            "/v1/a-b_c.d~e"               // the unreserved set
        ]
        for path in accepted {
            XCTAssertTrue(
                DeviceAuthorizationInputValidator.isCanonicalPath(path),
                "expected \(path) to be accepted"
            )
        }
    }

    /// Malformed `canonical_path` values are rejected.
    ///
    /// These pin the outcome, not the mechanism. `isCanonicalPath` runs before
    /// `matchesAllowList`, but every operation compares the path against a
    /// literal, so each of these would be rejected by the allow-list even if
    /// `isCanonicalPath` were removed. They are still worth having because they
    /// cover the shapes — traversal, empty segments, encoded separators — that
    /// a path check exists to stop; `testCanonicalPathRule` covers the rule
    /// itself.
    func testRejectsMalformedCanonicalPaths() throws {
        let malformed = [
            "/v1/accounts/../accounts",
            "/v1/accounts/./auth",
            "/v1/accounts//auth",
            "/v1/accounts/auth/",
            "v1/accounts/auth/context",
            "/v1/accounts%2Fauth%2Fcontext",
            "/v1/accounts/auth/context?query=1",
            "/v1/accounts/auth/con text",
            "/",
            ""
        ]

        for path in malformed {
            var payload = DeviceAuthorizationFixture.getDeviceContextPayload()
            payload["canonical_path"] = path
            assertInvalid(
                try DeviceAuthorizationFixture.signingInput(payload: payload)
            )
        }
    }

    func testRejectsInvalidGetDeviceContextOperationBinding() throws {
        var idempotency = DeviceAuthorizationFixture.getDeviceContextPayload()
        idempotency["idempotency_key"] = "01234567-89ab-cdef-0123-456789abcdef"

        var nonEmptyDigest = DeviceAuthorizationFixture.getDeviceContextPayload()
        nonEmptyDigest["body_sha256"] = Base64URL.encode(Data(repeating: 0xAB, count: 32))

        var wrongPath = DeviceAuthorizationFixture.getDeviceContextPayload()
        wrongPath["canonical_path"] = "/v1/accounts/auth/social/sessions"

        var wrongMethod = DeviceAuthorizationFixture.getDeviceContextPayload()
        wrongMethod["method"] = "POST"

        var wrongDiscriminator = DeviceAuthorizationFixture.getDeviceContextPayload()
        wrongDiscriminator["discriminator"] = "complete_social_login"

        for payload in [idempotency, nonEmptyDigest, wrongPath, wrongMethod, wrongDiscriminator] {
            assertInvalid(try DeviceAuthorizationFixture.signingInput(payload: payload))
        }
    }

    private func assertInvalid(
        _ exactBytes: Data,
        nowEpochSeconds: Int64? = nil,
        file: StaticString = #filePath,
        line: UInt = #line
    ) {
        XCTAssertThrowsError(
            try makeSigningInput(exactBytes, nowEpochSeconds: nowEpochSeconds),
            file: file,
            line: line
        ) { error in
            XCTAssertEqual(error as? DaaSecureKeyError, .invalidSigningInput)
        }
    }

    private func makeSigningInput(
        _ exactBytes: Data,
        nowEpochSeconds: Int64?
    ) throws -> DaaDeviceAuthorizationSigningInput {
        if let nowEpochSeconds {
            return try DaaDeviceAuthorizationSigningInput(
                exactBytes: exactBytes,
                nowEpochSeconds: nowEpochSeconds
            )
        }
        return try DaaDeviceAuthorizationSigningInput(exactBytes: exactBytes)
    }

}
