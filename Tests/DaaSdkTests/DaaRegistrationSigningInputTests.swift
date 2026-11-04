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

final class DaaRegistrationSigningInputTests: XCTestCase {
    func testAcceptsBothRegistrationTypsAndPreservesExactBytes() throws {
        let flowBytes = try RegistrationAuthorizationFixture.signingInput(
            header: RegistrationAuthorizationFixture.header(typ: RegistrationAuthorizationFixture.flowTyp)
        )
        let deviceBytes = try RegistrationAuthorizationFixture.signingInput(
            header: RegistrationAuthorizationFixture.header(
                typ: RegistrationAuthorizationFixture.deviceTyp
            ),
            payload: RegistrationAuthorizationFixture.devicePayload()
        )

        let flowInput = try DaaRegistrationAuthorizationSigningInput(exactBytes: flowBytes)
        let deviceInput = try DaaRegistrationAuthorizationSigningInput(exactBytes: deviceBytes)

        XCTAssertEqual(flowInput.exactBytes, flowBytes)
        XCTAssertEqual(deviceInput.exactBytes, deviceBytes)
        XCTAssertEqual(
            RegistrationAuthorizationFixture.payload()["canonical_path"] as? String,
            "/v1/accounts/auth/deviceKeyRegistration"
        )
    }

    func testRequiredPayloadKeysAreTheFourteenFlowClaimsAndTheTenDeviceClaims() {
        let deviceClaims: Set<String> = [
            "discriminator", "schema_version", "aud", "method", "canonical_path",
            "body_sha256", "idempotency_key", "jti", "iat", "exp"
        ]
        let flowClaims = deviceClaims.union([
            "registration_handle_sha256", "profile_id", "auth_key_thumbprint", "code_verifier_sha256"
        ])

        XCTAssertEqual(
            RegistrationAuthorizationInputValidator.requiredPayloadKeys(for: .deviceAuthorization),
            deviceClaims
        )
        XCTAssertEqual(
            RegistrationAuthorizationInputValidator.requiredPayloadKeys(for: .flowAuthorization),
            flowClaims
        )
        XCTAssertEqual(deviceClaims.count, 10)
        XCTAssertEqual(flowClaims.count, 14)
        XCTAssertEqual(Set(RegistrationAuthorizationFixture.devicePayload().keys), deviceClaims)
        XCTAssertEqual(Set(RegistrationAuthorizationFixture.payload().keys), flowClaims)
    }

    func testAcceptsDevicePayloadWithExactlyTheTenSharedClaims() throws {
        let deviceBytes = try RegistrationAuthorizationFixture.signingInput(
            header: RegistrationAuthorizationFixture.header(
                typ: RegistrationAuthorizationFixture.deviceTyp
            ),
            payload: RegistrationAuthorizationFixture.devicePayload()
        )

        let input = try DaaRegistrationAuthorizationSigningInput(exactBytes: deviceBytes)

        XCTAssertEqual(input.typ, .deviceAuthorization)
        XCTAssertEqual(input.exactBytes, deviceBytes)
    }

    /// The verifier decodes the device proof strictly and rejects unknown
    /// members, so a device payload carrying any binding claim must be
    /// rejected here rather than signed.
    func testRejectsDevicePayloadCarryingAnyBindingClaim() throws {
        let flowPayload = RegistrationAuthorizationFixture.payload()
        let deviceHeader = RegistrationAuthorizationFixture.header(
            typ: RegistrationAuthorizationFixture.deviceTyp
        )

        for claim in RegistrationAuthorizationFixture.bindingClaims {
            var withBindingClaim = RegistrationAuthorizationFixture.devicePayload()
            withBindingClaim[claim] = flowPayload[claim]
            assertInvalid(try RegistrationAuthorizationFixture.signingInput(
                header: deviceHeader,
                payload: withBindingClaim
            ))
        }
        assertInvalid(try RegistrationAuthorizationFixture.signingInput(
            header: deviceHeader,
            payload: flowPayload
        ))
    }

    func testRejectsDevicePayloadMissingASharedClaim() throws {
        let deviceHeader = RegistrationAuthorizationFixture.header(
            typ: RegistrationAuthorizationFixture.deviceTyp
        )

        for claim in RegistrationAuthorizationFixture.devicePayload().keys {
            var missingClaim = RegistrationAuthorizationFixture.devicePayload()
            missingClaim.removeValue(forKey: claim)
            assertInvalid(try RegistrationAuthorizationFixture.signingInput(
                header: deviceHeader,
                payload: missingClaim
            ))
        }
    }

    func testFlowRequiresAllFourteenClaims() throws {
        let flowHeader = RegistrationAuthorizationFixture.header(
            typ: RegistrationAuthorizationFixture.flowTyp
        )

        XCTAssertNoThrow(try DaaRegistrationAuthorizationSigningInput(
            exactBytes: try RegistrationAuthorizationFixture.signingInput(
                header: flowHeader,
                payload: RegistrationAuthorizationFixture.payload()
            )
        ))
        assertInvalid(try RegistrationAuthorizationFixture.signingInput(
            header: flowHeader,
            payload: RegistrationAuthorizationFixture.devicePayload()
        ))
        for claim in RegistrationAuthorizationFixture.bindingClaims {
            var missingBindingClaim = RegistrationAuthorizationFixture.payload()
            missingBindingClaim.removeValue(forKey: claim)
            assertInvalid(try RegistrationAuthorizationFixture.signingInput(
                header: flowHeader,
                payload: missingBindingClaim
            ))
        }
    }

    func testFlowValidatesBindingClaimValues() throws {
        let flowHeader = RegistrationAuthorizationFixture.header(
            typ: RegistrationAuthorizationFixture.flowTyp
        )
        let malformedValues: [(String, Any)] = [
            ("auth_key_thumbprint", "not-a-thumbprint"),
            ("code_verifier_sha256", Base64URL.encode(Data(repeating: 0x22, count: 31))),
            ("registration_handle_sha256", 1),
            ("profile_id", String(repeating: "p", count: 21))
        ]

        for (claim, value) in malformedValues {
            var malformed = RegistrationAuthorizationFixture.payload()
            malformed[claim] = value
            assertInvalid(try RegistrationAuthorizationFixture.signingInput(
                header: flowHeader,
                payload: malformed
            ))
        }
    }

    func testRetainsTheRFC7638ThumbprintOfTheHeaderJWK() throws {
        let fixture = try AuthKeyWireFixture.load()
        let publicKeyX963 = try XCTUnwrap(Data(hexadecimal: fixture.p256PublicKey.x963Hex))
        let jwk = RegistrationAuthorizationFixture.embeddedJWK(x963: publicKeyX963)

        let deviceInput = try DaaRegistrationAuthorizationSigningInput(
            exactBytes: try RegistrationAuthorizationFixture.signingInput(
                header: RegistrationAuthorizationFixture.header(
                    typ: RegistrationAuthorizationFixture.deviceTyp,
                    jwk: jwk
                ),
                payload: RegistrationAuthorizationFixture.devicePayload()
            )
        )
        let flowInput = try DaaRegistrationAuthorizationSigningInput(
            exactBytes: try RegistrationAuthorizationFixture.signingInput(
                header: RegistrationAuthorizationFixture.header(
                    typ: RegistrationAuthorizationFixture.flowTyp,
                    jwk: jwk
                )
            )
        )

        XCTAssertEqual(deviceInput.headerJWKThumbprint, fixture.p256PublicKey.jwkThumbprint)
        XCTAssertEqual(flowInput.headerJWKThumbprint, fixture.p256PublicKey.jwkThumbprint)
    }

    func testRejectsWrongTypKidPresentMissingJWKWrongPathAndExtraClaim() throws {
        let payload = RegistrationAuthorizationFixture.payload()
        var wrongPath = payload
        wrongPath["canonical_path"] = "/v1/accounts/auth/sessions"
        var extraClaim = payload
        extraClaim["nonce"] = "unexpected"
        var missingJTI = payload
        missingJTI.removeValue(forKey: "jti")

        var kidPresent = RegistrationAuthorizationFixture.header()
        kidPresent["kid"] = "key-1"
        var extraJWKMember = RegistrationAuthorizationFixture.embeddedJWK()
        extraJWKMember["kid"] = "key-1"

        let invalidInputs = [
            try RegistrationAuthorizationFixture.signingInput(
                header: RegistrationAuthorizationFixture.header(typ: "aw-device-authorization+jws")
            ),
            try RegistrationAuthorizationFixture.signingInput(header: kidPresent),
            try RegistrationAuthorizationFixture.signingInput(
                header: ["alg": "ES256", "typ": RegistrationAuthorizationFixture.flowTyp]
            ),
            try RegistrationAuthorizationFixture.signingInput(
                header: RegistrationAuthorizationFixture.header(jwk: extraJWKMember)
            ),
            try RegistrationAuthorizationFixture.signingInput(payload: wrongPath),
            try RegistrationAuthorizationFixture.signingInput(payload: extraClaim),
            try RegistrationAuthorizationFixture.signingInput(payload: missingJTI)
        ]

        for input in invalidInputs {
            assertInvalid(input)
        }
    }

    func testRejectsUnknownDeviceTypClaimNameDiscriminatorAndSchemaVersion() throws {
        let payload = RegistrationAuthorizationFixture.payload()
        var unknownVerifierClaimName = payload
        unknownVerifierClaimName.removeValue(forKey: "code_verifier_sha256")
        unknownVerifierClaimName["registration_code_verifier_sha256"] = Base64URL.encode(
            Data(repeating: 0x22, count: 32)
        )
        var wrongDiscriminator = payload
        wrongDiscriminator["discriminator"] = "register_device_key"
        var wrongSchemaVersion = payload
        wrongSchemaVersion["schema_version"] = 2
        var stringSchemaVersion = payload
        stringSchemaVersion["schema_version"] = "1"
        var missingDiscriminator = payload
        missingDiscriminator.removeValue(forKey: "discriminator")

        let invalidInputs = [
            try RegistrationAuthorizationFixture.signingInput(
                header: RegistrationAuthorizationFixture.header(
                    typ: "daa-registration-device-authorization+jws"
                )
            ),
            try RegistrationAuthorizationFixture.signingInput(payload: unknownVerifierClaimName),
            try RegistrationAuthorizationFixture.signingInput(payload: wrongDiscriminator),
            try RegistrationAuthorizationFixture.signingInput(payload: wrongSchemaVersion),
            try RegistrationAuthorizationFixture.signingInput(payload: stringSchemaVersion),
            try RegistrationAuthorizationFixture.signingInput(payload: missingDiscriminator)
        ]

        for input in invalidInputs {
            assertInvalid(input)
        }
    }

    func testRejectsExpiredAndTooFarFutureInputsAtConstruction() throws {
        let now: Int64 = 1_700_000_000
        let expired = try RegistrationAuthorizationFixture.signingInput(
            payload: RegistrationAuthorizationFixture.payload(nowEpochSeconds: now - 361)
        )
        let future = try RegistrationAuthorizationFixture.signingInput(
            payload: RegistrationAuthorizationFixture.payload(nowEpochSeconds: now + 61)
        )

        assertInvalid(expired, nowEpochSeconds: now)
        assertInvalid(future, nowEpochSeconds: now)
    }

    func testAcceptsInclusiveFreshnessSkewBoundaries() throws {
        let now: Int64 = 1_700_000_000
        let issuedAtFutureBoundary = try RegistrationAuthorizationFixture.signingInput(
            payload: RegistrationAuthorizationFixture.payload(nowEpochSeconds: now + 60)
        )
        let expiresAtPastBoundary = try RegistrationAuthorizationFixture.signingInput(
            payload: RegistrationAuthorizationFixture.payload(nowEpochSeconds: now - 360)
        )

        XCTAssertNoThrow(try DaaRegistrationAuthorizationSigningInput(
            exactBytes: issuedAtFutureBoundary,
            nowEpochSeconds: now
        ))
        XCTAssertNoThrow(try DaaRegistrationAuthorizationSigningInput(
            exactBytes: expiresAtPastBoundary,
            nowEpochSeconds: now
        ))
    }

    func testRevalidatesFreshnessImmediatelyBeforeSigning() throws {
        let now: Int64 = 1_700_000_000
        let exactBytes = try RegistrationAuthorizationFixture.signingInput(
            payload: RegistrationAuthorizationFixture.payload(nowEpochSeconds: now - 1)
        )
        let input = try DaaRegistrationAuthorizationSigningInput(
            exactBytes: exactBytes,
            nowEpochSeconds: now
        )

        XCTAssertThrowsError(try input.signingBytes(nowEpochSeconds: now + 361)) { error in
            XCTAssertEqual(error as? DaaSecureKeyError, .invalidSigningInput)
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
    ) throws -> DaaRegistrationAuthorizationSigningInput {
        if let nowEpochSeconds {
            return try DaaRegistrationAuthorizationSigningInput(
                exactBytes: exactBytes,
                nowEpochSeconds: nowEpochSeconds
            )
        }
        return try DaaRegistrationAuthorizationSigningInput(exactBytes: exactBytes)
    }

}
