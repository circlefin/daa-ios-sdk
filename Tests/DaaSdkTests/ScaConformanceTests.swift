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

import XCTest

@testable import DaaSdk

// Drives the real parser and configuration rules with the vectors the Android
// SDK runs too. Where the SDKs differ by design the fixture names each side's
// outcome, and this suite checks the iOS one.
final class ScaConformanceTests: XCTestCase {
    typealias Fixture = ScaConformanceFixture

    static let redirect = "https://app.example.com/sca/callback"

    private var fixture: Fixture!

    override func setUpWithError() throws {
        fixture = try Fixture.load()
    }

    // MARK: - Callbacks

    func testEveryCallbackVectorHasTheExpectedIOSOutcome() {
        XCTAssertFalse(fixture.callbackVectors.isEmpty)
        for vector in fixture.callbackVectors {
            XCTAssertEqual(Self.outcome(of: vector.input), vector.expected.ios, vector.id)
        }
    }

    func testCallbackVectorIdsAreUnique() {
        let ids = fixture.callbackVectors.map(\.id)
        XCTAssertEqual(Set(ids).count, ids.count)
    }

    func testOnlyAndroidIgnoresACallbackAndOnlyIOSReportsAStateMismatch() {
        for vector in fixture.callbackVectors {
            XCTAssertNotEqual(vector.expected.ios.outcome, "ignored", vector.id)
            XCTAssertNotEqual(vector.expected.android.outcome, "stateMismatch", vector.id)
        }
    }

    /// Outcomes differ only where the platforms differ by design: a callback
    /// Android cannot attribute it ignores, and the size caps differ.
    func testPerPlatformOutcomesAreOnlyTheDocumentedDifferences() {
        let attributable: Set<String> = ["result", "error", "protocolError"]
        for vector in fixture.callbackVectors where vector.expected.isPerPlatform {
            let android = vector.expected.android.outcome
            let ios = vector.expected.ios.outcome
            let androidIgnores = android == "ignored"
            let messageCap = ios == "protocolError" && android == "error"
                && (vector.expected.android.message?.value.utf8.count ?? 0) > ScaCallback.maxMessageLength
            XCTAssertTrue(androidIgnores || messageCap, vector.id)
            if androidIgnores {
                XCTAssertTrue(attributable.contains(ios) || ios == "stateMismatch", vector.id)
            }
        }
    }

    static func outcome(of input: ScaCallbackVectorInput) -> ScaCallbackOutcome {
        guard let kind = ScaCeremonyKind(rawValue: input.ceremony) else {
            return ScaCallbackOutcome(outcome: "invalidVector")
        }
        let request = ScaCeremonyRequest(
            kind: kind,
            circleOrigin: "https://daa-sca-sandbox.circle.com",
            redirectURI: input.redirectUri.value,
            frameToken: "frame-token",
            state: input.state
        )
        switch ScaCallback.parse(input.callback.value, for: request) {
        case let .success(text):
            return ScaCallbackOutcome(outcome: "result", result: text)
        case let .failure(error):
            return outcome(of: error)
        }
    }

    private static func outcome(of error: DaaScaError) -> ScaCallbackOutcome {
        switch error {
        case .cancelled:
            return ScaCallbackOutcome(outcome: "error", code: "Cancelled")
        case let .expired(message):
            return ScaCallbackOutcome(outcome: "error", code: "Expired", message: message)
        case let .unsupported(message):
            return ScaCallbackOutcome(outcome: "error", code: "Unsupported", message: message)
        case let .alreadyEnrolled(message):
            return ScaCallbackOutcome(outcome: "error", code: "AlreadyEnrolled", message: message)
        case .stateMismatch:
            return ScaCallbackOutcome(outcome: "stateMismatch")
        case .protocol:
            return ScaCallbackOutcome(outcome: "protocolError")
        case .sessionUnavailable:
            return ScaCallbackOutcome(outcome: "sessionUnavailable")
        }
    }

    // MARK: - Redirect URIs

    func testEveryAcceptedRedirectURIBuildsAConfiguration() throws {
        XCTAssertFalse(fixture.redirectUriVectors.accept.isEmpty)
        for vector in fixture.redirectUriVectors.accept {
            let uri = vector.input.value
            XCTAssertTrue(ScaConfigRules.isValidRedirectURI(uri), vector.id)
            XCTAssertEqual(try configuration(redirectURI: uri).redirectURI, uri, vector.id)
        }
    }

    func testEveryRejectedRedirectURIIsRefusedAtConstruction() {
        XCTAssertFalse(fixture.redirectUriVectors.reject.isEmpty)
        for vector in fixture.redirectUriVectors.reject {
            let uri = vector.input.value
            XCTAssertFalse(ScaConfigRules.isValidRedirectURI(uri), vector.id)
            XCTAssertThrowsError(try configuration(redirectURI: uri), vector.id) {
                XCTAssertEqual($0 as? DaaScaConfigurationError, .invalidRedirectURI, vector.id)
            }
        }
    }

    func testTheRedirectURILengthLimitIsTheFixtures() {
        let accepted = fixture.redirectUriVectors.accept.map { $0.input.value.utf8.count }
        let rejected = fixture.redirectUriVectors.reject.map { $0.input.value.utf8.count }
        XCTAssertEqual(accepted.max(), ScaConfigRules.maxRedirectURILength)
        XCTAssertEqual(rejected.max(), ScaConfigRules.maxRedirectURILength + 1)
    }

    func testTheIOSPlatformRules() throws {
        let rules = fixture.platformRules.filter { $0.platform == "ios" }
        XCTAssertFalse(rules.isEmpty)
        for rule in rules {
            let available = try XCTUnwrap(rule.input.httpsCallbackAvailable, rule.id)
            let build = {
                try self.configuration(redirectURI: rule.input.redirectUri, httpsCallbackAvailable: available)
            }
            switch rule.expected {
            case "accept":
                XCTAssertNoThrow(try build(), rule.id)
            case "httpsCallbackUnavailable":
                XCTAssertThrowsError(try build(), rule.id) {
                    XCTAssertEqual($0 as? DaaScaConfigurationError, .httpsCallbackUnavailable, rule.id)
                }
            default:
                XCTFail("Unknown expectation \(rule.expected) for \(rule.id)")
            }
        }
    }

    // MARK: - Ceremony origin

    func testEveryCircleOriginVector() throws {
        XCTAssertFalse(fixture.circleOriginVectors.isEmpty)
        for vector in fixture.circleOriginVectors {
            for environment in try environments(vector.input.environment) {
                let build = {
                    try self.configuration(
                        environment: environment,
                        redirectURI: Self.redirect,
                        circleOrigin: vector.input.circleOrigin
                    )
                }
                guard vector.expected.outcome != "accept" else {
                    XCTAssertEqual(try build().circleOrigin, vector.expected.origin, vector.id)
                    continue
                }
                let expected = try XCTUnwrap(Self.configurationError(vector.expected.outcome), vector.id)
                XCTAssertThrowsError(try build(), vector.id) {
                    XCTAssertEqual($0 as? DaaScaConfigurationError, expected, vector.id)
                }
            }
            // The origin rule alone agrees with the configuration outcome.
            if let origin = vector.input.circleOrigin, vector.input.environment == "sandbox" {
                XCTAssertEqual(ScaConfigRules.isValidOrigin(origin), vector.expected.outcome == "accept", vector.id)
            }
        }
    }

    /// The suite above skips the `nonPublic` vectors, so they must be exactly
    /// the ones that expect `unsupportedEnvironment`. Otherwise a vector moved
    /// to `nonPublic` with another outcome, or one that expects
    /// `unsupportedEnvironment` under a public environment, would pass
    /// unchecked.
    func testOnlyTheSkippedNonPublicVectorsExpectUnsupportedEnvironment() {
        let nonPublic = fixture.circleOriginVectors.filter { $0.input.environment == "nonPublic" }
        XCTAssertFalse(nonPublic.isEmpty)
        for vector in fixture.circleOriginVectors {
            XCTAssertEqual(
                vector.expected.outcome == "unsupportedEnvironment",
                vector.input.environment == "nonPublic",
                vector.id
            )
        }
    }

    private func environments(_ name: String) throws -> [DaaEnvironment] {
        switch name {
        case "sandbox": return [.sandbox]
        case "production": return [.production]
        // `DaaEnvironment` has no non-public case, so the type itself rules
        // these vectors out; there is nothing to construct.
        case "nonPublic": return []
        default: throw FixtureError.invalidMetadata
        }
    }

    // No `unsupportedEnvironment`: only the skipped `nonPublic` vectors
    // expect it, and the SDK never throws it.
    private static func configurationError(_ name: String) -> DaaScaConfigurationError? {
        switch name {
        case "circleOriginOverrideNotAllowed": return .circleOriginOverrideNotAllowed
        case "invalidCircleOrigin": return .invalidCircleOrigin
        default: return nil
        }
    }

    // MARK: - Timeouts

    func testTheTimeoutDefaultsAndBoundsAreTheFixtures() {
        let timeouts = fixture.timeoutVectors
        XCTAssertEqual(DaaScaConfiguration.defaultApproveTimeout, Self.seconds(timeouts.defaults.approveMs))
        XCTAssertEqual(DaaScaConfiguration.defaultEnrollTimeout, Self.seconds(timeouts.defaults.enrollMs))
        XCTAssertEqual(DaaScaConfiguration.minimumCeremonyTimeout, Self.seconds(timeouts.bounds.minimumMs))
        XCTAssertEqual(DaaScaConfiguration.maximumCeremonyTimeout, Self.seconds(timeouts.bounds.maximumMs))
    }

    func testEveryTimeoutVectorForBothCeremonies() throws {
        XCTAssertFalse(fixture.timeoutVectors.vectors.isEmpty)
        for vector in fixture.timeoutVectors.vectors {
            let timeout = Self.seconds(vector.input)
            let approve = { try self.configuration(redirectURI: Self.redirect, approveTimeout: timeout) }
            let enroll = { try self.configuration(redirectURI: Self.redirect, enrollTimeout: timeout) }
            switch vector.expected {
            case "accept":
                XCTAssertEqual(try approve().approveTimeout, timeout, vector.id)
                XCTAssertEqual(try enroll().enrollTimeout, timeout, vector.id)
            case "reject":
                for build in [approve, enroll] {
                    XCTAssertThrowsError(try build(), vector.id) {
                        XCTAssertEqual($0 as? DaaScaConfigurationError, .invalidCeremonyTimeout, vector.id)
                    }
                }
            default:
                XCTFail("Unknown expectation \(vector.expected) for \(vector.id)")
            }
        }
    }

    // The fixture is in milliseconds; the iOS API takes seconds.
    private static func seconds(_ milliseconds: Int) -> TimeInterval {
        TimeInterval(milliseconds) / 1000
    }

    // MARK: - Error vocabulary

    func testTheErrorVocabularyIsExactlyTheIOSErrorCases() {
        let vocabulary = fixture.errorVocabulary
        let all: [DaaScaError] = [
            .cancelled, .expired(message: nil), .unsupported(message: nil), .alreadyEnrolled(message: nil),
            .stateMismatch, .sessionUnavailable(message: nil), .protocol(message: nil)
        ]
        XCTAssertEqual(all.map(Self.vocabularyName), vocabulary.pageCodes + vocabulary.sdkLocal.ios)
    }

    func testEveryPageCodeHasACallbackVectorOnBothPlatforms() {
        for code in fixture.errorVocabulary.pageCodes {
            let reported = fixture.callbackVectors.filter {
                $0.expected.ios.code == code && $0.expected.android.code == code
            }
            XCTAssertFalse(reported.isEmpty, code)
        }
    }

    // Exhaustive, so a new case fails to compile here until the fixture names it.
    private static func vocabularyName(_ error: DaaScaError) -> String {
        switch error {
        case .cancelled: return "Cancelled"
        case .expired: return "Expired"
        case .unsupported: return "Unsupported"
        case .alreadyEnrolled: return "AlreadyEnrolled"
        case .stateMismatch: return "stateMismatch"
        case .sessionUnavailable: return "sessionUnavailable"
        case .protocol: return "protocol"
        }
    }

    // MARK: - Helpers

    private func configuration(
        environment: DaaEnvironment = .sandbox,
        redirectURI: String,
        circleOrigin: String? = nil,
        approveTimeout: TimeInterval = DaaScaConfiguration.defaultApproveTimeout,
        enrollTimeout: TimeInterval = DaaScaConfiguration.defaultEnrollTimeout,
        httpsCallbackAvailable: Bool = true
    ) throws -> DaaScaConfiguration {
        try DaaScaConfiguration(
            environment: environment,
            redirectURI: redirectURI,
            circleOrigin: circleOrigin,
            approveTimeout: approveTimeout,
            enrollTimeout: enrollTimeout,
            httpsCallbackAvailable: httpsCallbackAvailable
        )
    }
}
