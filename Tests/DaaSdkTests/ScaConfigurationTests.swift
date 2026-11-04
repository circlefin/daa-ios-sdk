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

// Accept/reject vectors are shared with the Android SDK and Circle's hosted
// ceremony page's `redirectUri` rules.
final class ScaConfigurationTests: XCTestCase {
    private static let redirect = "https://app.example.com/sca/callback"

    private static let testOrigin = "https://sca.example.circle.com"

    func testOnlySandboxAndProductionExistAndResolveToTheirCeremonyOrigins() throws {
        // These must equal the server's WebAuthn origins byte for byte, and
        // match the web and Android tables; a drift fails every ceremony's
        // origin check.
        XCTAssertEqual(try configuration(environment: .sandbox).circleOrigin, "https://daa-sca-sandbox.circle.com")
        XCTAssertEqual(try configuration(environment: .production).circleOrigin, "https://daa-sca.circle.com")
        // These are the only two environments.
        XCTAssertEqual(DaaEnvironment.allCases, [.sandbox, .production])
    }

    func testAcceptsHTTPSAndCustomSchemeRedirectURIs() {
        for uri in [
            "https://app.example.com/sca/callback",
            "https://app.example.com",
            "https://app.example.com/cb?tenant=acme",
            "com.example.app:/sca",
            "acme://sca-callback"
        ] {
            XCTAssertTrue(ScaConfigRules.isValidRedirectURI(uri), uri)
        }
    }

    func testRejectsRedirectURIsTheCeremonyPageWouldRefuse() {
        for uri in [
            "",
            "/sca/callback",
            "http://app.example.com/cb",
            "https://app.example.com/cb#x",
            "https://app.example.com/cb#",
            "https://user:pass@app.example.com/cb",
            "https://user@app.example.com/cb",
            "https:///cb",
            "javascript:alert(1)",
            "intent://cb#Intent;scheme=acme;end",
            "data:text/html,x",
            "file:///sdcard/x",
            "content://x/y",
            "Acme://cb",
            "com.Example.Wallet:/sca/callback",
            "HTTPS://app.example.com/cb",
            " https://app.example.com/cb",
            "https://app.example.com/cb ",
            "https://app.example.com/a b",
            "https://app.example.com/é",
            "1acme://cb",
            "not a uri"
        ] {
            XCTAssertFalse(ScaConfigRules.isValidRedirectURI(uri), uri)
        }
    }

    func testRejectsAnHTTPSRedirectURIWithAPort() {
        // The system matches an https callback by host and path, so a port
        // would be registered with Circle but never delivered to the app.
        for uri in [
            "https://app.example.com:8443/cb",
            "https://app.example.com:443/cb",
            "https://app.example.com:/cb",
            "https://app.example.com:8443",
            "https://app.example.com:8443?tenant=acme"
        ] {
            XCTAssertFalse(ScaConfigRules.isValidRedirectURI(uri), uri)
        }
        XCTAssertTrue(ScaConfigRules.isValidRedirectURI("https://app.example.com/cb?at=10:30"))
    }

    func testRejectsARedirectURIThatTheBrowserWouldRewrite() {
        // The page navigates to the WHATWG serialization of the URI, which
        // differs from each of these, so the callback would not match.
        for uri in [
            // Dot segments, literal or percent-encoded in either case.
            "https://app.example.com/sca/../callback",
            "https://app.example.com/sca/./callback",
            "https://app.example.com/sca/%2e%2e/callback",
            "https://app.example.com/sca/%2E./callback",
            "https://app.example.com/sca/.%2E/callback",
            "https://app.example.com/sca/%2e/callback",
            "https://app.example.com/sca/..",
            "https://app.example.com/.",
            "https://app.example.com/..?tenant=acme",
            "acme://host/sca/../callback",
            "acme://host/%2E%2E/callback",
            "com.example.app:/sca/./callback",
            // An apostrophe in an https query, which WHATWG encodes as %27.
            "https://app.example.com/cb?tenant=o'reilly",
            // An https host the host parser decodes or re-serializes.
            "https://app.ex%61mple.com/cb",
            "https://0x7f.1/cb",
            "https://127.1/cb",
            "https://127.0.0.1/cb",
            "https://example.123./cb",
            "https://[::1]/cb",
            // An uppercase https host, which the parser lowercases.
            "https://App.Example.com/cb",
            "https://APP.EXAMPLE.COM/cb"
        ] {
            XCTAssertFalse(ScaConfigRules.isValidRedirectURI(uri), uri)
            XCTAssertThrowsError(try configuration(redirectURI: uri), uri) {
                XCTAssertEqual($0 as? DaaScaConfigurationError, .invalidRedirectURI, uri)
            }
        }
    }

    func testAcceptsRedirectURIsTheBrowserLeavesAsWritten() {
        for uri in [
            "https://app.example.com/cb?at=10:30",
            "https://app.example.com/cb?tenant=o%27reilly",
            "https://app.example.com/%7Euser/cb",
            "https://app.example.com/o'reilly/cb",
            "https://app.example.com/sca/.well/cb...",
            "https://app.example.com/cb?path=../x",
            "https://app.example.com/cb?",
            "acme://cb?tenant=o'reilly",
            "acme:../cb",
            "com.example.app:/sca"
        ] {
            XCTAssertTrue(ScaConfigRules.isValidRedirectURI(uri), uri)
        }
    }

    func testRejectsARedirectURIOverTheServersLengthLimit() {
        let prefix = "https://app.example.com/"
        let atLimit = prefix + String(repeating: "a", count: ScaConfigRules.maxRedirectURILength - prefix.count)
        XCTAssertTrue(ScaConfigRules.isValidRedirectURI(atLimit))
        XCTAssertFalse(ScaConfigRules.isValidRedirectURI(atLimit + "a"))
    }

    func testAcceptsABareHTTPSOriginOnCircleDotComOrASubdomain() {
        let origins = [Self.testOrigin, "https://daa-sca.circle.com", "https://a.b-c.circle.com", "https://circle.com"]
        for origin in origins {
            XCTAssertTrue(ScaConfigRules.isValidOrigin(origin), origin)
        }
    }

    func testRejectsAnyOtherOrigin() {
        for origin in [
            // Not bare.
            "https://daa-sca.circle.com/",
            "https://daa-sca.circle.com/ceremony",
            "https://daa-sca.circle.com?x=1",
            "https://daa-sca.circle.com?",
            "https://daa-sca.circle.com#x",
            "https://daa-sca.circle.com:443",
            "https://user@daa-sca.circle.com",
            // Not https.
            "http://daa-sca.circle.com",
            "http://localhost:3000",
            "https://localhost",
            "http://127.0.0.1:3000",
            // Not circle.com.
            "https://evilcircle.com",
            "https://circle.com.example.com",
            "https://daa-sca.example.com",
            "https://circle.co",
            // Not spelled exactly.
            "HTTPS://daa-sca.circle.com",
            "https://DAA-SCA.circle.com",
            "https://daa-sca.circle.com.",
            "https://.circle.com",
            "https://-a.circle.com",
            "https://daa_sca.circle.com",
            "https://daa-scä.circle.com",
            " https://daa-sca.circle.com",
            "daa-sca.circle.com",
            ""
        ] {
            XCTAssertFalse(ScaConfigRules.isValidOrigin(origin), origin)
        }
    }

    func testConfigurationFailsAtConstructionNotMidCeremony() {
        XCTAssertThrowsError(try configuration(redirectURI: "http://x/cb")) {
            XCTAssertEqual($0 as? DaaScaConfigurationError, .invalidRedirectURI)
        }
        XCTAssertThrowsError(try configuration(environment: .sandbox, circleOrigin: "https://daa-sca.circle.com/")) {
            XCTAssertEqual($0 as? DaaScaConfigurationError, .invalidCircleOrigin)
        }
    }

    func testTheOriginOverrideIsRefusedForProductionAndValidatedForSandbox() throws {
        XCTAssertThrowsError(try configuration(environment: .production, circleOrigin: "https://daa-sca.circle.com")) {
            XCTAssertEqual($0 as? DaaScaConfigurationError, .circleOriginOverrideNotAllowed)
        }
        let overridden = try configuration(environment: .sandbox, circleOrigin: Self.testOrigin)
        XCTAssertEqual(overridden.circleOrigin, Self.testOrigin)
        XCTAssertThrowsError(try configuration(environment: .sandbox, circleOrigin: "https://daa-sca.example.com")) {
            XCTAssertEqual($0 as? DaaScaConfigurationError, .invalidCircleOrigin)
        }
    }

    func testAnHTTPSCallbackIsAConfigurationErrorWhereTheOSCannotDeliverIt() throws {
        // iOS 15–17.3: no `ASWebAuthenticationSession.Callback.https`.
        XCTAssertThrowsError(try configuration(redirectURI: Self.redirect, httpsCallbackAvailable: false)) {
            XCTAssertEqual($0 as? DaaScaConfigurationError, .httpsCallbackUnavailable)
        }
        // A custom scheme is the default and works on every supported version.
        XCTAssertNoThrow(try configuration(redirectURI: "acme://sca-callback", httpsCallbackAvailable: false))
        XCTAssertNoThrow(try configuration(redirectURI: Self.redirect, httpsCallbackAvailable: true))
    }

    func testThePublicInitializerAppliesThisOSsHTTPSCallbackRule() {
        let result = Result { try DaaScaConfiguration(environment: .production, redirectURI: Self.redirect) }
        if SystemScaSessionLauncher.isHTTPSCallbackAvailable {
            XCTAssertNoThrow(try result.get())
        } else {
            XCTAssertThrowsError(try result.get()) {
                XCTAssertEqual($0 as? DaaScaConfigurationError, .httpsCallbackUnavailable)
            }
        }
    }

    func testEachCeremonyKindDefaultsToItsTokenLifetime() throws {
        XCTAssertEqual(DaaScaConfiguration.defaultApproveTimeout, 300)
        XCTAssertEqual(DaaScaConfiguration.defaultEnrollTimeout, 600)
        let defaults = try configuration()
        XCTAssertEqual(defaults.approveTimeout, 300)
        XCTAssertEqual(defaults.enrollTimeout, 600)
        XCTAssertEqual(defaults.timeout(for: .challenge), 300)
        XCTAssertEqual(defaults.timeout(for: .registration), 600)
    }

    func testCeremonyTimeoutsAreConfigurableIndependentlyAndValidated() throws {
        let custom = try configuration(approveTimeout: 30, enrollTimeout: 1_800)
        XCTAssertEqual(custom.timeout(for: .challenge), 30)
        XCTAssertEqual(custom.timeout(for: .registration), 1_800)

        let longest = try configuration(approveTimeout: 3_600, enrollTimeout: 3_600)
        XCTAssertEqual(DaaScaConfiguration.maximumCeremonyTimeout, 3_600)
        XCTAssertEqual(longest.approveTimeout, 3_600)
        XCTAssertEqual(longest.enrollTimeout, 3_600)

        // Above the maximum is a configuration error, never a deadline that
        // traps converting to nanoseconds.
        let invalidTimeouts: [TimeInterval] = [
            0, -1, 29.9, 3_600.001, 20_000_000_000, .greatestFiniteMagnitude, .infinity, -.infinity, .nan
        ]
        for invalid in invalidTimeouts {
            XCTAssertThrowsError(try configuration(approveTimeout: invalid), "approve \(invalid)") {
                XCTAssertEqual($0 as? DaaScaConfigurationError, .invalidCeremonyTimeout)
            }
            XCTAssertThrowsError(try configuration(enrollTimeout: invalid), "enroll \(invalid)") {
                XCTAssertEqual($0 as? DaaScaConfigurationError, .invalidCeremonyTimeout)
            }
        }
    }

    func testCeremonyURLCarriesTokenAndStateInTheFragmentUnderTheKeysThePageReads() throws {
        let request = ScaCeremonyRequest(
            kind: .challenge,
            circleOrigin: "https://daa-sca.circle.com",
            redirectURI: Self.redirect,
            frameToken: "a b+c&d=é",
            state: "k3Jx0Qp2V9mZsYbT7uWc1eFgHiLnOrAdEvGhIjKlMn0"
        )

        // encodeURIComponent("a b+c&d=é") === "a%20b%2Bc%26d%3D%C3%A9"
        XCTAssertEqual(
            request.ceremonyURLString,
            "https://daa-sca.circle.com/ceremony#token=a%20b%2Bc%26d%3D%C3%A9"
                + "&state=k3Jx0Qp2V9mZsYbT7uWc1eFgHiLnOrAdEvGhIjKlMn0"
        )
        XCTAssertNotNil(URL(string: request.ceremonyURLString))
        // The page's own extraction regex must find the token, not a bare-fragment miss.
        let regex = try NSRegularExpression(pattern: "[#&]token=([^&]+)")
        let url = request.ceremonyURLString
        let match = try XCTUnwrap(regex.firstMatch(in: url, range: NSRange(url.startIndex..., in: url)))
        XCTAssertEqual((url as NSString).substring(with: match.range(at: 1)), "a%20b%2Bc%26d%3D%C3%A9")
    }

    func testEncodeURIComponentLeavesExactlyItsUnreservedSetAlone() {
        XCTAssertEqual(ScaCeremonyRequest.encodeURIComponent("AZaz09-_.!~*'()"), "AZaz09-_.!~*'()")
        XCTAssertEqual(ScaCeremonyRequest.encodeURIComponent("#/?:@$,;"), "%23%2F%3F%3A%40%24%2C%3B")
        // Non-ASCII letters are escaped, not passed through as "alphanumerics".
        XCTAssertEqual(ScaCeremonyRequest.encodeURIComponent("ß"), "%C3%9F")
    }

    func testStateMatchesThePatternThePageEchoesAndIsFreshEachCeremony() throws {
        let states = try (0..<32).map { _ in try ScaCeremonyRequest.newState() }
        let pattern = try NSRegularExpression(pattern: "^[A-Za-z0-9_-]{16,128}$")

        for state in states {
            XCTAssertEqual(state.count, 43)
            XCTAssertNotNil(pattern.firstMatch(in: state, range: NSRange(state.startIndex..., in: state)), state)
        }
        XCTAssertEqual(Set(states).count, states.count)
    }

    func testSessionCallbackIsDerivedFromTheRedirectURI() {
        XCTAssertEqual(
            ScaSessionCallback(redirectURI: "https://app.example.com/sca/callback"),
            .https(host: "app.example.com", path: "/sca/callback")
        )
        XCTAssertEqual(
            ScaSessionCallback(redirectURI: "https://app.example.com"),
            .https(host: "app.example.com", path: "/")
        )
        XCTAssertEqual(ScaSessionCallback(redirectURI: "com.example.app:/sca"), .customScheme("com.example.app"))
        XCTAssertEqual(ScaSessionCallback(redirectURI: "acme://sca-callback"), .customScheme("acme"))
    }

    private func configuration(
        environment: DaaEnvironment = .production,
        redirectURI: String = "acme://sca-callback",
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
