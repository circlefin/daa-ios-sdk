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

// The vectors are shared with the Android SDK's callback tests. The two
// payloads were produced by the ceremony page's own encoding in Node —
// base64url(TextEncoder().encode(JSON.stringify(payload))), padding stripped —
// so decoding them here is the cross-language check that the ends agree.
final class ScaCallbackTests: XCTestCase {
    static let redirect = "https://app.example.com/sca/callback"
    static let state = "k3Jx0Qp2V9mZsYbT7uWc1eFgHiLnOrAdEvGhIjKlMn0"
    // Well-formed, the right length, and not this ceremony's.
    static let otherState = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    static let envelope = "v=1&state=\(state)"

    static let assertionJSON =
        "{\"id\":\"cred-1\",\"rawId\":\"cred-1\",\"type\":\"public-key\",\"response\":{\"clientDataJSON\":"
            + "\"eyJ0eXBlIjoid2ViYXV0aG4uZ2V0In0\",\"authenticatorData\":\"SZYN5YgO\",\"signature\":\"MEUCIQ\","
            + "\"userHandle\":\"dXNlcg\"},\"clientExtensionResults\":{},\"authenticatorAttachment\":\"platform\"}"
    static let assertionBase64URL =
        "eyJpZCI6ImNyZWQtMSIsInJhd0lkIjoiY3JlZC0xIiwidHlwZSI6InB1YmxpYy1rZXkiLCJyZXNwb25zZSI6eyJjbGllbnREYXRh"
            + "SlNPTiI6ImV5SjBlWEJsSWpvaWQyVmlZWFYwYUc0dVoyVjBJbjAiLCJhdXRoZW50aWNhdG9yRGF0YSI6IlNaWU41WWdPIiwic2ln"
            + "bmF0dXJlIjoiTUVVQ0lRIiwidXNlckhhbmRsZSI6ImRYTmxjZyJ9LCJjbGllbnRFeHRlbnNpb25SZXN1bHRzIjp7fSwiYXV0aGVu"
            + "dGljYXRvckF0dGFjaG1lbnQiOiJwbGF0Zm9ybSJ9"

    private let request = ScaCeremonyRequest(
        kind: .challenge,
        circleOrigin: "https://daa-sca.circle.com",
        redirectURI: redirect,
        frameToken: "tok-1",
        state: state
    )

    func testResultRelaysTheExactJSONTextThePageEncoded() {
        let result = parse("kind=result&ceremony=challenge&payload=\(Self.assertionBase64URL)")

        XCTAssertEqual(result, .success(Self.assertionJSON))
    }

    func testNonASCIIPayloadTextSurvivesTheRoundTrip() {
        let result = parse("kind=result&ceremony=challenge&payload=eyJpZCI6IsOp4pyT8J-UkSJ9")

        XCTAssertEqual(result, .success("{\"id\":\"é✓🔑\"}"))
    }

    func testAByteOrderMarkIsRefusedRatherThanSilentlyDropped() {
        // EF BB BF then `{}`. Relaying `{}` would not be the page's bytes.
        let result = parse("kind=result&ceremony=challenge&payload=77u_e30")

        XCTAssertEqual(result, .failure(.protocol(message: "Callback payload is not UTF-8")))
    }

    func testCancelledMapsToCancelledNotAFailure() {
        XCTAssertEqual(parse("kind=error&code=Cancelled"), .failure(.cancelled))
    }

    func testEveryPageErrorCodeMapsToItsError() {
        let expected: [String: DaaScaError] = [
            "Cancelled": .cancelled,
            "Expired": .expired(message: nil),
            "Unsupported": .unsupported(message: nil),
            "AlreadyEnrolled": .alreadyEnrolled(message: nil)
        ]
        for (code, error) in expected {
            XCTAssertEqual(parse("kind=error&code=\(code)"), .failure(error), code)
        }
        XCTAssertEqual(
            parse("kind=error&code=AlreadyEnrolled&message=Already%20enrolled"),
            .failure(.alreadyEnrolled(message: "Already enrolled"))
        )
    }

    func testCodesOutsideThePagesSetAreOffContractNotMappedToAGuess() {
        // The page never redirects these: `Transport`/`Protocol` happen before it
        // knows the redirect target, and `NotEnrolled` is not in the set.
        for code in ["NotEnrolled", "Transport", "Protocol", "cancelled", "CANCELLED", "Bogus", ""] {
            XCTAssertEqual(
                parse("kind=error&code=\(code)"),
                .failure(.protocol(message: "Unknown callback error code")),
                code
            )
        }
    }

    func testTheCallbackIsBoundedBeforeItIsRead() {
        // A payload at the cap is read; one byte over is refused before decoding.
        let maxJSON = "{\"a\":\"" + String(repeating: "x", count: ScaCallback.maxPayloadBytes - 8) + "\"}"
        XCTAssertEqual(maxJSON.utf8.count, ScaCallback.maxPayloadBytes)
        let atCap = Base64URL.encode(Data(maxJSON.utf8))
        XCTAssertEqual(parse("kind=result&ceremony=challenge&payload=\(atCap)"), .success(maxJSON))
        let overJSON = "{\"a\":\"" + String(repeating: "x", count: ScaCallback.maxPayloadBytes - 7) + "\"}"
        let over = Base64URL.encode(Data(overJSON.utf8))
        XCTAssertEqual(
            parse("kind=result&ceremony=challenge&payload=\(over)"),
            .failure(.protocol(message: "Callback payload is missing or exceeds the size limit"))
        )

        let padding = String(repeating: "x", count: ScaCallback.maxCallbackLength)
        XCTAssertEqual(
            parse("kind=error&code=Cancelled&pad=\(padding)"),
            .failure(.protocol(message: "Callback exceeds the size limit"))
        )

        let longMessage = String(repeating: "m", count: ScaCallback.maxMessageLength + 1)
        XCTAssertEqual(
            parse("kind=error&code=Expired&message=\(longMessage)"),
            .failure(.protocol(message: "Callback message exceeds the size limit"))
        )
        let maxMessage = String(repeating: "m", count: ScaCallback.maxMessageLength)
        XCTAssertEqual(parse("kind=error&code=Expired&message=\(maxMessage)"), .failure(.expired(message: maxMessage)))
    }

    func testOnlyTheKeysThePageWritesForEachKindAreAccepted() {
        for tail in [
            "kind=result&ceremony=challenge&payload=e30&extra=1",
            "kind=result&ceremony=challenge&payload=e30&code=Cancelled",
            "kind=result&ceremony=challenge&payload=e30&message=x",
            "kind=error&code=Cancelled&payload=e30",
            "kind=error&code=Cancelled&ceremony=challenge",
            "kind=error&code=Cancelled&token=tok-1"
        ] {
            XCTAssertEqual(
                parse(tail),
                .failure(.protocol(message: "Callback carried an unexpected parameter")),
                tail
            )
        }
    }

    func testAPayloadWithARepeatedTopLevelMemberIsRefused() {
        // {"id":"a","id":"b"}: a dictionary keeps one, the relayed text keeps both.
        let repeated = Base64URL.encode(Data("{\"id\":\"a\",\"id\":\"b\"}".utf8))
        XCTAssertEqual(
            parse("kind=result&ceremony=challenge&payload=\(repeated)"),
            .failure(.protocol(message: "Callback payload repeats a member"))
        )
        // The same name at different depths is not a repeat.
        let nested = "{\"id\":\"a\",\"response\":{\"id\":\"b\"}}"
        XCTAssertEqual(
            parse("kind=result&ceremony=challenge&payload=\(Base64URL.encode(Data(nested.utf8)))"),
            .success(nested)
        )
    }

    func testAMissingOrForeignStateIsAStateMismatch() {
        let base = Self.redirect
        for callback in [
            // The page omits a state it would not echo, so absence is the common case.
            "\(base)#v=1&kind=error&code=Cancelled",
            "\(base)#v=1&state=\(Self.otherState)&kind=error&code=Cancelled",
            "\(base)#v=1&state=\(Self.otherState)&kind=result&ceremony=challenge&payload=e30",
            "\(base)#v=1&state=&kind=result&ceremony=challenge&payload=e30",
            "\(base)#v=1&state=\(Self.state.lowercased())&kind=result&ceremony=challenge&payload=e30"
        ] {
            XCTAssertEqual(ScaCallback.parse(callback, for: request), .failure(.stateMismatch), callback)
        }
    }

    func testErrorMessageIsDecodedWithEncodeURIComponentSemantics() {
        // From encodeURIComponent: a literal plus arrives as %2B and must stay a plus.
        let encoded = "Ceremony%20expired.%20Try%20again%20%2B%20retry%20%26%20go"
        let result = parse("kind=error&code=Expired&message=\(encoded)")

        XCTAssertEqual(result, .failure(.expired(message: "Ceremony expired. Try again + retry & go")))
    }

    func testHTTPSTargetMatchesRegardlessOfSchemeAndHostCaseAndTrailingSlash() {
        let bare = request(redirectURI: "https://app.example.com")
        let result = ScaCallback.parse("HTTPS://App.Example.com/#\(Self.envelope)&kind=error&code=Cancelled", for: bare)

        XCTAssertEqual(result, .failure(.cancelled))
    }

    func testAnExplicitDefaultHTTPSPortMatchesNoPortInEitherDirection() {
        let explicit = request(redirectURI: "https://app.example.com:443/sca/callback")
        XCTAssertEqual(
            ScaCallback.parse("\(Self.redirect)#\(Self.envelope)&kind=error&code=Cancelled", for: explicit),
            .failure(.cancelled)
        )
        XCTAssertEqual(
            ScaCallback.parse(
                "https://app.example.com:443/sca/callback#\(Self.envelope)&kind=error&code=Cancelled",
                for: request
            ),
            .failure(.cancelled)
        )
        // Any other port is still a different target.
        XCTAssertEqual(
            ScaCallback.parse(
                "https://app.example.com:8443/sca/callback#\(Self.envelope)&kind=error&code=Cancelled",
                for: request
            ),
            .failure(.protocol(message: "Callback did not arrive at the configured redirect URI"))
        )
    }

    func testCustomSchemeTargetsAreMatched() {
        for redirect in ["com.example.app:/sca", "acme://sca-callback"] {
            let result = ScaCallback.parse(
                "\(redirect)#\(Self.envelope)&kind=error&code=Cancelled",
                for: request(redirectURI: redirect)
            )
            XCTAssertEqual(result, .failure(.cancelled), redirect)
        }
    }

    func testACallbackAtTheBrowsersSerializationOfAValidRedirectIsMatched() {
        // Each is accepted at configuration, and its WHATWG serialization (what
        // `window.location` navigates to) is the URI as written, so the
        // callback the session hands back is matched.
        for redirect in [
            "https://app.example.com/cb?tenant=o%27reilly",
            "https://app.example.com/cb?at=10:30",
            "https://app.example.com/%7Euser/cb",
            "acme://cb?tenant=o'reilly"
        ] {
            XCTAssertTrue(ScaConfigRules.isValidRedirectURI(redirect), redirect)
            let result = ScaCallback.parse(
                "\(redirect)#\(Self.envelope)&kind=error&code=Cancelled",
                for: request(redirectURI: redirect)
            )
            XCTAssertEqual(result, .failure(.cancelled), redirect)
        }
    }

    func testAnythingOffContractFailsAsProtocolAndNeverCompletes() {
        let base = Self.redirect
        let state = Self.state
        let callbacks = [
            // Envelope.
            base,
            "\(base)#",
            "https://app.example.com/other#v=1&state=\(state)&kind=error&code=Cancelled",
            "https://evil.example.com/sca/callback#v=1&state=\(state)&kind=error&code=Cancelled",
            "https://app.example.com/sca/callback?x=1#v=1&state=\(state)&kind=error&code=Cancelled",
            "https://user@app.example.com/sca/callback#v=1&state=\(state)&kind=error&code=Cancelled",
            "acme://sca/callback#v=1&state=\(state)&kind=error&code=Cancelled",
            // Version: wrong, missing, empty, duplicated.
            "\(base)#v=2&state=\(state)&kind=error&code=Cancelled",
            "\(base)#state=\(state)&kind=error&code=Cancelled",
            "\(base)#v=&state=\(state)&kind=error&code=Cancelled",
            "\(base)#v=1&v=1&state=\(state)&kind=error&code=Cancelled",
            // State duplicated to try to win either first- or last-wins.
            "\(base)#v=1&state=wrong&state=\(state)&kind=error&code=Cancelled",
            "\(base)#v=1&state=\(state)&state=wrong&kind=error&code=Cancelled",
            // Shape.
            "\(base)#v=1&state=\(state)&kind=bogus",
            "\(base)#v=1&state=\(state)",
            "\(base)#v=1&state=\(state)&kind=error&code=NotEnrolled",
            "\(base)#v=1&state=\(state)&kind=error&code=Bogus",
            "\(base)#v=1&state=\(state)&kind=error",
            "\(base)#v=1&state=\(state)&kind=error&code=Cancelled&=x",
            "\(base)#v=1&state=\(state)&kind=error&code=Cancelled&",
            "\(base)#v=1&state=\(state)&kind=error&code=%ZZ",
            // Result: wrong ceremony kind, missing, non-canonical, non-UTF-8, and non-object payloads.
            "\(base)#v=1&state=\(state)&kind=result&ceremony=registration&payload=e30",
            "\(base)#v=1&state=\(state)&kind=result&ceremony=challenge",
            "\(base)#v=1&state=\(state)&kind=result&ceremony=challenge&payload=",
            "\(base)#v=1&state=\(state)&kind=result&ceremony=challenge&payload=e30=",
            "\(base)#v=1&state=\(state)&kind=result&ceremony=challenge&payload=e31",
            "\(base)#v=1&state=\(state)&kind=result&ceremony=challenge&payload=e30%2B",
            "\(base)#v=1&state=\(state)&kind=result&ceremony=challenge&payload=_w",
            "\(base)#v=1&state=\(state)&kind=result&ceremony=challenge&payload=WzFd",
            "\(base)#v=1&state=\(state)&kind=result&ceremony=challenge&payload=eyJh"
        ]
        for callback in callbacks {
            guard case let .failure(.protocol(message)) = ScaCallback.parse(callback, for: request) else {
                XCTFail("Not rejected as Protocol: \(callback)")
                continue
            }
            XCTAssertNotNil(message, callback)
        }
    }

    func testProtocolMessageNeverEchoesTheCallback() {
        guard case let .failure(.protocol(message)) = parse("kind=result&ceremony=challenge&payload=WzFd") else {
            return XCTFail("Expected Protocol")
        }
        XCTAssertFalse(message?.contains(Self.state) ?? false)
        XCTAssertFalse(message?.contains("WzFd") ?? false)
    }

    func testRequestDescriptionsRevealNeitherTokenNorState() {
        let secret = ScaCeremonyRequest(
            kind: .registration,
            circleOrigin: "https://daa-sca.circle.com",
            redirectURI: Self.redirect,
            frameToken: "secret-token",
            state: Self.state
        )
        for rendering in [
            "\(secret)", String(describing: secret), String(reflecting: secret), secret.debugDescription
        ] {
            XCTAssertFalse(rendering.contains("secret-token"), rendering)
            XCTAssertFalse(rendering.contains(Self.state), rendering)
        }
    }

    private func parse(_ tail: String) -> Result<String, DaaScaError> {
        ScaCallback.parse("\(Self.redirect)#\(Self.envelope)&\(tail)", for: request)
    }

    private func request(redirectURI: String) -> ScaCeremonyRequest {
        ScaCeremonyRequest(
            kind: request.kind,
            circleOrigin: request.circleOrigin,
            redirectURI: redirectURI,
            frameToken: request.frameToken,
            state: request.state
        )
    }
}
