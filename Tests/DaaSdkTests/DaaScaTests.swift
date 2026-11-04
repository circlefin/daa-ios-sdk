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

import AuthenticationServices
import XCTest

@testable import DaaSdk

// Lifecycle tests against an injected launcher and deadline scheduler: one
// result per call, the callback checked against the ceremony that opened it,
// replacement, task cancellation, a sheet closed with no callback,
// capabilities, and the session retained until the ceremony ends. The deadline
// is in `DaaScaDeadlineTests`.
@MainActor
final class DaaScaTests: XCTestCase {
    private static let redirect = ScaCallbackTests.redirect

    func testApproveOpensTheCeremonyAndRelaysTheExactResponse() async throws {
        let launcher = FakeScaSessionLauncher()
        let sca = try scaClient(launcher)

        let task = Task { try await sca.approve(frameToken: "tok-1", presentationAnchor: ASPresentationAnchor()) }
        let session = try await launcher.nextSession()

        XCTAssertEqual(session.callback, .https(host: "app.example.com", path: "/sca/callback"))
        let url = session.url.absoluteString
        XCTAssertTrue(url.hasPrefix("https://daa-sca.circle.com/ceremony#token=tok-1&state="), url)
        session.complete(kind: "result&ceremony=challenge&payload=\(ScaCallbackTests.assertionBase64URL)")

        let response = try await task.value
        XCTAssertEqual(response, ScaCallbackTests.assertionJSON)
    }

    func testEnrollExpectsARegistrationCallback() async throws {
        let launcher = FakeScaSessionLauncher()
        let sca = try scaClient(launcher)

        let enroll = Task { try await sca.enroll(frameToken: "tok-1", presentationAnchor: ASPresentationAnchor()) }
        try await launcher.nextSession().complete(kind: "result&ceremony=registration&payload=e30")
        let enrolled = try await enroll.value
        XCTAssertEqual(enrolled, "{}")

        let mismatched = Task { try await sca.enroll(frameToken: "tok-2", presentationAnchor: ASPresentationAnchor()) }
        try await launcher.nextSession().complete(kind: "result&ceremony=challenge&payload=e30")
        await assertScaThrows(mismatched, .protocol(message: "Callback is for a different ceremony kind"))
    }

    func testEachCeremonyGetsFreshStateAndAStaleCallbackCannotCompleteANewOne() async throws {
        let launcher = FakeScaSessionLauncher()
        let sca = try scaClient(launcher)

        let first = Task { try await sca.approve(frameToken: "tok-1", presentationAnchor: ASPresentationAnchor()) }
        let firstSession = try await launcher.nextSession()
        firstSession.complete(kind: "error&code=Cancelled")
        await assertScaThrows(first, .cancelled)

        let second = Task { try await sca.approve(frameToken: "tok-2", presentationAnchor: ASPresentationAnchor()) }
        let secondSession = try await launcher.nextSession()
        XCTAssertNotEqual(firstSession.state, secondSession.state)
        secondSession.complete(
            url: "\(Self.redirect)#v=1&state=\(firstSession.state)&kind=result&ceremony=challenge&payload=e30"
        )
        await assertScaThrows(second, .stateMismatch)
    }

    func testClosingTheSheetWithNoCallbackIsCancelled() async throws {
        // An expired or consumed token never redirects; the page asks the
        // user to close the window, which the session reports as canceledLogin.
        let launcher = FakeScaSessionLauncher()
        let scheduler = FakeScaDeadlineScheduler()
        let sca = try scaClient(launcher, scheduler: scheduler)

        let task = Task { try await sca.enroll(frameToken: "tok-1", presentationAnchor: ASPresentationAnchor()) }
        let session = try await launcher.nextSession()
        session.closeWithoutCallback()

        await assertScaThrows(task, .cancelled)
        XCTAssertFalse(session.wasCancelled, "The session ended itself; the SDK must not cancel it again")
        XCTAssertTrue(scheduler.deadlines.allSatisfy(\.wasCancelled), "No deadline may outlive the ceremony")
    }

    func testTheSessionErrorMappingTreatsAClosedSheetAsCancelled() {
        let canceled = ASWebAuthenticationSessionError(.canceledLogin)
        guard case .failed(.cancelled) = SystemScaSessionLauncher.outcome(url: nil, error: canceled) else {
            return XCTFail("canceledLogin must map to cancelled")
        }
        for code in [
            ASWebAuthenticationSessionError.Code.presentationContextNotProvided, .presentationContextInvalid
        ] {
            let outcome = SystemScaSessionLauncher.outcome(url: nil, error: ASWebAuthenticationSessionError(code))
            guard case .failed(.sessionUnavailable) = outcome else {
                return XCTFail("\(code) must map to sessionUnavailable")
            }
        }
        let foreign = SystemScaSessionLauncher.outcome(url: nil, error: URLError(.notConnectedToInternet))
        XCTAssertEqual(foreign.error, .sessionUnavailable(message: "The authentication session failed"))
        let callback = URL(string: "acme://cb#v=1")!
        guard case let .callback(url) = SystemScaSessionLauncher.outcome(url: callback, error: canceled) else {
            return XCTFail("A callback URL wins over any error")
        }
        XCTAssertEqual(url, callback)
    }

    func testSessionFailuresPassThrough() async throws {
        let launcher = FakeScaSessionLauncher()
        let sca = try scaClient(launcher)

        let task = Task { try await sca.approve(frameToken: "tok-1", presentationAnchor: ASPresentationAnchor()) }
        try await launcher.nextSession().fail(.cancelled)

        await assertScaThrows(task, .cancelled)
    }

    func testANewCeremonyReplacesTheOpenOne() async throws {
        let launcher = FakeScaSessionLauncher()
        let sca = try scaClient(launcher)

        let first = Task { try await sca.approve(frameToken: "tok-1", presentationAnchor: ASPresentationAnchor()) }
        let firstSession = try await launcher.nextSession()
        let second = Task { try await sca.approve(frameToken: "tok-2", presentationAnchor: ASPresentationAnchor()) }
        let secondSession = try await launcher.nextSession()

        await assertScaThrows(first, .cancelled)
        XCTAssertTrue(firstSession.wasCancelled)
        // The replaced session's late callback reaches nobody.
        firstSession.complete(kind: "result&ceremony=challenge&payload=e30")

        secondSession.complete(kind: "result&ceremony=challenge&payload=e30")
        let response = try await second.value
        XCTAssertEqual(response, "{}")
        XCTAssertFalse(secondSession.wasCancelled)
    }

    func testCancellingTheTaskCancelsTheCeremony() async throws {
        let launcher = FakeScaSessionLauncher()
        let sca = try scaClient(launcher)

        let task = Task { try await sca.approve(frameToken: "tok-1", presentationAnchor: ASPresentationAnchor()) }
        let session = try await launcher.nextSession()
        task.cancel()

        await assertScaThrows(task, .cancelled)
        XCTAssertTrue(session.wasCancelled)
    }

    func testAnAlreadyCancelledTaskNeverPresentsASheet() async throws {
        let launcher = FakeScaSessionLauncher()
        let sca = try scaClient(launcher)

        let task = Task {
            withUnsafeCurrentTask { $0?.cancel() }
            return try await sca.approve(frameToken: "tok-1", presentationAnchor: ASPresentationAnchor())
        }

        await assertScaThrows(task, .cancelled)
        XCTAssertEqual(launcher.launchCount, 0)
    }

    func testAnAlreadyCancelledCallDoesNotReplaceTheOpenCeremony() async throws {
        let launcher = FakeScaSessionLauncher()
        let sca = try scaClient(launcher)

        let open = Task { try await sca.approve(frameToken: "tok-1", presentationAnchor: ASPresentationAnchor()) }
        let openSession = try await launcher.nextSession()
        let cancelled = Task {
            withUnsafeCurrentTask { $0?.cancel() }
            return try await sca.approve(frameToken: "tok-2", presentationAnchor: ASPresentationAnchor())
        }
        await assertScaThrows(cancelled, .cancelled)

        XCTAssertFalse(openSession.wasCancelled)
        openSession.complete(kind: "result&ceremony=challenge&payload=e30")
        let response = try await open.value
        XCTAssertEqual(response, "{}")
        XCTAssertEqual(launcher.launchCount, 1)
    }

    func testTheSessionIsRetainedUntilTheCeremonyEnds() async throws {
        let launcher = FakeScaSessionLauncher(retainsSessions: false)
        let sca = try scaClient(launcher)

        let task = Task { try await sca.approve(frameToken: "tok-1", presentationAnchor: ASPresentationAnchor()) }
        weak var session = try await launcher.nextSession()
        XCTAssertNotNil(session, "The SDK, not the caller, must hold the session while it is open")

        session?.complete(kind: "error&code=Cancelled")
        await assertScaThrows(task, .cancelled)
        XCTAssertNil(session, "The session must be released once the ceremony ends")
    }

    func testAMalformedOrOversizedTokenFailsBeforeAnySheetOpens() async throws {
        let launcher = FakeScaSessionLauncher()
        let sca = try scaClient(launcher)

        let oversized = String(repeating: "a", count: ScaCeremonyRequest.maxFrameTokenLength + 1)
        for token in ["tok 1", "tok&state=x", "tok#1", "tok%201", "tök", "tok\n", oversized] {
            await assertScaThrows(
                Task { try await sca.approve(frameToken: token, presentationAnchor: ASPresentationAnchor()) },
                .protocol(message: "frameToken is malformed")
            )
        }
        XCTAssertEqual(launcher.launchCount, 0)

        // A real token shape, at the cap, still opens.
        let atCap = String(repeating: "A", count: ScaCeremonyRequest.maxFrameTokenLength)
        for token in ["k3Jx0Qp2V9mZsYbT7uWc1eFgHiLnOrAdEvGhIjKlMn0", "a.b~c-d_e", atCap] {
            let task = Task { try await sca.approve(frameToken: token, presentationAnchor: ASPresentationAnchor()) }
            try await launcher.nextSession().complete(kind: "result&ceremony=challenge&payload=e30")
            let response = try await task.value
            XCTAssertEqual(response, "{}")
        }
    }

    func testABlankTokenFailsBeforeAnySheetOpens() async throws {
        let launcher = FakeScaSessionLauncher()
        let sca = try scaClient(launcher)

        for token in ["", "  \n"] {
            await assertScaThrows(
                Task { try await sca.approve(frameToken: token, presentationAnchor: ASPresentationAnchor()) },
                .protocol(message: "frameToken must not be blank")
            )
        }
        XCTAssertEqual(launcher.launchCount, 0)
    }

    func testAnUndeliverableCallbackIsSessionUnavailableAndReportedByCapabilities() async throws {
        let launcher = FakeScaSessionLauncher(supportsHTTPS: false)
        let sca = try scaClient(launcher)

        let capabilities = sca.capabilities()
        XCTAssertEqual(capabilities.protocolVersion, 1)
        XCTAssertEqual(capabilities.surface, .none)
        XCTAssertFalse(capabilities.callbackSupported)
        XCTAssertFalse(capabilities.isCeremonySupported)
        await assertScaThrows(
            Task { try await sca.approve(frameToken: "tok-1", presentationAnchor: ASPresentationAnchor()) },
            .sessionUnavailable(message: "This OS cannot deliver the configured callback to the session")
        )
        XCTAssertEqual(launcher.launchCount, 0)

        let custom = try scaClient(launcher, redirectURI: "acme://sca-callback")
        XCTAssertEqual(custom.capabilities().surface, .webAuthenticationSession)
        XCTAssertTrue(custom.capabilities().callbackSupported)
        XCTAssertTrue(custom.capabilities().isCeremonySupported)
    }

    func testCapabilitiesDoNotClaimSupportWithoutPlatformPasskeys() throws {
        // iOS 15: the sheet can be shown, but the page could only reach `Unsupported`.
        let sca = try scaClient(FakeScaSessionLauncher(), redirectURI: "acme://sca-callback", platformPasskeys: false)

        let capabilities = sca.capabilities()
        XCTAssertEqual(capabilities.surface, .webAuthenticationSession)
        XCTAssertTrue(capabilities.callbackSupported)
        XCTAssertFalse(capabilities.platformPasskeys)
        XCTAssertFalse(capabilities.isCeremonySupported)
    }

    func testThePublicClientReportsThisOSHonestly() throws {
        let sca = DaaSca(configuration: try DaaScaConfiguration(environment: .production, redirectURI: "acme://cb"))
        let capabilities = sca.capabilities()
        var passkeys = false
        if #available(iOS 16, macOS 13, *) {
            passkeys = true
        }
        XCTAssertEqual(capabilities.platformPasskeys, passkeys)
        XCTAssertEqual(capabilities.surface, .webAuthenticationSession)
        XCTAssertEqual(capabilities.isCeremonySupported, passkeys)
    }

    func testALaunchThatCannotStartIsSessionUnavailable() async throws {
        let launcher = FakeScaSessionLauncher(launchError: .sessionUnavailable(message: "no"))
        let sca = try scaClient(launcher)

        await assertScaThrows(
            Task { try await sca.approve(frameToken: "tok-1", presentationAnchor: ASPresentationAnchor()) },
            .sessionUnavailable(message: "no")
        )
    }

    func testAPageErrorCallbackIsRelayedAsItsError() async throws {
        let launcher = FakeScaSessionLauncher()
        let sca = try scaClient(launcher)

        let task = Task { try await sca.enroll(frameToken: "tok-1", presentationAnchor: ASPresentationAnchor()) }
        try await launcher.nextSession().complete(kind: "error&code=AlreadyEnrolled")

        await assertScaThrows(task, .alreadyEnrolled(message: nil))
    }

    func testTheSystemLauncherSupportsCustomSchemesEverywhere() {
        XCTAssertTrue(SystemScaSessionLauncher().supports(.customScheme("acme")))
    }

}
