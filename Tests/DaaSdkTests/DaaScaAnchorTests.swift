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

// The anchor-less `approve(frameToken:)` / `enroll(frameToken:)` overloads,
// against an injected foreground-window lookup and wait, the system wait
// itself, and the developer-facing `LocalizedError` descriptions.
@MainActor
final class DaaScaAnchorTests: XCTestCase {
    func testApproveWithoutAnAnchorPresentsOverTheForegroundWindow() async throws {
        let window = ASPresentationAnchor()
        let launcher = FakeScaSessionLauncher()
        let sca = try scaClient(launcher, anchorProvider: { window })

        let task = Task { try await sca.approve(frameToken: "tok-1") }
        let session = try await launcher.nextSession()
        XCTAssertTrue(launcher.lastAnchor === window, "The sheet must present over the foreground key window")
        session.complete(kind: "result&ceremony=challenge&payload=\(ScaCallbackTests.assertionBase64URL)")

        let response = try await task.value
        XCTAssertEqual(response, ScaCallbackTests.assertionJSON)
    }

    func testEnrollWithoutAnAnchorRunsARegistrationCeremony() async throws {
        let window = ASPresentationAnchor()
        let launcher = FakeScaSessionLauncher()
        let sca = try scaClient(launcher, anchorProvider: { window })

        let task = Task { try await sca.enroll(frameToken: "tok-1") }
        try await launcher.nextSession().complete(kind: "result&ceremony=registration&payload=e30")

        let response = try await task.value
        XCTAssertEqual(response, "{}")
        XCTAssertTrue(launcher.lastAnchor === window)
    }

    func testWithoutAForegroundWindowNeitherCallOpensASheet() async throws {
        let launcher = FakeScaSessionLauncher()
        let scheduler = FakeScaDeadlineScheduler()
        let sca = try scaClient(launcher, scheduler: scheduler, anchorProvider: { nil })
        let expected = DaaScaError.sessionUnavailable(message: "No foreground scene has a key window to present from")

        await assertScaThrows(Task { try await sca.approve(frameToken: "tok-1") }, expected)
        await assertScaThrows(Task { try await sca.enroll(frameToken: "tok-1") }, expected)
        XCTAssertEqual(launcher.launchCount, 0)
        XCTAssertTrue(scheduler.deadlines.isEmpty)
    }

    func testAMissingWindowDoesNotReplaceTheOpenCeremony() async throws {
        var window: ASPresentationAnchor? = ASPresentationAnchor()
        let launcher = FakeScaSessionLauncher()
        let sca = try scaClient(launcher, anchorProvider: { window })

        let open = Task { try await sca.approve(frameToken: "tok-1") }
        let session = try await launcher.nextSession()
        window = nil
        await assertScaThrows(
            Task { try await sca.approve(frameToken: "tok-2") },
            .sessionUnavailable(message: "No foreground scene has a key window to present from")
        )
        XCTAssertFalse(session.wasCancelled, "A call that cannot present must leave the open ceremony alone")

        session.complete(kind: "result&ceremony=challenge&payload=e30")
        let response = try await open.value
        XCTAssertEqual(response, "{}")
    }

    func testAWindowAvailableAtTheCallIsUsedWithoutWaiting() async throws {
        let window = ASPresentationAnchor()
        let launcher = FakeScaSessionLauncher()
        let scheduler = FakeScaDeadlineScheduler()
        let waiter = FakeScaAnchorWaiter()
        let sca = try scaClient(launcher, scheduler: scheduler, anchorProvider: { window }, anchorWaiter: waiter)

        let task = Task { try await sca.approve(frameToken: "tok-1") }
        try await launcher.nextSession().complete(kind: "result&ceremony=challenge&payload=e30")

        _ = try await task.value
        XCTAssertTrue(waiter.timeouts.isEmpty, "A window that is already key must not be waited for")
        XCTAssertEqual(scheduler.deadlines.map(\.seconds), [DaaScaConfiguration.defaultApproveTimeout])
    }

    func testAWindowThatBecomesKeyWhileWaitingOpensTheCeremonyOverIt() async throws {
        var window: ASPresentationAnchor?
        let appeared = ASPresentationAnchor()
        let launcher = FakeScaSessionLauncher()
        let scheduler = FakeScaDeadlineScheduler()
        let waiter = FakeScaAnchorWaiter()
        waiter.duringWait = {
            XCTAssertEqual(launcher.launchCount, 0, "Nothing may be presented before a window is found")
            window = appeared
        }
        waiter.elapsed = 0.4
        let sca = try scaClient(
            launcher,
            scheduler: scheduler,
            approveTimeout: 45,
            anchorProvider: { window },
            anchorWaiter: waiter
        )

        let task = Task { try await sca.approve(frameToken: "tok-1") }
        let session = try await launcher.nextSession()
        XCTAssertTrue(launcher.lastAnchor === appeared)
        XCTAssertEqual(waiter.timeouts, [DaaSca.foregroundWindowWait])
        XCTAssertEqual(scheduler.deadlines.map(\.seconds), [44.6], "The wait counts against the deadline")
        session.complete(kind: "result&ceremony=challenge&payload=e30")

        let response = try await task.value
        XCTAssertEqual(response, "{}")
    }

    func testEnrollAlsoWaitsForAWindowAndCountsTheWaitAgainstItsDeadline() async throws {
        var window: ASPresentationAnchor?
        let launcher = FakeScaSessionLauncher()
        let scheduler = FakeScaDeadlineScheduler()
        let waiter = FakeScaAnchorWaiter()
        waiter.duringWait = { window = ASPresentationAnchor() }
        waiter.elapsed = 1
        let sca = try scaClient(launcher, scheduler: scheduler, anchorProvider: { window }, anchorWaiter: waiter)

        let task = Task { try await sca.enroll(frameToken: "tok-1") }
        try await launcher.nextSession().complete(kind: "result&ceremony=registration&payload=e30")

        _ = try await task.value
        XCTAssertEqual(waiter.timeouts, [DaaSca.foregroundWindowWait])
        XCTAssertEqual(scheduler.deadlines.map(\.seconds), [DaaScaConfiguration.defaultEnrollTimeout - 1])
    }

    func testNoWindowWithinTheWaitFailsWithTheUnchangedError() async throws {
        let launcher = FakeScaSessionLauncher()
        let scheduler = FakeScaDeadlineScheduler()
        let waiter = FakeScaAnchorWaiter()
        waiter.elapsed = DaaSca.foregroundWindowWait
        let sca = try scaClient(launcher, scheduler: scheduler, anchorProvider: { nil }, anchorWaiter: waiter)

        await assertScaThrows(
            Task { try await sca.approve(frameToken: "tok-1") },
            .sessionUnavailable(message: "No foreground scene has a key window to present from")
        )
        XCTAssertEqual(waiter.timeouts, [DaaSca.foregroundWindowWait])
        XCTAssertEqual(launcher.launchCount, 0)
        XCTAssertTrue(scheduler.deadlines.isEmpty)
    }

    func testCancellingTheTaskWhileWaitingIsCancelledAndOpensNothing() async throws {
        let launcher = FakeScaSessionLauncher()
        let waiter = FakeScaAnchorWaiter()
        waiter.cancelsWait = true
        let sca = try scaClient(launcher, anchorProvider: { nil }, anchorWaiter: waiter)

        await assertScaThrows(Task { try await sca.enroll(frameToken: "tok-1") }, .cancelled)
        XCTAssertEqual(launcher.launchCount, 0)
    }

    func testAnExplicitAnchorIsNeverLookedUpOrWaitedFor() async throws {
        let anchor = ASPresentationAnchor()
        let launcher = FakeScaSessionLauncher()
        let waiter = FakeScaAnchorWaiter()
        var lookups = 0
        let sca = try scaClient(
            launcher,
            anchorProvider: {
                lookups += 1
                return nil
            },
            anchorWaiter: waiter
        )

        let task = Task { try await sca.approve(frameToken: "tok-1", presentationAnchor: anchor) }
        try await launcher.nextSession().complete(kind: "result&ceremony=challenge&payload=e30")

        _ = try await task.value
        XCTAssertTrue(launcher.lastAnchor === anchor)
        XCTAssertEqual(lookups, 0)
        XCTAssertTrue(waiter.timeouts.isEmpty)
    }

    func testTheSystemWaitReturnsAWindowThatBecomesKey() async throws {
        let window = ASPresentationAnchor()
        var lookups = 0
        let waiter = SystemScaAnchorWaiter(pollInterval: 0.005)

        let wait = try await waiter.waitForAnchor(timeout: 5) {
            lookups += 1
            return lookups >= 3 ? window : nil
        }

        XCTAssertTrue(wait.anchor === window)
        XCTAssertEqual(lookups, 3)
        XCTAssertGreaterThan(wait.elapsed, 0)
        XCTAssertLessThan(wait.elapsed, 5)
    }

    func testTheSystemWaitGivesUpAtItsTimeout() async throws {
        var lookups = 0
        let waiter = SystemScaAnchorWaiter(pollInterval: 0.01)

        let wait = try await waiter.waitForAnchor(timeout: 0.05) {
            lookups += 1
            return nil
        }

        XCTAssertNil(wait.anchor)
        XCTAssertGreaterThanOrEqual(wait.elapsed, 0.05)
        XCTAssertGreaterThan(lookups, 0, "The lookup must be re-run while waiting")
    }

    func testTheSystemWaitNeverOutlastsItsTimeoutOnASlowClock() async throws {
        // A clock that jumps past the expiry on the first re-read: the wait
        // must not sleep again.
        let ticks = Ticks()
        let waiter = SystemScaAnchorWaiter(pollInterval: 0.001) { ticks.next() }

        let wait = try await waiter.waitForAnchor(timeout: 2) { nil }

        XCTAssertNil(wait.anchor)
        XCTAssertEqual(wait.elapsed, 3)
    }

    func testAnOlderCallStillWaitingForAWindowDoesNotReplaceANewerCeremony() async throws {
        // A waits (suspended) for a window; B presents with an explicit anchor;
        // A's window then appears. B's ceremony must stay open; A stands down.
        var window: ASPresentationAnchor?
        let waiter = FakeScaAnchorWaiter()
        waiter.holds = true
        let launcher = FakeScaSessionLauncher()
        let sca = try scaClient(launcher, anchorProvider: { window }, anchorWaiter: waiter)

        let older = Task { try await sca.approve(frameToken: "tok-1") }
        await waiter.untilHeld(1)
        let newer = Task { try await sca.approve(frameToken: "tok-2", presentationAnchor: ASPresentationAnchor()) }
        let session = try await launcher.nextSession()

        window = ASPresentationAnchor()
        waiter.releaseAll()
        await settle()
        // Checked before awaiting `older`, so a regression fails here instead
        // of hanging on a ceremony nobody completes.
        guard !session.wasCancelled, launcher.launchCount == 1 else {
            XCTFail("The older call replaced the newer ceremony")
            older.cancel()
            newer.cancel()
            return
        }
        await assertScaThrows(older, .cancelled)

        session.complete(kind: "result&ceremony=challenge&payload=e30")
        let response = try await newer.value
        XCTAssertEqual(response, "{}")
    }

    func testOfTwoCallsWaitingForAWindowOnlyTheNewerOpensOne() async throws {
        var window: ASPresentationAnchor?
        let waiter = FakeScaAnchorWaiter()
        waiter.holds = true
        let launcher = FakeScaSessionLauncher()
        let sca = try scaClient(launcher, anchorProvider: { window }, anchorWaiter: waiter)

        let older = Task { try await sca.approve(frameToken: "tok-1") }
        await waiter.untilHeld(1)
        let newer = Task { try await sca.enroll(frameToken: "tok-2") }
        await waiter.untilHeld(2)

        window = ASPresentationAnchor()
        waiter.releaseAll()
        await settle()
        guard launcher.launchCount == 1 else {
            XCTFail("Both waiting calls opened a sheet")
            older.cancel()
            newer.cancel()
            return
        }
        await assertScaThrows(older, .cancelled)
        let session = try await launcher.nextSession()

        session.complete(kind: "result&ceremony=registration&payload=e30")
        let response = try await newer.value
        XCTAssertEqual(response, "{}")
    }

    func testANewerCallThatWaitedStillReplacesAnOlderOpenCeremony() async throws {
        // The newest call still wins when it is the one that waited.
        var window: ASPresentationAnchor? = ASPresentationAnchor()
        let waiter = FakeScaAnchorWaiter()
        waiter.holds = true
        let launcher = FakeScaSessionLauncher()
        let sca = try scaClient(launcher, anchorProvider: { window }, anchorWaiter: waiter)

        let older = Task { try await sca.approve(frameToken: "tok-1") }
        let first = try await launcher.nextSession()
        window = nil
        let newer = Task { try await sca.approve(frameToken: "tok-2") }
        await waiter.untilHeld(1)

        window = ASPresentationAnchor()
        waiter.releaseAll()
        let second = try await launcher.nextSession()
        await assertScaThrows(older, .cancelled)
        XCTAssertTrue(first.wasCancelled)

        second.complete(kind: "result&ceremony=challenge&payload=e30")
        let response = try await newer.value
        XCTAssertEqual(response, "{}")
    }

    func testTheSystemWaitRejectsAWindowFoundAfterALateWake() async throws {
        // The clock is before the expiry when the wait goes to sleep, and past
        // it when it wakes; a window is available by then. It must not be used.
        let clock = LateWake()
        let waiter = SystemScaAnchorWaiter(pollInterval: 0.001) { clock.next() }

        let wait = try await waiter.waitForAnchor(timeout: 2) { ASPresentationAnchor() }

        XCTAssertNil(wait.anchor, "A window found after the wait expired must not be accepted")
    }

    func testTheSystemWaitStopsWhenItsTaskIsCancelled() async throws {
        let waiter = SystemScaAnchorWaiter(pollInterval: 0.01)
        let task = Task { @MainActor in
            try await waiter.waitForAnchor(timeout: 60) { nil }.elapsed
        }
        task.cancel()

        do {
            _ = try await task.value
            XCTFail("A cancelled wait must throw")
        } catch {
            XCTAssertTrue(error is CancellationError)
        }
    }

    func testErrorDescriptionsAreFixedEnglishWithoutTheDiagnosticMessage() {
        let secret = "diagnostic-detail"
        let cases: [DaaScaError] = [
            .cancelled,
            .expired(message: secret),
            .unsupported(message: secret),
            .alreadyEnrolled(message: secret),
            .stateMismatch,
            .sessionUnavailable(message: secret),
            .protocol(message: secret)
        ]
        var seen = Set<String>()
        for error in cases {
            let description = error.errorDescription ?? ""
            XCTAssertFalse(description.isEmpty, "\(error) has no description")
            XCTAssertFalse(description.contains(secret), "\(error) leaks its diagnostic message")
            XCTAssertEqual(error.localizedDescription, description)
            seen.insert(description)
        }
        XCTAssertEqual(seen.count, cases.count, "Each case needs its own description")
        XCTAssertEqual(
            DaaScaError.expired(message: nil).errorDescription,
            DaaScaError.expired(message: secret).errorDescription
        )
    }
}

/// A monotonic clock reading 0 s, then 3 s on every later read.
private final class Ticks: @unchecked Sendable {
    private let lock = NSLock()
    private var reads = 0

    func next() -> UInt64 {
        lock.lock()
        defer { lock.unlock() }
        reads += 1
        return reads == 1 ? 0 : 3_000_000_000
    }
}

/// Lets every task that is ready run on the main actor.
@MainActor
private func settle() async {
    for _ in 0..<50 {
        await Task.yield()
    }
}

/// Before the expiry for the first two reads (start, loop check), past it after.
private final class LateWake: @unchecked Sendable {
    private let lock = NSLock()
    private var reads = 0

    func next() -> UInt64 {
        lock.lock()
        defer { lock.unlock() }
        reads += 1
        return reads <= 2 ? 0 : 3_000_000_000
    }
}
