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

// The ceremony deadline: a per-kind default, a configured value applied only to
// its kind, dismissal as `expired`, and withdrawal whenever the ceremony ends some
// other way.
@MainActor
final class DaaScaDeadlineTests: XCTestCase {
    func testAConfiguredEnrollDeadlineAppliesToEnrollOnly() async throws {
        let launcher = FakeScaSessionLauncher()
        let scheduler = FakeScaDeadlineScheduler()
        let sca = try scaClient(launcher, scheduler: scheduler, enrollTimeout: 90)

        let task = Task { try await sca.enroll(frameToken: "tok-1", presentationAnchor: ASPresentationAnchor()) }
        _ = try await launcher.nextSession()
        XCTAssertEqual(scheduler.deadlines.map(\.seconds), [90])
        scheduler.deadlines.first?.fire()
        await assertScaThrows(task, .expired(message: ScaCallback.deadlineMessage))
    }

    func testACeremonyStillOpenAtTheDeadlineIsDismissedAndTimesOut() async throws {
        let launcher = FakeScaSessionLauncher()
        let scheduler = FakeScaDeadlineScheduler()
        let sca = try scaClient(launcher, scheduler: scheduler, approveTimeout: 45)

        let task = Task { try await sca.approve(frameToken: "tok-1", presentationAnchor: ASPresentationAnchor()) }
        let session = try await launcher.nextSession()
        let deadline = try XCTUnwrap(scheduler.deadlines.first)
        XCTAssertEqual(deadline.seconds, 45)

        deadline.fire()

        await assertScaThrows(task, .expired(message: ScaCallback.deadlineMessage))
        XCTAssertTrue(session.wasCancelled, "The sheet must be dismissed when the deadline passes")
        // A callback that arrives after the deadline reaches nobody.
        session.complete(kind: "result&ceremony=challenge&payload=e30")
    }

    func testACallbackThatRunsAfterTheDeadlineButBeforeItsFireExpires() async throws {
        let launcher = FakeScaSessionLauncher()
        let scheduler = FakeScaDeadlineScheduler()
        let sca = try scaClient(launcher, scheduler: scheduler)

        let task = Task { try await sca.approve(frameToken: "tok-1", presentationAnchor: ASPresentationAnchor()) }
        let session = try await launcher.nextSession()
        let deadline = try XCTUnwrap(scheduler.deadlines.first)

        // The deadline's time has come but its fire is still queued; a valid
        // result lands first.
        deadline.hasPassed = true
        session.complete(kind: "result&ceremony=challenge&payload=e30")

        await assertScaThrows(task, .expired(message: ScaCallback.deadlineMessage))
        XCTAssertFalse(session.wasCancelled, "The session already ended itself")
        XCTAssertTrue(deadline.wasCancelled)
        deadline.fire()
    }

    func testTheSystemDeadlineReportsWhenItsTimeHasPassed() async throws {
        let scheduler = SystemScaDeadlineScheduler()
        let distant = scheduler.schedule(after: 60) {}
        let immediate = scheduler.schedule(after: 0) {}
        defer {
            distant.cancel()
            immediate.cancel()
        }
        XCTAssertFalse(distant.hasPassed)
        XCTAssertTrue(immediate.hasPassed)
    }

    func testEachCeremonyKindGetsItsOwnDefaultDeadlineWithdrawnWhenItEnds() async throws {
        let launcher = FakeScaSessionLauncher()
        let scheduler = FakeScaDeadlineScheduler()
        let sca = try scaClient(launcher, scheduler: scheduler)

        let approve = Task { try await sca.approve(frameToken: "tok-1", presentationAnchor: ASPresentationAnchor()) }
        try await launcher.nextSession().complete(kind: "result&ceremony=challenge&payload=e30")
        _ = try await approve.value
        let enroll = Task { try await sca.enroll(frameToken: "tok-2", presentationAnchor: ASPresentationAnchor()) }
        try await launcher.nextSession().complete(kind: "result&ceremony=registration&payload=e30")
        _ = try await enroll.value

        XCTAssertEqual(scheduler.deadlines.map(\.seconds), [300, 600])
        XCTAssertTrue(scheduler.deadlines.allSatisfy(\.wasCancelled))

        // A deadline firing late, after the ceremony ended, changes nothing.
        scheduler.deadlines.first?.fire()
    }

    func testTheSystemSchedulerFiresOnceAndNeverAfterCancel() async throws {
        let scheduler = SystemScaDeadlineScheduler()
        let fired = expectation(description: "deadline fired")
        let withdrawn = expectation(description: "withdrawn deadline fired")
        withdrawn.isInverted = true

        let kept = scheduler.schedule(after: 0.01) { fired.fulfill() }
        scheduler.schedule(after: 0.01) { withdrawn.fulfill() }.cancel()

        await fulfillment(of: [fired, withdrawn], timeout: 0.5)
        kept.cancel()
    }

    func testATimeoutTaskThatStartsLateFiresAtOnceInsteadOfSleepingTheFullDuration() async throws {
        // The clock reads the scheduling instant once, then jumps an hour
        // ahead, as if the main actor were busy before the task started.
        let clock = SteppingClock(first: 1_000, then: 1_000 + 3_600_000_000_000)
        let scheduler = SystemScaDeadlineScheduler(clock: { clock.read() })
        let fired = expectation(description: "a late-starting deadline fired")

        let deadline = scheduler.schedule(after: 30) { fired.fulfill() }

        XCTAssertTrue(deadline.hasPassed)
        await fulfillment(of: [fired], timeout: 0.5)
    }

    func testATimeoutTaskSleepsOnlyWhatIsLeftOfTheAbsoluteExpiry() async throws {
        // Scheduled for 30 s, but 29.99 s have already elapsed when the task
        // starts: it must fire after the remaining 10 ms, not 30 s.
        let clock = SteppingClock(first: 0, then: 29_990_000_000)
        let scheduler = SystemScaDeadlineScheduler(clock: { clock.read() })
        let fired = expectation(description: "fired after the remaining time")

        let deadline = scheduler.schedule(after: 30) { fired.fulfill() }

        await fulfillment(of: [fired], timeout: 0.5)
        deadline.cancel()
    }

    func testTheSystemSchedulerClampsAnyDurationInsteadOfTrapping() async throws {
        XCTAssertEqual(SystemScaDeadlineScheduler.nanoseconds(30), 30_000_000_000)
        XCTAssertEqual(SystemScaDeadlineScheduler.nanoseconds(3_600), 3_600_000_000_000)
        let ceiling = SystemScaDeadlineScheduler.nanoseconds(DaaScaConfiguration.maximumCeremonyTimeout)
        for huge in [3_600.001, 20_000_000_000, .greatestFiniteMagnitude, .infinity] as [TimeInterval] {
            XCTAssertEqual(SystemScaDeadlineScheduler.nanoseconds(huge), ceiling, "\(huge)")
        }
        for none in [-1, -.infinity, .nan] as [TimeInterval] {
            XCTAssertEqual(SystemScaDeadlineScheduler.nanoseconds(none), 0, "\(none)")
        }

        // Scheduling directly with a huge value neither traps nor fires early.
        let scheduler = SystemScaDeadlineScheduler()
        let early = expectation(description: "a clamped deadline fired early")
        early.isInverted = true
        let deadlines = [20_000_000_000, .greatestFiniteMagnitude, .infinity].map { (seconds: TimeInterval) in
            scheduler.schedule(after: seconds) { early.fulfill() }
        }
        await fulfillment(of: [early], timeout: 0.1)
        deadlines.forEach { $0.cancel() }
    }

    func testNoDeadlineIsScheduledWhenNoSheetWasPresented() async throws {
        let launcher = FakeScaSessionLauncher(launchError: .sessionUnavailable(message: "no"))
        let scheduler = FakeScaDeadlineScheduler()
        let sca = try scaClient(launcher, scheduler: scheduler)

        await assertScaThrows(
            Task { try await sca.approve(frameToken: "tok-1", presentationAnchor: ASPresentationAnchor()) },
            .sessionUnavailable(message: "no")
        )
        XCTAssertTrue(scheduler.deadlines.isEmpty)
    }

    func testReplacingOrCancellingACeremonyWithdrawsItsDeadline() async throws {
        let launcher = FakeScaSessionLauncher()
        let scheduler = FakeScaDeadlineScheduler()
        let sca = try scaClient(launcher, scheduler: scheduler)

        let first = Task { try await sca.approve(frameToken: "tok-1", presentationAnchor: ASPresentationAnchor()) }
        _ = try await launcher.nextSession()
        let second = Task { try await sca.approve(frameToken: "tok-2", presentationAnchor: ASPresentationAnchor()) }
        _ = try await launcher.nextSession()
        await assertScaThrows(first, .cancelled)
        second.cancel()
        await assertScaThrows(second, .cancelled)

        XCTAssertEqual(scheduler.deadlines.count, 2)
        XCTAssertTrue(scheduler.deadlines.allSatisfy(\.wasCancelled))
    }
}

/// Returns `first` on the first read and `then` on every later read, plus the
/// real time elapsed since the second read so sleeping still advances it.
private final class SteppingClock: @unchecked Sendable {
    private let lock = NSLock()
    private let first: UInt64
    private let then: UInt64
    private var start: UInt64?

    init(first: UInt64, then: UInt64) {
        self.first = first
        self.then = then
    }

    func read() -> UInt64 {
        lock.lock()
        defer { lock.unlock() }
        guard let start else {
            start = SystemScaDeadlineScheduler.now()
            return first
        }
        return then + (SystemScaDeadlineScheduler.now() - start)
    }
}
