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

// Fakes and helpers shared by the `DaaSca` lifecycle and deadline suites.

@MainActor
extension XCTestCase {
    func scaClient(
        _ launcher: FakeScaSessionLauncher,
        scheduler: FakeScaDeadlineScheduler = FakeScaDeadlineScheduler(),
        redirectURI: String = ScaCallbackTests.redirect,
        approveTimeout: TimeInterval = DaaScaConfiguration.defaultApproveTimeout,
        enrollTimeout: TimeInterval = DaaScaConfiguration.defaultEnrollTimeout,
        platformPasskeys: Bool = true,
        anchorProvider: (@MainActor () -> ASPresentationAnchor?)? = nil,
        anchorWaiter: FakeScaAnchorWaiter = FakeScaAnchorWaiter()
    ) throws -> DaaSca {
        DaaSca(
            configuration: try DaaScaConfiguration(
                environment: .production,
                redirectURI: redirectURI,
                circleOrigin: nil,
                approveTimeout: approveTimeout,
                enrollTimeout: enrollTimeout,
                httpsCallbackAvailable: true
            ),
            launcher: launcher,
            scheduler: scheduler,
            platformPasskeys: platformPasskeys,
            anchorProvider: anchorProvider,
            anchorWaiter: anchorWaiter
        )
    }

    func assertScaThrows(
        _ task: Task<String, Error>,
        _ expected: DaaScaError,
        file: StaticString = #filePath,
        line: UInt = #line
    ) async {
        do {
            _ = try await task.value
            XCTFail("Expected \(expected)", file: file, line: line)
        } catch {
            XCTAssertEqual(error as? DaaScaError, expected, file: file, line: line)
        }
    }
}

@MainActor
final class FakeScaSessionLauncher: ScaSessionLaunching {
    private let supportsHTTPS: Bool
    private let retainsSessions: Bool
    private let launchError: DaaScaError?
    private var retained: [FakeScaSession] = []
    private var unclaimed: [FakeScaSession] = []
    private var waiters: [CheckedContinuation<FakeScaSession, Never>] = []
    private(set) var launchCount = 0
    private(set) var lastAnchor: ASPresentationAnchor?

    init(supportsHTTPS: Bool = true, retainsSessions: Bool = true, launchError: DaaScaError? = nil) {
        self.supportsHTTPS = supportsHTTPS
        self.retainsSessions = retainsSessions
        self.launchError = launchError
    }

    func supports(_ callback: ScaSessionCallback) -> Bool {
        if case .https = callback {
            return supportsHTTPS
        }
        return true
    }

    func launch(
        url: URL,
        callback: ScaSessionCallback,
        presentationAnchor: ASPresentationAnchor,
        completion: @escaping @MainActor @Sendable (ScaSessionOutcome) -> Void
    ) throws -> any ScaSession {
        launchCount += 1
        lastAnchor = presentationAnchor
        if let launchError {
            throw launchError
        }
        let session = FakeScaSession(url: url, callback: callback, completion: completion)
        if retainsSessions {
            retained.append(session)
        }
        if waiters.isEmpty {
            // Held only until claimed, so a retention test sees the SDK's reference alone.
            unclaimed.append(session)
        } else {
            waiters.removeFirst().resume(returning: session)
        }
        return session
    }

    /// The next session `DaaSca` launches, in launch order.
    func nextSession() async throws -> FakeScaSession {
        if !unclaimed.isEmpty {
            return unclaimed.removeFirst()
        }
        return await withCheckedContinuation { waiters.append($0) }
    }
}

@MainActor
final class FakeScaSession: ScaSession {
    let url: URL
    let callback: ScaSessionCallback
    private let completion: @MainActor @Sendable (ScaSessionOutcome) -> Void
    private(set) var wasCancelled = false

    init(
        url: URL,
        callback: ScaSessionCallback,
        completion: @escaping @MainActor @Sendable (ScaSessionOutcome) -> Void
    ) {
        self.url = url
        self.callback = callback
        self.completion = completion
    }

    var state: String {
        String(url.absoluteString.split(separator: "&").last?.dropFirst("state=".count) ?? "")
    }

    func complete(kind: String) {
        complete(url: "\(ScaCallbackTests.redirect)#v=1&state=\(state)&kind=\(kind)")
    }

    func complete(url: String) {
        completion(.callback(URL(string: url)!))
    }

    func fail(_ error: DaaScaError) {
        completion(.failed(error))
    }

    /// What `ASWebAuthenticationSession` reports when the user closes the sheet.
    func closeWithoutCallback() {
        completion(SystemScaSessionLauncher.outcome(url: nil, error: ASWebAuthenticationSessionError(.canceledLogin)))
    }

    func cancel() {
        wasCancelled = true
    }
}

@MainActor
final class FakeScaDeadlineScheduler: ScaDeadlineScheduling {
    private(set) var deadlines: [FakeScaDeadline] = []

    func schedule(after seconds: TimeInterval, _ fire: @escaping @MainActor @Sendable () -> Void) -> any ScaDeadline {
        let deadline = FakeScaDeadline(seconds: seconds, fire: fire)
        deadlines.append(deadline)
        return deadline
    }
}

@MainActor
final class FakeScaDeadline: ScaDeadline {
    let seconds: TimeInterval
    private let action: @MainActor @Sendable () -> Void
    private(set) var wasCancelled = false
    /// Set to model the deadline's time passing before its fire has run.
    var hasPassed = false

    init(seconds: TimeInterval, fire: @escaping @MainActor @Sendable () -> Void) {
        self.seconds = seconds
        action = fire
    }

    /// Fires regardless of cancellation, to prove a late fire is harmless.
    func fire() {
        action()
    }

    func cancel() {
        wasCancelled = true
    }
}

/// Stands in for the wait for a key window without waiting in real time. By
/// default the wait ends at once with whatever the lookup now returns.
@MainActor
final class FakeScaAnchorWaiter: ScaAnchorWaiting {
    /// The timeout of each wait the SDK entered, in order.
    private(set) var timeouts: [TimeInterval] = []
    /// Runs inside the wait, before the lookup is queried again: models a
    /// window becoming key (or not) while the SDK waits.
    var duringWait: (@MainActor () -> Void)?
    /// Reported as the time the wait took.
    var elapsed: TimeInterval = 0
    /// Models the calling task being cancelled while it waits.
    var cancelsWait = false
    /// Suspends each wait until `releaseAll()`, so other calls can run while
    /// one is genuinely suspended in the wait.
    var holds = false
    private var held: [CheckedContinuation<Void, Never>] = []

    /// How many waits are suspended right now.
    var heldCount: Int { held.count }

    /// Resumes every suspended wait; each then queries the lookup again.
    func releaseAll() {
        let waiting = held
        held.removeAll()
        waiting.forEach { $0.resume() }
    }

    /// Yields until `count` waits are suspended.
    func untilHeld(_ count: Int) async {
        while held.count < count {
            await Task.yield()
        }
    }

    func waitForAnchor(
        timeout: TimeInterval,
        _ resolve: @MainActor () -> ASPresentationAnchor?
    ) async throws -> ScaAnchorWait {
        timeouts.append(timeout)
        if cancelsWait {
            throw CancellationError()
        }
        if holds {
            await withCheckedContinuation { held.append($0) }
        }
        duringWait?()
        return ScaAnchorWait(anchor: resolve(), elapsed: elapsed)
    }
}

extension ScaSessionOutcome {
    var error: DaaScaError? {
        if case let .failed(error) = self {
            return error
        }
        return nil
    }
}
