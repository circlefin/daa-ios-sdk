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

// The short wait the anchor-less `approve(frameToken:)` / `enroll(frameToken:)`
// overloads allow for a key window, behind a protocol so `DaaSca` is testable
// without waiting in real time.
//
// Right after a system sheet the host app presented (a biometric prompt, an
// alert, a permission request) dismisses, iOS can take a moment to make the
// app's window key again and to move its scene back to `foregroundActive`.
// A call made in that gap finds no key window. Failing it at once would make
// every integrator that does anything modal before a ceremony retry on its own.

import AuthenticationServices
import Foundation

/// What a wait for a presentation anchor produced.
struct ScaAnchorWait {
    /// The anchor that became available, or `nil` if none did in time.
    let anchor: ASPresentationAnchor?

    /// Seconds spent waiting, counted against the ceremony deadline.
    let elapsed: TimeInterval
}

/// The anchor a ceremony presents over, and the seconds spent waiting for it.
struct ScaResolvedAnchor {
    let anchor: ASPresentationAnchor
    let waited: TimeInterval
}

@MainActor
protocol ScaAnchorWaiting {
    /// Re-query `resolve` until it returns an anchor or `timeout` seconds
    /// pass. The caller has already queried once and found none.
    ///
    /// - Throws: `CancellationError` if the calling task is cancelled while
    ///   waiting.
    func waitForAnchor(
        timeout: TimeInterval,
        _ resolve: @MainActor () -> ASPresentationAnchor?
    ) async throws -> ScaAnchorWait
}

/// Polls on the main actor rather than observing `didBecomeKey` /
/// `didActivate` notifications: the window becoming key and the scene becoming
/// `foregroundActive` are separate events in no fixed order, so a notification
/// alone cannot say the lookup will now succeed, and the lookup would have to
/// be re-run on a timer anyway. One lookup per interval for at most the
/// timeout is negligible work, and the main actor is free between lookups.
@MainActor
struct SystemScaAnchorWaiter: ScaAnchorWaiting {
    /// How often the lookup is re-run while waiting. Small next to the time a
    /// system sheet takes to dismiss, so the ceremony opens with no visible
    /// delay once a window is key.
    nonisolated static let defaultPollInterval: TimeInterval = 0.05

    var pollInterval: TimeInterval = Self.defaultPollInterval

    /// Monotonic nanoseconds.
    var clock: @Sendable () -> UInt64 = { SystemScaDeadlineScheduler.now() }

    func waitForAnchor(
        timeout: TimeInterval,
        _ resolve: @MainActor () -> ASPresentationAnchor?
    ) async throws -> ScaAnchorWait {
        let start = clock()
        let (sum, overflow) = start.addingReportingOverflow(SystemScaDeadlineScheduler.nanoseconds(timeout))
        let expiry = overflow ? UInt64.max : sum
        let interval = Swift.max(SystemScaDeadlineScheduler.nanoseconds(pollInterval), 1)
        // Sleep only for what is left of the absolute expiry, re-reading the
        // clock each time, so a late wake-up cannot extend the wait.
        while case let now = clock(), now < expiry {
            try await Task.sleep(nanoseconds: Swift.min(expiry - now, interval))
            // A late wake-up can land past the expiry: re-check it, and
            // cancellation, before accepting a window, so a ceremony never
            // opens after the wait was due to give up.
            try Task.checkCancellation()
            guard clock() < expiry else {
                break
            }
            if let anchor = resolve() {
                return ScaAnchorWait(anchor: anchor, elapsed: Self.seconds(since: start, clock))
            }
        }
        return ScaAnchorWait(anchor: nil, elapsed: Self.seconds(since: start, clock))
    }

    private static func seconds(since start: UInt64, _ clock: @Sendable () -> UInt64) -> TimeInterval {
        let now = clock()
        return now > start ? TimeInterval(now - start) / 1_000_000_000 : 0
    }
}
