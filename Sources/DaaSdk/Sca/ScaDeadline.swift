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

// The ceremony deadline, behind a protocol so `DaaSca`'s timeout is testable
// without waiting for it.

import Foundation

/// A scheduled deadline that can be withdrawn before it fires.
@MainActor
protocol ScaDeadline: AnyObject {
    /// Whether the deadline's time has come, whether or not `fire` has run
    /// yet. The fire is a main-actor task, so a session callback queued
    /// alongside it can run first.
    var hasPassed: Bool { get }

    func cancel()
}

@MainActor
protocol ScaDeadlineScheduling {
    /// Run `fire` on the main actor after `seconds`, unless the returned
    /// deadline is cancelled first.
    func schedule(after seconds: TimeInterval, _ fire: @escaping @MainActor @Sendable () -> Void) -> any ScaDeadline
}

@MainActor
struct SystemScaDeadlineScheduler: ScaDeadlineScheduling {
    /// Monotonic nanoseconds. Injectable so a test can stand in for a task
    /// that starts late.
    var clock: @Sendable () -> UInt64 = { Self.now() }

    func schedule(after seconds: TimeInterval, _ fire: @escaping @MainActor @Sendable () -> Void) -> any ScaDeadline {
        let clock = clock
        let (sum, overflow) = clock().addingReportingOverflow(Self.nanoseconds(seconds))
        let expiry = overflow ? UInt64.max : sum
        return SystemScaDeadline(expiry: expiry, clock: clock, task: Task { @MainActor in
            // Sleep only for what is left of the absolute expiry, re-reading
            // the clock each time, so a task that starts late (a busy main
            // actor) or wakes early still fires at the configured moment, and
            // fires at once if that moment has already passed. A cancelled
            // sleep throws, so a withdrawn deadline never fires.
            while case let now = clock(), now < expiry {
                guard (try? await Task.sleep(nanoseconds: expiry - now)) != nil else {
                    return
                }
            }
            guard !Task.isCancelled else {
                return
            }
            fire()
        })
    }

    /// `seconds` as a sleep duration that cannot trap. The configuration
    /// already bounds it to `minimumCeremonyTimeout ... maximumCeremonyTimeout`;
    /// this clamps again so a direct caller cannot overflow `UInt64` with a
    /// huge, infinite, negative, or NaN value.
    nonisolated static func nanoseconds(_ seconds: TimeInterval) -> UInt64 {
        guard !seconds.isNaN else {
            return 0
        }
        let bounded = Swift.min(Swift.max(seconds, 0), DaaScaConfiguration.maximumCeremonyTimeout)
        return UInt64(bounded * 1_000_000_000)
    }

    /// Monotonic nanoseconds, counting time the device spends asleep.
    nonisolated static func now() -> UInt64 {
        clock_gettime_nsec_np(CLOCK_MONOTONIC)
    }
}

@MainActor
private final class SystemScaDeadline: ScaDeadline {
    private let expiry: UInt64
    private let clock: @Sendable () -> UInt64
    private let task: Task<Void, Never>

    init(expiry: UInt64, clock: @escaping @Sendable () -> UInt64, task: Task<Void, Never>) {
        self.expiry = expiry
        self.clock = clock
        self.task = task
    }

    var hasPassed: Bool {
        clock() >= expiry
    }

    func cancel() {
        task.cancel()
    }
}
