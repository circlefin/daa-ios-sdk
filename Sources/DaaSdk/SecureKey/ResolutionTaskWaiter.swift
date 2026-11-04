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

// NSLock lets one caller stop waiting without cancelling the shared resolution.
final class ResolutionTaskWaiter<Output: Sendable>: @unchecked Sendable {
    private let lock = NSLock()
    private var continuation: CheckedContinuation<Output, Error>?
    private var cancellationRequested = false
    private var isCompleted = false

    func install(_ continuation: CheckedContinuation<Output, Error>) -> Bool {
        lock.lock()
        if cancellationRequested {
            isCompleted = true
            lock.unlock()
            continuation.resume(throwing: CancellationError())
            return false
        }
        self.continuation = continuation
        lock.unlock()
        return true
    }

    func cancel() {
        var pendingContinuation: CheckedContinuation<Output, Error>?
        lock.lock()
        cancellationRequested = true
        if !isCompleted {
            isCompleted = true
            pendingContinuation = continuation
            continuation = nil
        }
        lock.unlock()
        pendingContinuation?.resume(throwing: CancellationError())
    }

    func complete(with result: Result<Output, Error>) {
        lock.lock()
        guard !isCompleted, let pendingContinuation = continuation else {
            lock.unlock()
            return
        }
        isCompleted = true
        continuation = nil
        lock.unlock()
        pendingContinuation.resume(with: result)
    }
}
