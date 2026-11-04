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

// Strong customer authentication through Circle's hosted ceremony page,
// presented in the system authentication browser rather than through a
// platform passkey API.
//
// This is not part of the Owner AuthKey. It generates, stores, and signs with
// no key material: the passkey ceremony runs in the system browser against
// Circle's origin, and this code only opens a URL and reads a redirect.

import AuthenticationServices
import Foundation

/// Presents Circle's hosted SCA ceremony and relays its result.
///
/// The client's part is small: present the ceremony for a `frameToken` your
/// backend obtained from Circle, and relay what comes back to your backend
/// unchanged. The client never holds API credentials and never sees the
/// operation summary — the page reads that from Circle, so what the user
/// approves is drawn by Circle, not by the host app.
///
/// The page runs in `ASWebAuthenticationSession`, never a web view, and the
/// session hands the redirect straight back to this client; the host app does
/// not route the callback URL itself.
///
/// ```swift
/// let sca = DaaSca(configuration: try DaaScaConfiguration(
///     environment: .production,
///     redirectURI: "com.example.app.sca://callback"
/// ))
/// // Your backend opens the challenge, keeps its challengeId against the
/// // transfer, and returns only the frameToken.
/// let frameToken = try await backend.startTransfer(transferId)
/// do {
///     let assertion = try await sca.approve(frameToken: frameToken)
///     try await backend.confirmTransfer(transferId, assertion: assertion)
/// } catch DaaScaError.cancelled {
///     offerRetry() // with a new challenge from your backend
/// }
/// ```
///
/// Hold one `DaaSca` per configuration. Run one ceremony at a time: a new
/// `approve` or `enroll` while a ceremony is open replaces it, so the open
/// call throws `cancelled` and the newest ceremony runs. Disable the control
/// that starts a ceremony until the call returns. Cancelling the calling task
/// cancels the ceremony. A ceremony still open after
/// `configuration.approveTimeout` or `enrollTimeout` is dismissed and throws
/// `expired`.
@MainActor
public final class DaaSca {
    /// Version of the native redirect contract with the ceremony page.
    public nonisolated static let protocolVersion = ScaCallback.protocolVersion

    /// How long the anchor-less overloads wait for a foreground key window
    /// when there is none at the call.
    ///
    /// A system sheet the host app showed just before (a biometric prompt, an
    /// alert) can leave no window key for a few hundred milliseconds after it
    /// dismisses. Two seconds covers that with margin, yet is short enough
    /// that a call made from the background still fails promptly, and small
    /// next to the shortest ceremony deadline (30 s), which the wait counts
    /// against.
    nonisolated static let foregroundWindowWait: TimeInterval = 2

    public nonisolated let configuration: DaaScaConfiguration

    private let launcher: any ScaSessionLaunching
    private let scheduler: any ScaDeadlineScheduling
    private let platformPasskeys: Bool
    /// Replaces the foreground key-window lookup in tests; `nil` uses the
    /// system lookup.
    private let anchorProvider: (@MainActor () -> ASPresentationAnchor?)?
    private let anchorWaiter: any ScaAnchorWaiting
    private var pending: ScaPendingCeremony?
    /// Numbers each `approve` / `enroll` call as it starts. A call that
    /// suspended to wait for a window compares its number on resuming, so an
    /// older call can never replace a ceremony a newer call already opened.
    private var latestCall: UInt64 = 0

    public convenience init(configuration: DaaScaConfiguration) {
        self.init(
            configuration: configuration,
            launcher: SystemScaSessionLauncher(),
            scheduler: SystemScaDeadlineScheduler(),
            platformPasskeys: Self.osSupportsPasskeys,
            anchorWaiter: SystemScaAnchorWaiter()
        )
    }

    init(
        configuration: DaaScaConfiguration,
        launcher: any ScaSessionLaunching,
        scheduler: any ScaDeadlineScheduling,
        platformPasskeys: Bool,
        anchorProvider: (@MainActor () -> ASPresentationAnchor?)? = nil,
        anchorWaiter: any ScaAnchorWaiting
    ) {
        self.configuration = configuration
        self.launcher = launcher
        self.scheduler = scheduler
        self.platformPasskeys = platformPasskeys
        self.anchorProvider = anchorProvider
        self.anchorWaiter = anchorWaiter
    }

    // Passkeys in `ASWebAuthenticationSession` arrived with iOS 16.
    private nonisolated static var osSupportsPasskeys: Bool {
        if #available(iOS 16, macOS 13, *) {
            return true
        }
        return false
    }

    /// What this device can do with this configuration. Cheap; safe to call
    /// before every ceremony.
    public func capabilities() -> DaaScaCapabilities {
        let supported = callback.map(launcher.supports) ?? false
        return DaaScaCapabilities(
            protocolVersion: Self.protocolVersion,
            surface: supported ? .webAuthenticationSession : .none,
            callbackSupported: supported,
            platformPasskeys: platformPasskeys
        )
    }

    /// Runs a step-up ceremony for a challenge `frameToken`.
    ///
    /// Your backend opens a new challenge for every attempt, including a
    /// retry after `cancelled` or `expired`; a `frameToken` is single-use.
    ///
    /// - Parameter presentationAnchor: The window the sheet presents over.
    /// - Returns: The `X-Sca-Assertion` value — the exact JSON text the page
    ///   produced. Send it to your backend unchanged, which re-sends the gated
    ///   request with it and `X-Sca-Challenge-Id`. Do not parse and
    ///   re-serialize it.
    /// - Throws: `DaaScaError`.
    public func approve(frameToken: String, presentationAnchor: ASPresentationAnchor) async throws -> String {
        try await run(.challenge, frameToken: frameToken, presentationAnchor: presentationAnchor, call: beginCall())
    }

    /// Runs a step-up ceremony over the foreground scene's key window.
    ///
    /// The same as `approve(frameToken:presentationAnchor:)`, for callers
    /// such as SwiftUI views that have no window at hand. The sheet presents
    /// over the key window of the first foreground-active scene. With several
    /// windows open (iPad, Mac), pass the anchor explicitly instead.
    ///
    /// If no scene has a key window yet — as right after a system sheet such
    /// as a biometric prompt dismisses — the call waits up to two seconds for
    /// one before opening the ceremony. The wait counts against
    /// `configuration.approveTimeout`. Nothing is presented and the
    /// `frameToken` is not used until a window is found. If another `approve`
    /// or `enroll` call starts while this one waits, the newer call wins: this
    /// one ends with `cancelled` and leaves the newer ceremony alone.
    ///
    /// - Throws: `DaaScaError.sessionUnavailable` if no foreground-active
    ///   scene has a key window within that wait; `cancelled` if the task is
    ///   cancelled, or a newer call starts, while waiting; otherwise as the
    ///   anchored overload.
    @available(iOSApplicationExtension, unavailable)
    @available(macCatalystApplicationExtension, unavailable)
    @available(macOSApplicationExtension, unavailable)
    public func approve(frameToken: String) async throws -> String {
        let call = beginCall()
        let wait = try await foregroundAnchor()
        return try await run(
            .challenge,
            frameToken: frameToken,
            presentationAnchor: wait.anchor,
            waited: wait.elapsed,
            call: call
        )
    }

    /// Runs an enrollment ceremony for a registration `frameToken`.
    ///
    /// Your backend opens a new registration for every attempt, including a
    /// retry after `cancelled` or `expired`; a `frameToken` is single-use.
    ///
    /// - Parameter presentationAnchor: The window the sheet presents over.
    /// - Returns: The registration response JSON, exactly as the page
    ///   produced it. Send it to your backend unchanged, which passes it to
    ///   Circle with the registration ID to complete enrollment.
    /// - Throws: `DaaScaError`.
    public func enroll(frameToken: String, presentationAnchor: ASPresentationAnchor) async throws -> String {
        try await run(.registration, frameToken: frameToken, presentationAnchor: presentationAnchor, call: beginCall())
    }

    /// Runs an enrollment ceremony over the foreground scene's key window.
    ///
    /// The same as `enroll(frameToken:presentationAnchor:)`, presenting over
    /// the key window of the first foreground-active scene, waiting briefly
    /// for one as `approve(frameToken:)` does; the wait counts against
    /// `configuration.enrollTimeout`, and a newer call started meanwhile wins.
    ///
    /// - Throws: `DaaScaError.sessionUnavailable` if no foreground-active
    ///   scene has a key window within that wait; `cancelled` if the task is
    ///   cancelled, or a newer call starts, while waiting; otherwise as the
    ///   anchored overload.
    @available(iOSApplicationExtension, unavailable)
    @available(macCatalystApplicationExtension, unavailable)
    @available(macOSApplicationExtension, unavailable)
    public func enroll(frameToken: String) async throws -> String {
        let call = beginCall()
        let wait = try await foregroundAnchor()
        return try await run(
            .registration,
            frameToken: frameToken,
            presentationAnchor: wait.anchor,
            waited: wait.elapsed,
            call: call
        )
    }

    private func beginCall() -> UInt64 {
        latestCall &+= 1
        return latestCall
    }

    @available(iOSApplicationExtension, unavailable)
    @available(macCatalystApplicationExtension, unavailable)
    @available(macOSApplicationExtension, unavailable)
    private func foregroundAnchor() async throws -> (anchor: ASPresentationAnchor, elapsed: TimeInterval) {
        let resolve: @MainActor () -> ASPresentationAnchor? = anchorProvider ?? { ScaForegroundWindow.keyWindow() }
        if let anchor = resolve() {
            return (anchor, 0)
        }
        let wait: ScaAnchorWait
        do {
            wait = try await anchorWaiter.waitForAnchor(timeout: Self.foregroundWindowWait, resolve)
        } catch {
            throw DaaScaError.cancelled
        }
        guard let anchor = wait.anchor else {
            throw DaaScaError.sessionUnavailable(message: "No foreground scene has a key window to present from")
        }
        return (anchor, wait.elapsed)
    }

    private var callback: ScaSessionCallback? {
        ScaSessionCallback(redirectURI: configuration.redirectURI)
    }

    private func run(
        _ kind: ScaCeremonyKind,
        frameToken: String,
        presentationAnchor: ASPresentationAnchor,
        waited: TimeInterval = 0,
        call: UInt64
    ) async throws -> String {
        guard let callback, launcher.supports(callback) else {
            throw DaaScaError.sessionUnavailable(
                message: "This OS cannot deliver the configured callback to the session"
            )
        }
        let request = try makeRequest(kind, frameToken: frameToken)
        guard let url = URL(string: request.ceremonyURLString) else {
            throw DaaScaError.protocol(message: "Could not build the ceremony URL")
        }

        // `onCancel` below can only schedule its finish onto the main actor,
        // which this synchronous path holds until the sheet is presented. So a
        // call whose task is already cancelled must stop here: before it opens
        // a sheet only to dismiss it, and before it replaces a ceremony another
        // caller has open.
        guard !Task.isCancelled else {
            throw DaaScaError.cancelled
        }
        // A call that waited for a window and was overtaken by a newer call
        // meanwhile must not replace what the newer call opened: the newest
        // call wins, as it does when neither waits.
        guard call == latestCall else {
            throw DaaScaError.cancelled
        }
        pending?.finish(.failure(.cancelled))
        let ceremony = ScaPendingCeremony()
        pending = ceremony
        defer {
            if pending === ceremony {
                pending = nil
            }
        }

        return try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                ceremony.attach(continuation)
                guard !ceremony.isFinished else {
                    return
                }
                // Backstop for a cancellation that lands after the entry check.
                guard !Task.isCancelled else {
                    ceremony.finish(.failure(.cancelled))
                    return
                }
                present(
                    ceremony,
                    request: request,
                    url: url,
                    callback: callback,
                    anchor: ScaResolvedAnchor(anchor: presentationAnchor, waited: waited)
                )
            }
        } onCancel: {
            Task { @MainActor in ceremony.finish(.failure(.cancelled)) }
        }
    }

    /// Presents the session for `ceremony` and arms its deadline. A launch
    /// that fails finishes `ceremony` at once; otherwise the session's
    /// outcome, a replacement, cancellation, or the deadline does.
    ///
    /// Any time spent waiting for the anchor is taken off the deadline, so
    /// the call as a whole never outlasts it.
    private func present(
        _ ceremony: ScaPendingCeremony,
        request: ScaCeremonyRequest,
        url: URL,
        callback: ScaSessionCallback,
        anchor: ScaResolvedAnchor
    ) {
        let session: any ScaSession
        do {
            session = try launcher.launch(url: url, callback: callback, presentationAnchor: anchor.anchor) { outcome in
                // The deadline's fire and this completion both hop to the main
                // actor in no fixed order, so an outcome can arrive after the
                // deadline but run before its fire. Past the deadline, nothing
                // the session reports is relayed.
                if ceremony.deadline?.hasPassed == true {
                    ceremony.finish(.failure(.expired(message: ScaCallback.deadlineMessage)), sessionEnded: true)
                    return
                }
                switch outcome {
                case let .callback(url):
                    ceremony.finish(ScaCallback.parse(url.absoluteString, for: request), sessionEnded: true)
                case let .failed(error):
                    ceremony.finish(.failure(error), sessionEnded: true)
                }
            }
        } catch {
            ceremony.finish(.failure(error as? DaaScaError ?? .sessionUnavailable(message: nil)))
            return
        }
        // A launcher may report the end before returning; then there is
        // nothing left to hold or time out.
        guard !ceremony.isFinished else {
            return
        }
        ceremony.session = session
        // Counted from presentation, less any wait for a window. The page
        // cannot redirect a failure from before it loads the ceremony, so this
        // is what ends a sheet stuck on one.
        let remaining = Swift.max(configuration.timeout(for: request.kind) - Swift.max(anchor.waited, 0), 0)
        ceremony.deadline = scheduler.schedule(after: remaining) {
            ceremony.finish(.failure(.expired(message: ScaCallback.deadlineMessage)))
        }
    }

    private func makeRequest(_ kind: ScaCeremonyKind, frameToken: String) throws -> ScaCeremonyRequest {
        // A blank or malformed token cannot name a ceremony; it is a caller
        // bug, so fail before opening a sheet that can only show an error.
        guard !frameToken.allSatisfy(\.isWhitespace) else {
            throw DaaScaError.protocol(message: "frameToken must not be blank")
        }
        guard ScaCeremonyRequest.isValidFrameToken(frameToken) else {
            throw DaaScaError.protocol(message: "frameToken is malformed")
        }
        let state: String
        do {
            state = try ScaCeremonyRequest.newState()
        } catch {
            throw DaaScaError.sessionUnavailable(message: "The platform CSPRNG is unavailable")
        }
        return ScaCeremonyRequest(
            kind: kind,
            circleOrigin: configuration.circleOrigin,
            redirectURI: configuration.redirectURI,
            frameToken: frameToken,
            state: state
        )
    }
}

/// One open ceremony. Resumes its caller exactly once, whichever of the
/// session's completion, a replacing call, task cancellation, or the deadline
/// comes first, and releases the session and the deadline when it does.
@MainActor
private final class ScaPendingCeremony {
    var session: (any ScaSession)?
    var deadline: (any ScaDeadline)?
    private var continuation: CheckedContinuation<String, Error>?
    private var result: Result<String, DaaScaError>?

    var isFinished: Bool { result != nil }

    func attach(_ continuation: CheckedContinuation<String, Error>) {
        if let result {
            continuation.resume(with: result)
        } else {
            self.continuation = continuation
        }
    }

    /// - Parameter sessionEnded: Whether the session itself reported the end.
    ///   Otherwise it is still open — replaced, its task cancelled, or timed
    ///   out — and is cancelled here, which dismisses its sheet.
    func finish(_ result: Result<String, DaaScaError>, sessionEnded: Bool = false) {
        guard self.result == nil else {
            return
        }
        self.result = result
        if !sessionEnded {
            session?.cancel()
        }
        session = nil
        deadline?.cancel()
        deadline = nil
        continuation?.resume(with: result)
        continuation = nil
    }
}
