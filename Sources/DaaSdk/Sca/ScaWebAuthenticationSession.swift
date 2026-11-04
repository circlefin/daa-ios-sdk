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

// The one place the SCA client touches `ASWebAuthenticationSession`.
//
// It sits behind `ScaSessionLaunching` so `DaaSca`'s lifecycle — one result
// per call, replacement, task cancellation, retention — is testable on the
// host without presenting a sheet.
//
// Not `SFSafariViewController`, which cannot hand a callback back to the app,
// and never `WKWebView`: the host app would become the page's script host and
// could read or rewrite what the user approves.

import AuthenticationServices
import Foundation
#if canImport(UIKit)
import UIKit
#elseif canImport(AppKit)
import AppKit
#endif

/// How the session recognizes the page's redirect as the end of the ceremony.
enum ScaSessionCallback: Equatable, Sendable {
    case customScheme(String)
    case https(host: String, path: String)

    init?(redirectURI: String) {
        guard let components = URLComponents(string: redirectURI), let scheme = components.scheme else {
            return nil
        }
        guard scheme == "https" else {
            self = .customScheme(scheme)
            return
        }
        guard let host = components.host, !host.isEmpty else {
            return nil
        }
        self = .https(host: host, path: components.path.isEmpty ? "/" : components.path)
    }
}

/// How one presented session ended.
enum ScaSessionOutcome: Sendable {
    case callback(URL)
    case failed(DaaScaError)
}

/// A presented session the SDK keeps alive until it ends.
@MainActor
protocol ScaSession: AnyObject {
    func cancel()
}

@MainActor
protocol ScaSessionLaunching {
    func supports(_ callback: ScaSessionCallback) -> Bool

    /// Present `url`. `completion` runs at most once, on the main actor.
    ///
    /// - Throws: `DaaScaError.sessionUnavailable` if the session cannot be
    ///   started.
    func launch(
        url: URL,
        callback: ScaSessionCallback,
        presentationAnchor: ASPresentationAnchor,
        completion: @escaping @MainActor @Sendable (ScaSessionOutcome) -> Void
    ) throws -> any ScaSession
}

@MainActor
struct SystemScaSessionLauncher: ScaSessionLaunching {
    /// Whether `ASWebAuthenticationSession.Callback.https(host:path:)` exists
    /// on this OS and in this build. The one place the iOS 17.4 rule lives:
    /// configuration validation and `supports` both read it.
    nonisolated static var isHTTPSCallbackAvailable: Bool {
        #if compiler(>=5.10)
        if #available(iOS 17.4, macOS 14.4, *) {
            return true
        }
        #endif
        return false
    }

    func supports(_ callback: ScaSessionCallback) -> Bool {
        switch callback {
        case .customScheme:
            return true
        case .https:
            return Self.isHTTPSCallbackAvailable
        }
    }

    func launch(
        url: URL,
        callback: ScaSessionCallback,
        presentationAnchor: ASPresentationAnchor,
        completion: @escaping @MainActor @Sendable (ScaSessionOutcome) -> Void
    ) throws -> any ScaSession {
        let handler: @Sendable (URL?, Error?) -> Void = { url, error in
            let outcome = Self.outcome(url: url, error: error)
            Task { @MainActor in completion(outcome) }
        }
        guard let session = Self.makeSession(url: url, callback: callback, handler: handler) else {
            throw DaaScaError.sessionUnavailable(message: "This OS cannot deliver an https callback to the session")
        }
        let context = ScaPresentationContext(anchor: presentationAnchor)
        session.presentationContextProvider = context
        // Ephemeral. A shared session makes iOS show "<App> wants to use
        // <domain> to Sign In" before the page even loads, which reads as a
        // login prompt for what is an approval, and it would let the page see
        // Safari's cookies for Circle's origin. Passkeys are
        // unaffected: they come from iCloud Keychain or the credential
        // provider, not from browser storage, and the ceremony carries its
        // own capability token, so there is no cookie state it needs.
        session.prefersEphemeralWebBrowserSession = true
        guard session.canStart, session.start() else {
            throw DaaScaError.sessionUnavailable(message: "The authentication session could not be started")
        }
        return SystemScaSession(session: session, context: context)
    }

    private static func makeSession(
        url: URL,
        callback: ScaSessionCallback,
        handler: @escaping @Sendable (URL?, Error?) -> Void
    ) -> ASWebAuthenticationSession? {
        #if compiler(>=5.10)
        if #available(iOS 17.4, macOS 14.4, *) {
            switch callback {
            case let .customScheme(scheme):
                return ASWebAuthenticationSession(url: url, callback: .customScheme(scheme), completionHandler: handler)
            case let .https(host, path):
                return ASWebAuthenticationSession(
                    url: url,
                    callback: .https(host: host, path: path),
                    completionHandler: handler
                )
            }
        }
        #endif
        guard case let .customScheme(scheme) = callback else {
            return nil
        }
        return ASWebAuthenticationSession(url: url, callbackURLScheme: scheme, completionHandler: handler)
    }

    nonisolated static func outcome(url: URL?, error: Error?) -> ScaSessionOutcome {
        if let url {
            return .callback(url)
        }
        guard let error = error as? ASWebAuthenticationSessionError else {
            // Not the session's own error domain. The error's description is
            // not relayed: it is not ours to promise it names no URL.
            return .failed(.sessionUnavailable(message: "The authentication session failed"))
        }
        switch error.code {
        // The user closed the sheet with no callback; iOS reports it
        // explicitly. This is also how an expired or consumed token ends: the
        // page cannot redirect it and asks the user to close the window, so
        // it is `cancelled`, not an error of its own.
        case .canceledLogin:
            return .failed(.cancelled)
        case .presentationContextNotProvided, .presentationContextInvalid:
            return .failed(.sessionUnavailable(message: "The session had no usable presentation anchor"))
        @unknown default:
            return .failed(
                .sessionUnavailable(message: "The authentication session failed (code \(error.code.rawValue))")
            )
        }
    }
}

/// Holds the session and its presentation context for the ceremony's
/// lifetime. `ASWebAuthenticationSession` cancels silently when released, and
/// `presentationContextProvider` is weak.
@MainActor
private final class SystemScaSession: ScaSession {
    private let session: ASWebAuthenticationSession
    private let context: ScaPresentationContext

    init(session: ASWebAuthenticationSession, context: ScaPresentationContext) {
        self.session = session
        self.context = context
    }

    func cancel() {
        session.cancel()
    }
}

private final class ScaPresentationContext: NSObject, ASWebAuthenticationPresentationContextProviding {
    private let anchor: ASPresentationAnchor

    init(anchor: ASPresentationAnchor) {
        self.anchor = anchor
    }

    func presentationAnchor(for session: ASWebAuthenticationSession) -> ASPresentationAnchor {
        anchor
    }
}

/// The window `DaaSca.approve(frameToken:)` and `enroll(frameToken:)` present
/// over when the caller passes none.
@MainActor
enum ScaForegroundWindow {
    /// The key window of the first foreground-active scene, or `nil` if there
    /// is none (the app is in the background, or no window is key yet).
    @available(iOSApplicationExtension, unavailable)
    @available(macCatalystApplicationExtension, unavailable)
    @available(macOSApplicationExtension, unavailable)
    static func keyWindow() -> ASPresentationAnchor? {
        #if canImport(UIKit)
        return UIApplication.shared.connectedScenes
            .lazy
            .filter { $0.activationState == .foregroundActive }
            .compactMap { ($0 as? UIWindowScene)?.keyWindow }
            .first
        #elseif canImport(AppKit)
        return NSApplication.shared.keyWindow
        #else
        return nil
        #endif
    }
}
