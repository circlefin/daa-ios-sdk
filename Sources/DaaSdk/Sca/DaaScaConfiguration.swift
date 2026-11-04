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

/// Why a `DaaScaConfiguration` was refused.
public enum DaaScaConfigurationError: Error, Equatable, Sendable {
    /// Never thrown: `DaaEnvironment` has only `.sandbox` and `.production`,
    /// and the ceremony runs in both. Deprecated, and kept for source
    /// compatibility with code that matches on it.
    @available(*, deprecated, message: "Never thrown; the ceremony runs in every DaaEnvironment.")
    case unsupportedEnvironment

    /// `circleOrigin` is a testing override and cannot be set for
    /// `.production`.
    case circleOriginOverrideNotAllowed

    /// `circleOrigin` is not a bare, lowercase `https` origin on `circle.com`
    /// or one of its subdomains.
    case invalidCircleOrigin

    /// `redirectURI` is not a lowercase `https` URI or custom scheme, has a
    /// fragment, credentials, or characters outside RFC 3986, is longer than
    /// 2048 characters, or is an `https` URI with a port. Also refused is
    /// anything a browser would rewrite when it navigates to the URI, since
    /// the callback would then not match it: a `.` or `..` path segment
    /// (including `%2e` forms), and, for `https`, a `'` in the query (write
    /// `%27`) or a host that is uppercase, an IP address, or contains `%`.
    case invalidRedirectURI

    /// `redirectURI` is `https`, which `ASWebAuthenticationSession` can only
    /// deliver from iOS 17.4 (`Callback.https(host:path:)`). Use a custom
    /// scheme on older versions; both URIs must be registered with Circle.
    case httpsCallbackUnavailable

    /// `approveTimeout` or `enrollTimeout` is not finite or is outside
    /// `DaaScaConfiguration.minimumCeremonyTimeout` ...
    /// `DaaScaConfiguration.maximumCeremonyTimeout` (30 s to one hour).
    case invalidCeremonyTimeout
}

/// Where the SCA ceremony runs, where its result comes back, and how long the
/// SDK waits for it.
///
/// Validated at construction, so a misconfiguration fails when the host app
/// builds its client rather than halfway through a ceremony the user has
/// already started.
public struct DaaScaConfiguration: Equatable, Sendable {
    /// Five minutes: the lifetime of a step-up challenge token. The token was
    /// minted before the sheet opened, so by this deadline the challenge can
    /// no longer succeed.
    public static let defaultApproveTimeout: TimeInterval = 300

    /// Ten minutes: the lifetime of an enrollment token, for the same reason.
    public static let defaultEnrollTimeout: TimeInterval = 600

    /// Shorter deadlines would cut off users still reading the summary or
    /// finding their passkey.
    public static let minimumCeremonyTimeout: TimeInterval = 30

    /// One hour. Far above the challenge and enrollment token lifetimes (five
    /// and ten minutes), so a longer deadline could only keep a sheet open
    /// on a token that can no longer succeed.
    public static let maximumCeremonyTimeout: TimeInterval = 3600

    /// Selects Circle's ceremony origin: `.sandbox` or `.production`. The
    /// origin must equal the one the server validates
    /// `clientDataJSON.origin` against, so it is not free-form.
    public let environment: DaaEnvironment

    /// The callback the ceremony page navigates to on completion.
    ///
    /// It must be registered with Circle for the partner during onboarding.
    /// The partner backend sends the same URI as `redirectUri` when it opens
    /// each ceremony, and the API refuses an unregistered one with
    /// `420068 SCA_REDIRECT_URI_NOT_ALLOWED` before any `frameToken` exists.
    /// Matching is by exact string, so this value, the backend's, and the
    /// registered URI must be identical. The page takes its return target
    /// from the server, never from this value.
    ///
    /// Use a custom scheme by default: it works on every supported iOS
    /// version and the session catches it in-process, so the app needs no
    /// `CFBundleURLTypes` entry or URL handler for it. An `https` callback
    /// on your app's own domain (requires the `webcredentials`
    /// Associated Domain, not `applinks`, plus an
    /// `apple-app-site-association` file on that domain) needs iOS 17.4; on
    /// older versions it is refused here with `httpsCallbackUnavailable`.
    public let redirectURI: String

    /// The ceremony origin, resolved from `environment` unless overridden.
    public let circleOrigin: String

    /// How long, in seconds, an `approve` ceremony may stay open before the
    /// SDK dismisses it and throws `DaaScaError.expired`.
    ///
    /// The page cannot redirect a failure that happens before it has loaded
    /// the ceremony (network, an unreadable frame), so without a deadline a
    /// sheet stuck on such a failure would wait for the user forever. The SDK
    /// cannot observe page load, so this is one deadline for the whole
    /// ceremony, counted from presentation. Between
    /// `minimumCeremonyTimeout` (30 s) and `maximumCeremonyTimeout` (one
    /// hour), inclusive.
    public let approveTimeout: TimeInterval

    /// How long, in seconds, an `enroll` ceremony may stay open before the
    /// SDK dismisses it and throws `DaaScaError.expired`. Same range as
    /// `approveTimeout`.
    public let enrollTimeout: TimeInterval

    /// - Parameters:
    ///   - redirectURI: See `redirectURI`.
    ///   - circleOrigin: Override for the ceremony origin, for testing
    ///     against a non-production Circle host. Accepted only with
    ///     `.sandbox`, and only as a bare `https` origin on `circle.com` or a
    ///     subdomain. Refused for `.production`, so an override left in a
    ///     debug configuration fails when the configuration is built instead
    ///     of sending production ceremonies to another origin.
    ///   - approveTimeout: See `approveTimeout`. From
    ///     `minimumCeremonyTimeout` (30 s) to `maximumCeremonyTimeout`
    ///     (one hour), inclusive.
    ///   - enrollTimeout: See `enrollTimeout`. The same range.
    /// - Throws: `DaaScaConfigurationError`.
    public init(
        environment: DaaEnvironment,
        redirectURI: String,
        circleOrigin: String? = nil,
        approveTimeout: TimeInterval = DaaScaConfiguration.defaultApproveTimeout,
        enrollTimeout: TimeInterval = DaaScaConfiguration.defaultEnrollTimeout
    ) throws {
        try self.init(
            environment: environment,
            redirectURI: redirectURI,
            circleOrigin: circleOrigin,
            approveTimeout: approveTimeout,
            enrollTimeout: enrollTimeout,
            httpsCallbackAvailable: SystemScaSessionLauncher.isHTTPSCallbackAvailable
        )
    }

    /// `httpsCallbackAvailable` is injected so the iOS 17.4 rule is testable
    /// on any host.
    init(
        environment: DaaEnvironment,
        redirectURI: String,
        circleOrigin: String?,
        approveTimeout: TimeInterval,
        enrollTimeout: TimeInterval,
        httpsCallbackAvailable: Bool
    ) throws {
        if environment == .production, circleOrigin != nil {
            throw DaaScaConfigurationError.circleOriginOverrideNotAllowed
        }
        let origin = circleOrigin ?? ScaConfigRules.origin(for: environment)
        guard ScaConfigRules.isValidOrigin(origin) else {
            throw DaaScaConfigurationError.invalidCircleOrigin
        }
        guard ScaConfigRules.isValidRedirectURI(redirectURI),
              let callback = ScaSessionCallback(redirectURI: redirectURI)
        else {
            throw DaaScaConfigurationError.invalidRedirectURI
        }
        if case .https = callback, !httpsCallbackAvailable {
            throw DaaScaConfigurationError.httpsCallbackUnavailable
        }
        guard Self.isValidTimeout(approveTimeout), Self.isValidTimeout(enrollTimeout) else {
            throw DaaScaConfigurationError.invalidCeremonyTimeout
        }
        self.environment = environment
        self.redirectURI = redirectURI
        self.circleOrigin = origin
        self.approveTimeout = approveTimeout
        self.enrollTimeout = enrollTimeout
    }

    /// The deadline for one ceremony of `kind`.
    func timeout(for kind: ScaCeremonyKind) -> TimeInterval {
        switch kind {
        case .challenge: return approveTimeout
        case .registration: return enrollTimeout
        }
    }

    private static func isValidTimeout(_ timeout: TimeInterval) -> Bool {
        timeout.isFinite && timeout >= minimumCeremonyTimeout && timeout <= maximumCeremonyTimeout
    }
}
