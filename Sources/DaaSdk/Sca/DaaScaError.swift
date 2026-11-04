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

/// Why an SCA ceremony did not complete.
///
/// Two groups of cases:
///
/// - **Reported by the ceremony page.** `cancelled`, `expired`, `unsupported`
///   and `alreadyEnrolled` are exactly the codes the page can redirect with
///   (`Cancelled | Expired | Unsupported | AlreadyEnrolled`). `cancelled` is
///   also what a sheet closed with no callback becomes.
/// - **Detected by this SDK.** `stateMismatch`, `sessionUnavailable` and
///   `protocol` never come from the page; they describe something the SDK
///   saw on the device. A ceremony still open at its deadline is also
///   reported as `expired`.
///
/// The associated message is diagnostic text for logs, not for display; it
/// never contains the ceremony token, the correlation state, or a response.
/// `errorDescription` (from `LocalizedError`) is neutral, developer-facing
/// English for logs and crash reports. It is not localized: write your own
/// user-facing copy for each case.
///
/// `cancelled` is a normal outcome to offer a retry for, not a failure to
/// report: `catch DaaScaError.cancelled` before handling the rest.
///
/// There is no "not enrolled" case: the page has no such code. Have your
/// backend list the user's passkeys before it opens a challenge, and call
/// `enroll` instead of `approve` when there is no active one.
public enum DaaScaError: Error, Equatable, Sendable {
    /// The user declined on the page, or closed the sheet before the page
    /// redirected back, or the call was replaced by a newer `approve` or
    /// `enroll`, or its task was cancelled.
    ///
    /// A closed sheet includes the page's "close this window and return to
    /// the app" screen, which it shows when the token was already used or had
    /// expired and so it never learned where to redirect.
    ///
    /// What to do: offer a retry. Your backend opens a new challenge or
    /// registration, stores its new `challengeId` or `registrationId`, and
    /// returns the new `frameToken`. Never reuse a `frameToken`.
    case cancelled

    /// The ceremony token was consumed or passed its lifetime.
    ///
    /// Either the page reported it, or the ceremony was still open at
    /// `DaaScaConfiguration.approveTimeout` / `enrollTimeout` and the SDK
    /// dismissed the sheet. The default deadlines equal the token lifetimes,
    /// so by then the token has expired either way, and the remedy is the
    /// same.
    ///
    /// What to do: retry once. Your backend opens a new challenge or
    /// registration, stores its new `challengeId` or `registrationId`, and
    /// returns the new `frameToken`.
    case expired(message: String?)

    /// The page reported the browser has no usable authenticator.
    ///
    /// What to do: offer your non-passkey fallback.
    case unsupported(message: String?)

    /// The page reported a passkey is already enrolled for this client entity
    /// (enrollment only).
    ///
    /// What to do: treat the user as enrolled and use `approve`.
    case alreadyEnrolled(message: String?)

    /// The callback did not carry the `state` this ceremony was opened with,
    /// or carried none. It is refused rather than relayed.
    ///
    /// What to do: treat it as an integration bug and report it; nothing
    /// was relayed.
    case stateMismatch

    /// The sheet could not be shown: the OS cannot deliver the configured
    /// callback, the session would not start, the presentation anchor was
    /// unusable or no foreground window was found, or the platform CSPRNG
    /// failed. Nothing reached the page.
    ///
    /// What to do: treat it as an integration or configuration bug; check
    /// the callback setup and the window you present from.
    case sessionUnavailable(message: String?)

    /// The call or the callback did not follow the ceremony contract: a blank
    /// token, a callback for another target or version, a malformed
    /// fragment or payload, or an error code outside the page's set.
    ///
    /// What to do: treat it as an integration bug, not a user action;
    /// retrying will not help. Update the SDK and contact Circle if it
    /// persists.
    case `protocol`(message: String?)
}

extension DaaScaError: LocalizedError {
    /// A fixed, developer-facing English description of the case, for logs
    /// and crash reports. Not localized and not meant for end users; host
    /// apps write and localize their own user-facing copy. It never includes
    /// the associated diagnostic message.
    public var errorDescription: String? {
        switch self {
        case .cancelled:
            return "The SCA ceremony was cancelled."
        case .expired:
            return "The SCA ceremony expired."
        case .unsupported:
            return "This device or browser cannot complete a passkey ceremony."
        case .alreadyEnrolled:
            return "A passkey is already enrolled for this user."
        case .stateMismatch:
            return "The SCA callback did not match the ceremony that was opened."
        case .sessionUnavailable:
            return "The SCA ceremony sheet could not be shown."
        case .protocol:
            return "The SCA ceremony did not follow the expected protocol."
        }
    }
}

/// Which surface a ceremony would run in on this device.
public enum DaaScaSurface: Equatable, Sendable {
    /// `ASWebAuthenticationSession` — the only surface this SDK uses.
    case webAuthenticationSession

    /// The session cannot deliver the configured callback on this OS version;
    /// every ceremony fails `sessionUnavailable`.
    case none
}

/// What this device and host app can do, for choosing copy and for checking
/// support before a transfer is attempted rather than discovering a gap
/// mid-ceremony.
///
/// Gate on `isCeremonySupported`, not on `surface` alone: a sheet that can be
/// shown on an OS without passkeys only reaches the page's `Unsupported`
/// screen.
public struct DaaScaCapabilities: Equatable, Sendable {
    /// Version of the native redirect contract this SDK speaks.
    public let protocolVersion: Int

    /// The surface `approve` and `enroll` will use.
    public let surface: DaaScaSurface

    /// Whether this OS can hand the configured redirect URI back to the
    /// session. A custom scheme always can; an `https` callback needs iOS
    /// 17.4 (a configuration that needs it is refused at construction on
    /// older versions). This cannot see the `webcredentials` Associated
    /// Domains entitlement an `https` callback also needs, so `true` for
    /// `https` is necessary, not sufficient.
    public let callbackSupported: Bool

    /// Whether the OS is recent enough for passkeys in the session (iOS 16+).
    /// A heuristic: it cannot see whether a device passcode is set, iCloud
    /// Keychain is on, or a credential provider is enabled. The browser and
    /// the credential provider make the final call, and the page reports
    /// `unsupported` if they refuse.
    public let platformPasskeys: Bool

    /// `true` when the sheet can be shown, can return its callback, and the
    /// OS supports passkeys. `false` means a ceremony cannot succeed here;
    /// `true` still leaves the device-state checks `platformPasskeys`
    /// describes to the page.
    public var isCeremonySupported: Bool {
        surface == .webAuthenticationSession && callbackSupported && platformPasskeys
    }
}
