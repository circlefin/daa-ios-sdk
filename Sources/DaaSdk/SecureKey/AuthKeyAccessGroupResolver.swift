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
import Security

/// Resolves this process's own application-identifier Keychain access group,
/// for use when a caller has not supplied an explicit `keychainAccessGroup`.
///
/// Without this, a lookup query that omits `kSecAttrAccessGroup` searches
/// every access group the process is entitled to, while an add that omits it
/// writes to the first group in that entitlement list — the two can diverge
/// whenever an integrator enables Keychain Sharing for any reason (a widget,
/// an app group). Resolving one concrete default and threading it through
/// `DaaAuthKeyIdentity.descriptor()` keeps every query — lookup, create,
/// metadata read, and metadata write — scoped to the same value.
///
/// The group resolved is the process's own application-identifier group,
/// `<App ID prefix>.<bundle identifier>`, not whichever group an unscoped
/// `SecItemAdd` would pick. Keychain Services assigns an unscoped add to the
/// first group in the process's combined list — `keychain-access-groups`
/// entries first, then the application identifier, then app groups — so an
/// integrator who lists a shared group first in Keychain Sharing would
/// otherwise put the AuthKey in that shared group without asking for it. The
/// application-identifier group is always in that list and belongs to this
/// app or extension alone, so it is the one default that never widens the
/// key's sharing scope. Sharing the AuthKey requires an explicit
/// `keychainAccessGroup`.
///
/// There is no public API that reports the application identifier directly
/// (`SecTaskCopyValueForEntitlement` reports it on macOS but is not declared
/// in the public iOS SDK, which is this SDK's actual target platform per
/// `Package.swift`). Resolution instead adds a throwaway generic password
/// item with no explicit access group, reads back whichever group Keychain
/// Services assigned it, and deletes it. Every group in that list except app
/// groups carries the App ID prefix, and app groups come last, so the probed
/// group's prefix is the App ID prefix; `ownAccessGroup` joins it to the
/// bundle identifier. That derived group is not probed a second time: if it
/// were somehow not entitled, every AuthKey query scoped to it fails closed
/// with `keychainEntitlementMissing` rather than falling back to an unscoped
/// query. On iOS the probe item is the only Keychain item this SDK ever
/// writes without an explicit access group; it holds no key material and is
/// deleted before the probe returns.
///
/// On iOS resolution either returns a concrete group or throws; it never
/// returns `nil`, so it can never hand `DaaAuthKeyIdentity.descriptor()` an
/// unscoped default. Every probe failure throws, whatever its cause, and the
/// operation that asked fails closed instead of running an unscoped query:
/// see `probeError(for:)` for which `DaaSecureKeyError` each failure
/// surfaces as. Only a resolved group is cached for the process lifetime,
/// since an app's own access group cannot change at runtime; a failure is
/// never cached, so a later call probes again. That holds even for a failure
/// that will recur on every call (for example, a process with no usable
/// data-protection keychain): the cost is that every AuthKey operation in
/// that process keeps failing closed, never that one of them runs unscoped.
///
/// The probe only runs on iOS: macOS here is host/test-only, and running it
/// on a developer's or build machine's login keychain would write/delete an item
/// there for no product reason. `resolveDefault()` returns `nil` there, the
/// one case where a descriptor is left unscoped.
///
/// Tests drive the iOS resolution logic on any host through
/// `resolve(cache:keychain:bundleIdentifier:)`, passing their own cache and a
/// fake `AuthKeyAccessGroupProbeKeychain` in place of `.system`; production
/// reaches it only through `resolveDefault()`. A test that needs a fixed
/// default access group without any Keychain at all constructs a
/// `DaaAuthKeyIdentity` via one of its internal initializers
/// (`defaultAccessGroupOverride:` or `resolveDefaultAccessGroup:`).
enum AuthKeyAccessGroupResolver {
    private static let sharedCache = AuthKeyAccessGroupResolutionCache()
    static let probeService = "com.circle.daa.authkey.access-group-probe"
    private static let maxProbeAttempts = 3

    /// - Returns: This process's own application-identifier group on iOS.
    ///   Returns `nil` only on the macOS host/test process, where no probe
    ///   runs.
    /// - Throws: The error `probeError(for:)` maps the failing Keychain status
    ///   to, or `keyAccessFailed` when the probe cannot produce a group; a
    ///   later call probes again.
    static func resolveDefault() throws -> String? {
        #if os(iOS)
        return try resolve(
            cache: sharedCache,
            keychain: .system,
            bundleIdentifier: Bundle.main.bundleIdentifier
        )
        #else
        return nil
        #endif
    }

    /// The iOS resolution logic, with its Keychain and cache supplied by the
    /// caller. Returns a concrete group or throws; a thrown failure leaves
    /// `cache` empty so the next call probes again.
    static func resolve(
        cache: AuthKeyAccessGroupResolutionCache,
        keychain: AuthKeyAccessGroupProbeKeychain,
        bundleIdentifier: String?
    ) throws -> String {
        try cache.value {
            ownAccessGroup(
                probedAccessGroup: try probeDefaultAccessGroup(keychain: keychain),
                bundleIdentifier: bundleIdentifier
            )
        }
    }

    /// Derives the application-identifier group from the group an unscoped
    /// probe item landed in and this process's bundle identifier: the probed
    /// group's App ID prefix (everything before its first `.`) joined to the
    /// bundle identifier.
    ///
    /// Returns `probedAccessGroup` unchanged when there is no App ID prefix
    /// or bundle identifier to derive from. With no prefix there is no
    /// Keychain Sharing group for the AuthKey to land in by mistake, and a
    /// concrete group is still safer than an unscoped query.
    static func ownAccessGroup(
        probedAccessGroup: String,
        bundleIdentifier: String?
    ) -> String {
        guard let bundleIdentifier, !bundleIdentifier.isEmpty,
              let separator = probedAccessGroup.firstIndex(of: "."),
              separator != probedAccessGroup.startIndex else {
            return probedAccessGroup
        }
        return "\(probedAccessGroup[..<separator]).\(bundleIdentifier)"
    }

    private static func probeDefaultAccessGroup(
        keychain: AuthKeyAccessGroupProbeKeychain
    ) throws -> String {
        let probeQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: probeService,
            kSecAttrAccount as String: probeService,
            kSecUseDataProtectionKeychain as String: true
        ]
        defer {
            keychain.delete(probeQuery)
        }

        var addQuery = probeQuery
        addQuery[kSecValueData as String] = Data([0x00])
        addQuery[kSecReturnAttributes as String] = true

        // Two processes can cold-launch together: one wins SecItemAdd while
        // the other sees a duplicate, then the winner deletes the probe
        // before the loser reads it. Only that duplicate-then-not-found race
        // is retried here; every other failure throws on the first attempt,
        // since spinning cannot fix it (an unlock, for instance, needs real
        // elapsed time).
        for _ in 0..<maxProbeAttempts {
            if let accessGroup = try attemptAdd(addQuery, keychain: keychain) {
                return accessGroup
            }
            // A previous probe was never cleaned up (for example, the process
            // was killed between add and delete), or another process owns the
            // probe. Read its access group instead of treating duplication as
            // a resolution failure.
            if let accessGroup = try attemptReadExistingProbe(probeQuery, keychain: keychain) {
                return accessGroup
            }
        }
        // Still contended after every attempt. Like every other probe failure
        // this is not cached: another process may stop deleting the shared
        // probe before the next caller's read.
        throw DaaSecureKeyError.keyAccessFailed
    }

    /// Attempts to claim the probe item. Returns `nil` (meaning: fall through
    /// to reading whoever already owns it) only on `errSecDuplicateItem`;
    /// every other status either resolves or throws.
    private static func attemptAdd(
        _ addQuery: [String: Any],
        keychain: AuthKeyAccessGroupProbeKeychain
    ) throws -> String? {
        let (addStatus, attributes) = keychain.add(addQuery)
        if addStatus == errSecSuccess {
            return try accessGroup(in: attributes)
        }
        guard addStatus == errSecDuplicateItem else {
            throw probeError(for: addStatus)
        }
        return nil
    }

    /// Reads back whichever process's probe item won the race. Returns `nil`
    /// (meaning: retry the loop, the winner may since have deleted it) only
    /// on `errSecItemNotFound`; every other status either resolves or throws.
    private static func attemptReadExistingProbe(
        _ probeQuery: [String: Any],
        keychain: AuthKeyAccessGroupProbeKeychain
    ) throws -> String? {
        var readQuery = probeQuery
        readQuery[kSecReturnAttributes as String] = true
        readQuery[kSecMatchLimit as String] = kSecMatchLimitOne
        let (readStatus, attributes) = keychain.copyMatching(readQuery)
        if readStatus == errSecSuccess {
            return try accessGroup(in: attributes)
        }
        guard readStatus == errSecItemNotFound else {
            throw probeError(for: readStatus)
        }
        return nil
    }

    /// A probe item Keychain Services stored but will not describe gives no
    /// group to scope to, so it fails closed like any other probe failure.
    private static func accessGroup(in attributes: [String: Any]?) throws -> String {
        guard let accessGroup = attributes?[kSecAttrAccessGroup as String] as? String,
              !accessGroup.isEmpty else {
            throw DaaSecureKeyError.keyAccessFailed
        }
        return accessGroup
    }

    /// Maps a failed probe status to the error the AuthKey operation throws,
    /// using the same mapping as every other AuthKey Keychain call.
    ///
    /// The mapping only chooses which error the integrator sees. It does not
    /// decide whether the failure is cached or whether anything runs
    /// unscoped: every probe failure throws and none is cached, so a later
    /// call probes again regardless of the status.
    ///
    /// `errSecInteractionNotAllowed` means the device hasn't been unlocked
    /// since boot (a background launch from a push, VoIP, or
    /// `BGTaskScheduler` task, before the data-protection keychain is
    /// available) and surfaces as `deviceLocked`, whose documented recovery is
    /// to retry after the user unlocks the device.
    ///
    /// `errSecNotAvailable` is deliberately not mapped to `deviceLocked`, even
    /// though it can also surface on a pre-unlock cold launch, because its
    /// documented meaning is broader than that one timing case: it can mean a
    /// data-protection keychain is genuinely unavailable in some
    /// process/extension contexts, where telling the integrator to wait for
    /// an unlock would be wrong. It surfaces as `keyAccessFailed`, which the
    /// integrator can retry, and the probe runs again on that retry, so a
    /// pre-unlock `errSecNotAvailable` still resolves the app's own group once
    /// the keychain becomes available.
    static func probeError(for status: OSStatus) -> DaaSecureKeyError {
        SecureEnclaveAuthKeyBackend.map(status: status, fallback: .keyAccessFailed)
    }
}

/// The three Keychain calls the access-group probe makes, so a test can
/// inject probe statuses without a real Keychain. Production always uses
/// `.system`.
struct AuthKeyAccessGroupProbeKeychain: Sendable {
    /// `SecItemAdd`, returning the status and the added item's attributes.
    let add: @Sendable ([String: Any]) -> (OSStatus, [String: Any]?)
    /// `SecItemCopyMatching`, returning the status and the matched attributes.
    let copyMatching: @Sendable ([String: Any]) -> (OSStatus, [String: Any]?)
    /// `SecItemDelete`. Its status is ignored: the probe deletes on a
    /// best-effort basis, and a leftover probe item is read back by the next
    /// probe rather than treated as a failure.
    let delete: @Sendable ([String: Any]) -> Void

    static let system = Self(
        add: { query in
            var result: CFTypeRef?
            let status = SecItemAdd(query as CFDictionary, &result)
            return (status, result as? [String: Any])
        },
        copyMatching: { query in
            var result: CFTypeRef?
            let status = SecItemCopyMatching(query as CFDictionary, &result)
            return (status, result as? [String: Any])
        },
        delete: { query in
            _ = SecItemDelete(query as CFDictionary)
        }
    )
}

/// Memoizes a resolved access group; an app's own access group cannot change
/// at runtime, so a successful probe only ever needs to run once. A thrown
/// failure is never stored, so the next call computes again. NSLock
/// serializes the probe itself as well as the stored value, so concurrent
/// first callers in one process never race each other's probe item.
final class AuthKeyAccessGroupResolutionCache: @unchecked Sendable {
    private let lock = NSLock()
    private var resolvedValue: String?

    func value(compute: () throws -> String) rethrows -> String {
        lock.lock()
        defer { lock.unlock() }
        if let resolvedValue {
            return resolvedValue
        }
        let computed = try compute()
        resolvedValue = computed
        return computed
    }
}
