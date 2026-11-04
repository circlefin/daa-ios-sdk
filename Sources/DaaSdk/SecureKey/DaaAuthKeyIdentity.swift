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

/// Stable namespace for one DAA Owner AuthKey in the current app installation.
///
/// This value does not identify the active Owner. A multi-user host must select
/// a distinct identity per Owner, for example by persisting a separate
/// installation UUID for each Owner within the app installation.
public struct DaaAuthKeyIdentity: Hashable, Sendable {
    public let appID: String
    public let environment: DaaEnvironment
    public let installationID: UUID
    /// An explicit Keychain access group for an app/extension pair sharing
    /// the AuthKey via Keychain Sharing. Any app or app extension that holds
    /// this same access group entitlement can read, use, and overwrite the
    /// AuthKey and its metadata records — scope it no more broadly than the
    /// pair that must share the key. When `nil`, the effective group defaults
    /// to this process's own application-identifier access group
    /// (`<App ID prefix>.<bundle identifier>`) rather than being left
    /// unscoped, so a Keychain lookup and a Keychain write always resolve to
    /// the same group, and the AuthKey never lands in a shared
    /// group just because Keychain Sharing lists that group first. If that
    /// default cannot be resolved (for example, before the first unlock after
    /// boot), each AuthKey operation throws instead of running unscoped, and
    /// the next operation tries again.
    public let keychainAccessGroup: String?
    /// Resolves the default access group when `keychainAccessGroup` is `nil`.
    /// The public initializer always uses
    /// `AuthKeyAccessGroupResolver.resolveDefault()`, called lazily when a
    /// descriptor is first needed; only the internal initializers below
    /// substitute a test value, so no production caller can change it.
    /// Excluded from `==`/`hash(into:)`: it is an environment detail a test
    /// injects, not part of this identity's own definition, so two identities
    /// with the same real fields are still the same identity regardless of
    /// what a test told them to assume.
    private let resolveDefaultAccessGroup: @Sendable () throws -> String?
    /// Whether `descriptor()` rejects an unscoped descriptor. Platform-derived
    /// in production; only the internal initializer below lets a test force it
    /// on the macOS test host. Excluded from `==`/`hash(into:)` like
    /// `resolveDefaultAccessGroup`.
    private let requiresExplicitAccessGroup: Bool

    public init(
        appID: String,
        environment: DaaEnvironment,
        installationID: UUID,
        keychainAccessGroup: String? = nil
    ) throws {
        try self.init(
            appID: appID,
            environment: environment,
            installationID: installationID,
            keychainAccessGroup: keychainAccessGroup,
            defaultAccessGroupOverride: nil
        )
    }

    /// Not part of the public API: lets a test supply a fixed resolved
    /// default access group (or `.some(nil)` to simulate the macOS host,
    /// where no default resolves) without ever touching
    /// `AuthKeyAccessGroupResolver` or a real Keychain. Production always
    /// goes through the public initializer above, which passes `nil` here and
    /// so always defers to the resolver.
    init(
        appID: String,
        environment: DaaEnvironment,
        installationID: UUID,
        keychainAccessGroup: String? = nil,
        defaultAccessGroupOverride: String??
    ) throws {
        let resolveDefaultAccessGroup: @Sendable () throws -> String?
        if let defaultAccessGroupOverride {
            resolveDefaultAccessGroup = { defaultAccessGroupOverride }
        } else {
            resolveDefaultAccessGroup = { try AuthKeyAccessGroupResolver.resolveDefault() }
        }
        try self.init(
            appID: appID,
            environment: environment,
            installationID: installationID,
            keychainAccessGroup: keychainAccessGroup,
            resolveDefaultAccessGroup: resolveDefaultAccessGroup
        )
    }

    /// Not part of the public API: lets a test make default access-group
    /// resolution fail, as a probe failure does, without a real Keychain, or
    /// wire in `AuthKeyAccessGroupResolver.resolve(cache:keychain:bundleIdentifier:)`
    /// with a fake probe Keychain. `requiresExplicitAccessGroup` is only
    /// overridden by tests, to exercise the iOS rule on the macOS test host.
    init(
        appID: String,
        environment: DaaEnvironment,
        installationID: UUID,
        keychainAccessGroup: String? = nil,
        requiresExplicitAccessGroup: Bool = AuthKeyDescriptor.requiresExplicitAccessGroup,
        resolveDefaultAccessGroup: @escaping @Sendable () throws -> String?
    ) throws {
        guard Self.isValidNamespace(appID, maximumLength: 64) else {
            throw DaaSecureKeyError.invalidAppID
        }
        if let keychainAccessGroup {
            guard Self.isValidNamespace(keychainAccessGroup, maximumLength: 255) else {
                throw DaaSecureKeyError.invalidKeychainAccessGroup
            }
            // A caller-supplied group naming a different team than this
            // process's own is never correct: it would either fail
            // entitlement checks on device or, worse, name a group this app
            // is not supposed to be sharing with. Only enforced when a
            // default is resolvable at all — never on the macOS test host,
            // where resolution is a deliberate no-op (see
            // `AuthKeyAccessGroupResolver`). A failed resolution attempt
            // also skips the check rather than failing construction: every
            // query still uses the caller-supplied group, so nothing runs
            // unscoped.
            let defaultAccessGroup = (try? resolveDefaultAccessGroup()) ?? nil
            if let defaultAccessGroup,
               Self.teamIdentifierPrefix(of: keychainAccessGroup) !=
                Self.teamIdentifierPrefix(of: defaultAccessGroup) {
                throw DaaSecureKeyError.invalidKeychainAccessGroup
            }
        }
        self.appID = appID
        self.environment = environment
        self.installationID = installationID
        self.keychainAccessGroup = keychainAccessGroup
        self.resolveDefaultAccessGroup = resolveDefaultAccessGroup
        self.requiresExplicitAccessGroup = requiresExplicitAccessGroup
    }

    /// The Keychain scope for every AuthKey query.
    ///
    /// - Throws: When `keychainAccessGroup` is `nil` and the default group
    ///   could not be resolved this time, the resolver's error (`deviceLocked`,
    ///   `keychainEntitlementMissing`, or `keyAccessFailed`). On iOS, also
    ///   `keyAccessFailed` if no group resolved at all. The operation fails
    ///   closed instead of running an unscoped query; a later call resolves
    ///   again.
    func descriptor() throws -> AuthKeyDescriptor {
        let descriptor = AuthKeyDescriptor(
            applicationTag: applicationTag,
            // Short-circuits: the resolver (and the lock/Keychain I/O behind
            // it) is only reached when keychainAccessGroup is nil.
            accessGroup: try keychainAccessGroup ?? resolveDefaultAccessGroup()
        )
        // The iOS resolver never returns nil; this keeps a nil-returning
        // resolver from ever producing an unscoped iOS descriptor anyway.
        try descriptor.requireExplicitAccessGroup(required: requiresExplicitAccessGroup)
        return descriptor
    }

    public static func == (lhs: Self, rhs: Self) -> Bool {
        lhs.appID == rhs.appID
            && lhs.environment == rhs.environment
            && lhs.installationID == rhs.installationID
            && lhs.keychainAccessGroup == rhs.keychainAccessGroup
    }

    public func hash(into hasher: inout Hasher) {
        hasher.combine(appID)
        hasher.combine(environment)
        hasher.combine(installationID)
        hasher.combine(keychainAccessGroup)
    }

    private static func teamIdentifierPrefix(of accessGroup: String) -> Substring {
        accessGroup.prefix(while: { $0 != "." })
    }

    var applicationTag: Data {
        let installation = installationID.uuidString.lowercased()
        return Data(
            "com.circle.daa.authkey.v1.\(appID).\(environment.rawValue).\(installation)".utf8
        )
    }

    private static func isValidNamespace(
        _ value: String,
        maximumLength: Int
    ) -> Bool {
        guard (1...maximumLength).contains(value.count) else {
            return false
        }
        return value.unicodeScalars.allSatisfy { scalar in
            let value = scalar.value
            return (48...57).contains(value) ||
                (65...90).contains(value) ||
                (97...122).contains(value) ||
                value == 45 || value == 46 || value == 95
        }
    }
}
