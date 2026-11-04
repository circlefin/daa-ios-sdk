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

/// How a metadata read treats legacy records and unexpected Keychain statuses.
enum AuthKeyMetadataReadMode: Equatable, Sendable {
    /// Resolution and signing: migrate a `v1` protection record, delete an
    /// unbound `v1` registration marker, and report an unexpected Keychain
    /// status as `keyMetadataUnavailable`.
    case resolving
    /// `resolveExisting()`: write nothing, and report an unexpected Keychain
    /// status as `keyAccessFailed`, so a read failure throws rather than being
    /// mistaken for a record that is missing or cannot be trusted, which the
    /// restore path reports as nothing to restore.
    case restoring

    var writesLegacyRecords: Bool {
        self == .resolving
    }

    var unexpectedStatusError: DaaSecureKeyError {
        switch self {
        case .resolving:
            return .keyMetadataUnavailable
        case .restoring:
            return .keyAccessFailed
        }
    }
}

extension SecureEnclaveAuthKeyBackend {
    /// The error a metadata read reports for a Keychain status other than
    /// success or not-found.
    static func metadataReadFailure(
        status: OSStatus,
        mode: AuthKeyMetadataReadMode
    ) -> DaaSecureKeyError {
        map(status: status, fallback: mode.unexpectedStatusError)
    }

    func loadProtection(
        descriptor: AuthKeyDescriptor,
        expectedKeyBinding: String,
        mode: AuthKeyMetadataReadMode = .resolving
    ) throws -> DaaAuthKeyProtection? {
        guard let data = try loadSingleMetadataData(
            query: metadataQuery(descriptor: descriptor),
            mode: mode
        ) else {
            return nil
        }
        do {
            let record = try AuthKeyMetadataCodec.decodeProtection(
                data,
                expectedKeyBinding: expectedKeyBinding
            )
            if record.requiresMigration, mode.writesLegacyRecords {
                try updateProtection(
                    record.protection,
                    descriptor: descriptor,
                    keyBinding: expectedKeyBinding
                )
            }
            return record.protection
        } catch AuthKeyMetadataDecodeError.unsupportedVersion {
            throw DaaSecureKeyError.keyMetadataVersionUnsupported
        } catch let error as DaaSecureKeyError {
            throw error
        } catch {
            throw DaaSecureKeyError.keyMetadataUnavailable
        }
    }

    func saveProtection(
        _ protection: DaaAuthKeyProtection,
        descriptor: AuthKeyDescriptor,
        keyBinding: String
    ) throws {
        var attributes = metadataQuery(descriptor: descriptor)
        attributes[kSecAttrAccessible as String] =
            kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly
        attributes[kSecValueData as String] = AuthKeyMetadataCodec.encodeProtection(
            protection,
            keyBinding: keyBinding
        )
        let status = SecItemAdd(attributes as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw Self.map(status: status, fallback: .keyCreationFailed)
        }
    }

    func deleteProtection(descriptor: AuthKeyDescriptor) throws {
        let status = SecItemDelete(metadataQuery(descriptor: descriptor) as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw Self.map(status: status, fallback: .keyAccessFailed)
        }
    }

    private func updateProtection(
        _ protection: DaaAuthKeyProtection,
        descriptor: AuthKeyDescriptor,
        keyBinding: String
    ) throws {
        let updates = [
            kSecValueData as String: AuthKeyMetadataCodec.encodeProtection(
                protection,
                keyBinding: keyBinding
            )
        ]
        let status = SecItemUpdate(
            metadataQuery(descriptor: descriptor) as CFDictionary,
            updates as CFDictionary
        )
        guard status == errSecSuccess else {
            throw Self.map(status: status, fallback: .keyMetadataUnavailable)
        }
    }

    func loadRegistration(
        descriptor: AuthKeyDescriptor,
        expectedKeyBinding: String
    ) throws -> Bool {
        try loadRegistrationRecord(
            descriptor: descriptor,
            expectedKeyBinding: expectedKeyBinding
        ) != nil
    }

    /// The decoded registration record, or `nil` when the key is not
    /// acknowledged. In `.restoring` mode an unbound `v1` marker is reported
    /// as not acknowledged without being deleted.
    func loadRegistrationRecord(
        descriptor: AuthKeyDescriptor,
        expectedKeyBinding: String,
        mode: AuthKeyMetadataReadMode = .resolving
    ) throws -> AuthKeyRegistrationMetadataRecord? {
        guard let data = try loadSingleMetadataData(
            query: registrationQuery(descriptor: descriptor),
            mode: mode
        ) else {
            return nil
        }
        if AuthKeyMetadataCodec.isLegacyUnboundRegistration(data) {
            if mode.writesLegacyRecords {
                try deleteRegistration(descriptor: descriptor)
            }
            return nil
        }
        do {
            return try AuthKeyMetadataCodec.decodeRegistration(
                data,
                expectedKeyBinding: expectedKeyBinding
            )
        } catch AuthKeyMetadataDecodeError.unsupportedVersion {
            throw DaaSecureKeyError.keyMetadataVersionUnsupported
        } catch let error as DaaSecureKeyError {
            throw error
        } catch {
            throw DaaSecureKeyError.keyMetadataUnavailable
        }
    }

    private func loadSingleMetadataData(
        query: [String: Any],
        mode: AuthKeyMetadataReadMode
    ) throws -> Data? {
        var query = query
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitAll

        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound {
            return nil
        }
        guard status == errSecSuccess else {
            throw Self.metadataReadFailure(status: status, mode: mode)
        }
        guard let items = result as? [Data], items.count == 1, let data = items.first else {
            // A metadata tag must identify exactly one record. Never allow
            // Keychain Services to choose an arbitrary record when duplicate
            // metadata exists across entitled access groups.
            throw DaaSecureKeyError.keyMetadataUnavailable
        }
        return data
    }

    func saveRegistration(
        descriptor: AuthKeyDescriptor,
        keyBinding: String
    ) throws {
        var attributes = registrationQuery(descriptor: descriptor)
        attributes[kSecAttrAccessible as String] =
            kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly
        attributes[kSecValueData as String] = AuthKeyMetadataCodec.encodeRegistration(
            keyBinding: keyBinding
        )
        let status = SecItemAdd(attributes as CFDictionary, nil)
        if status == errSecSuccess {
            return
        }
        if status == errSecDuplicateItem {
            guard try loadRegistration(
                descriptor: descriptor,
                expectedKeyBinding: keyBinding
            ) else {
                throw DaaSecureKeyError.keyMetadataUnavailable
            }
            return
        }
        throw Self.map(status: status, fallback: .keyAccessFailed)
    }

    /// Write a `v3` registration record carrying `registration`'s ids,
    /// replacing whatever registration record already exists.
    func upsertRegistration(
        _ registration: DaaRegisteredAuthKey,
        descriptor: AuthKeyDescriptor,
        keyBinding: String
    ) throws {
        let value = AuthKeyMetadataCodec.encodeRegistration(
            registration,
            keyBinding: keyBinding
        )
        var attributes = registrationQuery(descriptor: descriptor)
        attributes[kSecAttrAccessible as String] =
            kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly
        attributes[kSecValueData as String] = value
        let status = SecItemAdd(attributes as CFDictionary, nil)
        if status == errSecSuccess {
            return
        }
        guard status == errSecDuplicateItem else {
            throw Self.map(status: status, fallback: .keyAccessFailed)
        }
        let updateStatus = SecItemUpdate(
            registrationQuery(descriptor: descriptor) as CFDictionary,
            [kSecValueData as String: value] as CFDictionary
        )
        guard updateStatus == errSecSuccess else {
            throw Self.map(status: updateStatus, fallback: .keyAccessFailed)
        }
    }

    func deleteRegistration(descriptor: AuthKeyDescriptor) throws {
        let status = SecItemDelete(registrationQuery(descriptor: descriptor) as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw Self.map(status: status, fallback: .keyAccessFailed)
        }
    }

    private func metadataQuery(
        descriptor: AuthKeyDescriptor
    ) -> [String: Any] {
        Self.genericPasswordQuery(
            descriptor: descriptor,
            service: Self.metadataService
        )
    }

    private func registrationQuery(
        descriptor: AuthKeyDescriptor
    ) -> [String: Any] {
        Self.genericPasswordQuery(
            descriptor: descriptor,
            service: Self.registrationService
        )
    }

    static func genericPasswordQuery(
        descriptor: AuthKeyDescriptor,
        service: String
    ) -> [String: Any] {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: Base64URL.encode(descriptor.applicationTag),
            kSecUseDataProtectionKeychain as String: true
        ]
        if let accessGroup = descriptor.accessGroup {
            query[kSecAttrAccessGroup as String] = accessGroup
        }
        return query
    }
}
