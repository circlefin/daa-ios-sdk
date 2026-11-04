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

/// The registration Circle recorded for the installation AuthKey, as last
/// acknowledged with `DaaSecureKey.acknowledgeRegistration(authKeyId:ownerBindingId:)`.
///
/// `authKeyId` is the server-assigned id that names this key, for example as
/// a JWS `kid`. Neither id is secret, but both identify the Owner, so keep
/// them out of logs.
public struct DaaRegisteredAuthKey: Equatable, Sendable {
    /// The server-assigned AuthKey id, a UUID string exactly as it was
    /// acknowledged.
    public let authKeyId: String
    /// The server-assigned Owner binding id, a UUID string exactly as it was
    /// acknowledged.
    public let ownerBindingId: String
    /// When this device last recorded the acknowledgement, at millisecond
    /// precision. It is the local write time, not a server timestamp.
    public let registeredAt: Date

    /// The latest instant `registeredAt` can hold, 9999-12-31T23:59:59.999Z.
    /// The earliest is the Unix epoch, 1970-01-01T00:00:00.000Z.
    static let maximumEpochMilliseconds: Int64 = 253_402_300_799_999

    /// Creates a value, for example for a test double.
    ///
    /// `registeredAt` is rounded to the millisecond and clamped to the range
    /// a registration record can hold, 1970-01-01T00:00:00.000Z through
    /// 9999-12-31T23:59:59.999Z. A date before that range, negative
    /// infinity, and NaN become the earliest instant; a later date and
    /// positive infinity become the latest. The initializer never traps.
    public init(authKeyId: String, ownerBindingId: String, registeredAt: Date) {
        self.authKeyId = authKeyId
        self.ownerBindingId = ownerBindingId
        self.registeredAt = Self.date(
            epochMilliseconds: Self.epochMilliseconds(of: registeredAt)
        )
    }

    init(
        authKeyId: String,
        ownerBindingId: String,
        registeredAtEpochMilliseconds: Int64
    ) {
        self.authKeyId = authKeyId
        self.ownerBindingId = ownerBindingId
        let clamped = min(max(registeredAtEpochMilliseconds, 0), Self.maximumEpochMilliseconds)
        registeredAt = Self.date(epochMilliseconds: clamped)
    }

    var registeredAtEpochMilliseconds: Int64 {
        Self.epochMilliseconds(of: registeredAt)
    }

    /// Whether `value` is a hyphenated 36-character UUID string. Case is
    /// preserved rather than normalized, so the stored id is byte-for-byte
    /// the value Circle returned.
    static func isCanonicalUUID(_ value: String) -> Bool {
        value.utf8.count == 36 && UUID(uuidString: value) != nil
    }

    /// Total: clamps instead of trapping, because `Int64(_: Double)` traps on
    /// NaN, infinity, and values outside `Int64`.
    private static func epochMilliseconds(of date: Date) -> Int64 {
        let milliseconds = (date.timeIntervalSince1970 * 1_000).rounded()
        guard !milliseconds.isNaN else {
            return 0
        }
        let clamped = min(max(milliseconds, 0), Double(maximumEpochMilliseconds))
        return Int64(clamped)
    }

    private static func date(epochMilliseconds: Int64) -> Date {
        Date(timeIntervalSince1970: Double(epochMilliseconds) / 1_000)
    }
}
