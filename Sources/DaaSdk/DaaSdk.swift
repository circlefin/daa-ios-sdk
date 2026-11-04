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

/// DAA iOS SDK — Swift SDK for Digital Asset Accounts (DAA).
///
/// The SDK contains the installation Secure Enclave AuthKey, wire encoders, and
/// the pre-Prepare registration primitives — the platform CSPRNG and the
/// ephemeral registration-flow key, which is not an AuthKey. It does not
/// include enrollment, sessions, HTTP transport, REST clients, Owner grants,
/// JWS claim construction, or Programmable Wallets request/response models.
/// The React Native SDK owns DAA networking and business clients.
///
/// `DaaSca` presents Circle's hosted SCA ceremony in
/// `ASWebAuthenticationSession` and relays its result. It holds no key
/// material; see "Passkey SCA (strong customer authentication)" in the
/// package README.
public enum DaaSdk {
    /// The SDK version. Kept in sync with the published package version.
    public static let version = "0.7.1" // x-release-please-version
}
