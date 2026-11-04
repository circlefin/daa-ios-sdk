// swift-tools-version:5.9

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

// The swift-tools-version declares the minimum version of Swift required to
// build this package.
//
// DAA iOS SDK — Swift SDK for Circle Digital Asset Accounts (DAA), including
// the installation Secure Enclave AuthKey.

import PackageDescription

let package = Package(
    name: "DaaSdk",
    platforms: [
        // iOS is the SDK's target platform for the Secure Enclave / Keychain
        // surface.
        .iOS(.v15),
        // macOS is host/test-only: it lets `swift test` run on a Mac. It is
        // NOT a supported consumer platform.
        .macOS(.v12),
    ],
    products: [
        // The single public library product consumers depend on.
        .library(
            name: "DaaSdk",
            targets: ["DaaSdk"]
        ),
    ],
    targets: [
        .target(
            name: "DaaSdk",
            swiftSettings: [
                .enableUpcomingFeature("StrictConcurrency")
            ]
        ),
        .testTarget(
            name: "DaaSdkTests",
            dependencies: ["DaaSdk"],
            resources: [
                .copy("Fixtures")
            ],
            swiftSettings: [
                .enableUpcomingFeature("StrictConcurrency")
            ]
        ),
    ]
)
