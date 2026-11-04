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

/// The shared SCA conformance vectors, `Conformance/ScaCallbackV1.json`.
///
/// Loaded the way `AuthKeyWireFixture` is: from the SwiftPM resource copy,
/// which must be byte-identical to the canonical artifact the Android SDK
/// copies.
struct ScaConformanceFixture: Decodable {
    let version: Int
    let profile: String
    let description: String
    let callbackVectors: [ScaCallbackVector]
    let redirectUriVectors: ScaRedirectURIVectors
    let platformRules: [ScaPlatformRule]
    let circleOriginVectors: [ScaCircleOriginVector]
    let timeoutVectors: ScaTimeoutVectors
    let errorVocabulary: ScaErrorVocabulary

    static func load() throws -> ScaConformanceFixture {
        let url = Bundle.module.url(
            forResource: "ScaCallbackV1",
            withExtension: "json",
            subdirectory: "Fixtures"
        )
        guard let url else {
            throw FixtureError.missing
        }

        let bundledData = try Data(contentsOf: url)
        let canonicalData = try Data(contentsOf: canonicalURL)
        guard bundledData == canonicalData else {
            throw FixtureError.outOfSync
        }

        let fixture = try JSONDecoder().decode(ScaConformanceFixture.self, from: bundledData)
        guard fixture.version == 1, fixture.profile == "daa-sca-callback-v1" else {
            throw FixtureError.invalidMetadata
        }
        return fixture
    }

    private static var canonicalURL: URL {
        URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .appendingPathComponent("Conformance/ScaCallbackV1.json")
    }
}

// The fixture's record types, top level to keep nesting shallow.

struct ScaCallbackVectorInput: Decodable {
    let redirectUri: GeneratedString
    let state: String
    let ceremony: String
    let callback: GeneratedString
}

struct ScaCallbackVector: Decodable {
    let id: String
    let input: ScaCallbackVectorInput
    let expected: ScaCallbackExpectation
}

/// One callback outcome, as the fixture spells it.
struct ScaCallbackOutcome: Decodable, Equatable, CustomStringConvertible {
    let outcome: String
    let result: GeneratedString?
    let code: String?
    let message: GeneratedString?

    init(outcome: String, result: String? = nil, code: String? = nil, message: String? = nil) {
        self.outcome = outcome
        self.result = result.map(GeneratedString.init(value:))
        self.code = code
        self.message = message.map(GeneratedString.init(value:))
    }

    // Kept short: a payload or message can run to tens of kilobytes.
    var description: String {
        let detail = [code, result.map { "result(\($0.value.utf8.count) bytes)" },
                      message.map { "message(\($0.value.utf8.count) bytes)" }]
        return ([outcome] + detail.compactMap { $0 }).joined(separator: " ")
    }
}

/// Either one outcome for both SDKs, or `{"ios": …, "android": …}`.
struct ScaCallbackExpectation: Decodable {
    let ios: ScaCallbackOutcome
    let android: ScaCallbackOutcome

    var isPerPlatform: Bool { ios != android }

    private enum CodingKeys: String, CodingKey {
        case ios
        case android
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        if container.contains(.ios) {
            ios = try container.decode(ScaCallbackOutcome.self, forKey: .ios)
            android = try container.decode(ScaCallbackOutcome.self, forKey: .android)
        } else {
            let common = try ScaCallbackOutcome(from: decoder)
            ios = common
            android = common
        }
    }
}

struct ScaRedirectURIVectors: Decodable {
    let accept: [ScaNamedString]
    let reject: [ScaNamedString]
}

struct ScaNamedString: Decodable {
    let id: String
    let input: GeneratedString
}

struct ScaPlatformRuleInput: Decodable {
    let redirectUri: String
    let ceremony: String?
    let httpsCallbackAvailable: Bool?
}

struct ScaPlatformRule: Decodable {
    let id: String
    let platform: String
    let input: ScaPlatformRuleInput
    let expected: String
}

struct ScaCircleOriginInput: Decodable {
    let environment: String
    let circleOrigin: String?
}

struct ScaCircleOriginExpected: Decodable {
    let outcome: String
    let origin: String?
}

struct ScaCircleOriginVector: Decodable {
    let id: String
    let input: ScaCircleOriginInput
    let expected: ScaCircleOriginExpected
}

struct ScaTimeoutDefaults: Decodable {
    let approveMs: Int
    let enrollMs: Int
}

struct ScaTimeoutBounds: Decodable {
    let minimumMs: Int
    let maximumMs: Int
}

struct ScaTimeoutVector: Decodable {
    let id: String
    let input: Int
    let expected: String
}

struct ScaTimeoutVectors: Decodable {
    let defaults: ScaTimeoutDefaults
    let bounds: ScaTimeoutBounds
    let vectors: [ScaTimeoutVector]
}

struct ScaSDKLocalErrors: Decodable {
    let ios: [String]
    let android: [String]
}

struct ScaErrorVocabulary: Decodable {
    let pageCodes: [String]
    let sdkLocal: ScaSDKLocalErrors
}

/// A fixture string: a literal, `{"repeat": s, "count": n}`, or
/// `{"concat": [parts]}`. Oversized inputs are generated so the fixture never
/// inlines them.
struct GeneratedString: Decodable, Equatable {
    let value: String

    init(value: String) {
        self.value = value
    }

    private enum CodingKeys: String, CodingKey {
        case repeated = "repeat"
        case count
        case concat
    }

    init(from decoder: Decoder) throws {
        if let literal = try? decoder.singleValueContainer().decode(String.self) {
            value = literal
            return
        }
        let container = try decoder.container(keyedBy: CodingKeys.self)
        if let parts = try container.decodeIfPresent([GeneratedString].self, forKey: .concat) {
            value = parts.map(\.value).joined()
            return
        }
        let unit = try container.decode(String.self, forKey: .repeated)
        let count = try container.decode(Int.self, forKey: .count)
        guard count >= 0 else {
            throw FixtureError.invalidMetadata
        }
        value = String(repeating: unit, count: count)
    }
}
