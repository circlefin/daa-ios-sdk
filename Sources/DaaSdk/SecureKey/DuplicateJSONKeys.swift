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

/// Detects repeated member names in the top-level JSON object.
///
/// `JSONSerialization` represents objects as dictionaries and therefore
/// discards repeated members before the signing-input validators inspect the
/// allowed key set. The validators retain and sign the original bytes, so a
/// downstream parser could otherwise assign different semantics to those
/// bytes. This scanner recovers the top-level member names before parsing.
///
/// This is intentionally not a general JSON parser. `JSONSerialization` still
/// owns syntax validation. A backslash in a top-level member name is rejected
/// because the fixed signing-input member names are plain ASCII and comparing
/// escaped spellings safely would require duplicating JSON string decoding.
enum DuplicateJSONKeys {
    static func existAtTopLevel(_ data: Data) -> Bool {
        guard let text = String(data: data, encoding: .utf8),
              text.data(using: .utf8) == data,
              !text.unicodeScalars.contains(where: { $0.value == 0 }) else {
            return true
        }

        var scanner = DuplicateJSONKeyScanner()
        return scanner.scan(text)
    }
}

private struct DuplicateJSONKeyScanner {
    private var depth = 0
    private var inString = false
    private var escaped = false
    private var expectMemberName = false
    private var capturingKey = false
    private var key = ""
    private var seen = Set<String>()

    mutating func scan(_ text: String) -> Bool {
        for scalar in text.unicodeScalars {
            if inString {
                if scanStringScalar(scalar) {
                    return true
                }
                continue
            }
            if scanStructuralScalar(scalar) {
                return true
            }
        }
        return false
    }

    private mutating func scanStringScalar(_ scalar: Unicode.Scalar) -> Bool {
        if escaped {
            escaped = false
            return false
        }
        if scalar.value == 92 {
            if capturingKey {
                return true
            }
            escaped = true
            return false
        }
        if scalar.value == 34 {
            inString = false
            capturingKey = false
            return false
        }
        if capturingKey {
            key.append(String(scalar))
        }
        return false
    }

    private mutating func scanStructuralScalar(_ scalar: Unicode.Scalar) -> Bool {
        switch scalar.value {
        case 34:
            beginString()
        case 123:
            openObject()
        case 91:
            openArray()
        case 93, 125:
            closeContainer()
        case 44:
            markNextMember()
        case 58:
            return recordMemberName()
        default:
            break
        }
        return false
    }

    private mutating func beginString() {
        inString = true
        if depth == 1, expectMemberName {
            capturingKey = true
            key.removeAll(keepingCapacity: true)
        }
    }

    private mutating func openObject() {
        if depth == 0 {
            expectMemberName = true
        }
        depth += 1
    }

    private mutating func openArray() {
        depth += 1
    }

    private mutating func closeContainer() {
        depth -= 1
    }

    private mutating func markNextMember() {
        if depth == 1 {
            expectMemberName = true
        }
    }

    private mutating func recordMemberName() -> Bool {
        guard depth == 1, expectMemberName else {
            return false
        }
        if !seen.insert(key).inserted {
            return true
        }
        expectMemberName = false
        return false
    }
}
