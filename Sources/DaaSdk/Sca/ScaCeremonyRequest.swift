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

/// The two ceremonies the page runs. The raw value is what the callback's
/// `ceremony` field carries.
enum ScaCeremonyKind: String, Sendable {
    case registration
    case challenge
}

/// One pending ceremony: everything needed to open it and to recognize its
/// callback.
///
/// `description` is overridden because `frameToken` is a capability for one
/// pending ceremony and `state` is what makes its callback authentic; neither
/// may reach a log.
struct ScaCeremonyRequest: Sendable, CustomStringConvertible, CustomDebugStringConvertible {
    static let ceremonyPath = "/ceremony"

    // The page echoes state only if it matches [A-Za-z0-9_-]{16,128}. 32
    // random bytes encode to 43 unpadded Base64URL characters, inside that
    // range with no escaping.
    static let stateByteCount = 32

    let kind: ScaCeremonyKind
    let circleOrigin: String
    let redirectURI: String
    let frameToken: String
    let state: String

    // The server issues 32 random bytes as unpadded Base64URL (43 characters).
    // The cap leaves room for a longer format without admitting an unbounded
    // string into a URL.
    static let maxFrameTokenLength = 512

    /// Whether `frameToken` can name a ceremony: 1–512 RFC 3986 unreserved
    /// characters, which covers Base64URL and needs no escaping. Anything
    /// else is a caller bug, refused before a sheet opens.
    static func isValidFrameToken(_ frameToken: String) -> Bool {
        (1...maxFrameTokenLength).contains(frameToken.utf8.count)
            && frameToken.unicodeScalars.allSatisfy(isUnreserved)
    }

    private static func isUnreserved(_ scalar: Unicode.Scalar) -> Bool {
        ("a"..."z").contains(scalar) || ("A"..."Z").contains(scalar) || ("0"..."9").contains(scalar)
            || "-._~".unicodeScalars.contains(scalar)
    }

    static func newState() throws -> String {
        Base64URL.encode(try DaaSecureRandom.bytes(count: stateByteCount))
    }

    /// `<origin>/ceremony#token=…&state=…`.
    ///
    /// Both values ride in the fragment, which the browser never sends to a
    /// server or puts in a `Referer`; the page clears it from the address bar
    /// once read. The page matches `[#&]token=([^&]+)`, so the `token=` key is
    /// load-bearing — a bare `#<token>` is read as no token at all.
    var ceremonyURLString: String {
        "\(circleOrigin)\(Self.ceremonyPath)#token=\(Self.encodeURIComponent(frameToken))"
            + "&state=\(Self.encodeURIComponent(state))"
    }

    var description: String {
        "ScaCeremonyRequest(kind: \(kind), circleOrigin: \(circleOrigin))"
    }

    var debugDescription: String { description }

    // encodeURIComponent's unreserved set, spelled out in ASCII:
    // `CharacterSet.alphanumerics` also admits non-ASCII letters, and
    // `.urlFragmentAllowed` leaves `&` and `=` unescaped.
    private static let uriComponentAllowed = CharacterSet(
        charactersIn: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.!~*'()"
    )

    static func encodeURIComponent(_ value: String) -> String {
        // Only fails for strings that are not valid Unicode, which a Swift
        // String cannot hold.
        value.addingPercentEncoding(withAllowedCharacters: uriComponentAllowed) ?? ""
    }
}
